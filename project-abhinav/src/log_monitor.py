#!/usr/bin/env python3
"""Evidence Protector - Automated Log Integrity Monitor."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


ISO_8601_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
APACHE_RE = re.compile(r"\b\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\b")
STANDARD_RE = re.compile(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b")
US_STYLE_RE = re.compile(r"\b\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}\b")
SYSLOG_SHORT_RE = re.compile(
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2}\b"
)
EPOCH_RE = re.compile(r"\b\d{10}\b")

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_ORDER = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
SEVERITY_COLOR = {
    SEVERITY_LOW: "\033[93m",       # yellow
    SEVERITY_MEDIUM: "\033[33m",    # dark yellow
    SEVERITY_HIGH: "\033[91m",      # light red
    SEVERITY_CRITICAL: "\033[1;31m" # bold red
}


@dataclass(frozen=True)
class LogEntry:
    """Represents one parsed log line."""

    line_number: int
    timestamp: datetime
    raw_line: str


@dataclass(frozen=True)
class Gap:
    """Represents one suspicious time gap."""

    gap_id: int
    start_line: int
    end_line: int
    start_time: datetime
    end_time: datetime
    duration_seconds: int
    duration_human: str
    severity: str


@dataclass(frozen=True)
class ParseStats:
    """Aggregated parse statistics for a log file."""

    total_lines: int
    parsed_lines: int
    skipped_lines: int
    first_timestamp: Optional[datetime]
    last_timestamp: Optional[datetime]


def human_duration(seconds: int) -> str:
    """Convert seconds into a compact human-readable duration string."""
    duration = timedelta(seconds=seconds)
    days = duration.days
    hours, rem = divmod(duration.seconds, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def classify_severity(delta_seconds: int, threshold_seconds: int) -> str:
    """Classify a gap duration relative to threshold."""
    ratio = delta_seconds / threshold_seconds
    if ratio < 2:
        return SEVERITY_LOW
    if ratio <= 5:
        return SEVERITY_MEDIUM
    if ratio <= 20:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL


def _parse_iso_8601(raw_value: str) -> Optional[datetime]:
    """Parse ISO 8601 text and normalize to naive UTC when timezone is present."""
    normalized = raw_value
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = normalized[:-5] + normalized[-5:-2] + ":" + normalized[-2:]
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def extract_timestamp(line: str) -> Optional[datetime]:
    """Extract and parse the first supported timestamp found in a line."""
    iso_match = ISO_8601_RE.search(line)
    if iso_match:
        parsed_iso = _parse_iso_8601(iso_match.group(0))
        if parsed_iso is not None:
            return parsed_iso

    apache_match = APACHE_RE.search(line)
    if apache_match:
        try:
            return datetime.strptime(apache_match.group(0), "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            pass

    standard_match = STANDARD_RE.search(line)
    if standard_match:
        try:
            return datetime.strptime(standard_match.group(0), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    us_style_match = US_STYLE_RE.search(line)
    if us_style_match:
        try:
            return datetime.strptime(us_style_match.group(0), "%m/%d/%Y %H:%M:%S")
        except ValueError:
            pass

    syslog_match = SYSLOG_SHORT_RE.search(line)
    if syslog_match:
        try:
            parsed = datetime.strptime(syslog_match.group(0), "%b %d %H:%M:%S")
            return parsed.replace(year=datetime.now().year)
        except ValueError:
            pass

    epoch_match = EPOCH_RE.search(line)
    if epoch_match:
        try:
            epoch_value = int(epoch_match.group(0))
            return datetime.fromtimestamp(epoch_value, tz=timezone.utc).replace(tzinfo=None)
        except (ValueError, OSError):
            pass

    return None


def parse_log_file(logfile: Path, verbose: bool) -> tuple[list[LogEntry], ParseStats]:
    """Parse a log file line-by-line and collect entries/statistics."""
    entries: list[LogEntry] = []
    total_lines = 0
    skipped_lines = 0

    try:
        with logfile.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                total_lines += 1
                text = raw_line.rstrip("\r\n")
                parsed = extract_timestamp(text)
                if parsed is None:
                    skipped_lines += 1
                    if verbose:
                        print(f"[SKIP] line {line_number}: no parseable timestamp")
                    continue
                entries.append(LogEntry(line_number=line_number, timestamp=parsed, raw_line=text))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Log file not found: {logfile}") from exc
    except PermissionError as exc:
        raise RuntimeError(f"Permission denied reading log file: {logfile}") from exc
    except OSError as exc:
        raise RuntimeError(f"Failed to read log file '{logfile}': {exc}") from exc

    stats = ParseStats(
        total_lines=total_lines,
        parsed_lines=len(entries),
        skipped_lines=skipped_lines,
        first_timestamp=entries[0].timestamp if entries else None,
        last_timestamp=entries[-1].timestamp if entries else None,
    )
    return entries, stats


def detect_gaps(entries: list[LogEntry], threshold_seconds: int) -> list[Gap]:
    """Detect suspicious timestamp gaps from parsed entries."""
    gaps: list[Gap] = []
    for index in range(1, len(entries)):
        previous = entries[index - 1]
        current = entries[index]
        delta_seconds = int((current.timestamp - previous.timestamp).total_seconds())
        if delta_seconds <= 0:
            continue
        if delta_seconds <= threshold_seconds:
            continue
        gaps.append(
            Gap(
                gap_id=len(gaps) + 1,
                start_line=previous.line_number,
                end_line=current.line_number,
                start_time=previous.timestamp,
                end_time=current.timestamp,
                duration_seconds=delta_seconds,
                duration_human=human_duration(delta_seconds),
                severity=classify_severity(delta_seconds, threshold_seconds),
            )
        )
    return gaps


def build_stats_span(stats: ParseStats) -> str:
    """Build a printable log span string."""
    if stats.first_timestamp is None or stats.last_timestamp is None:
        return "N/A"
    return f"{stats.first_timestamp.isoformat()} -> {stats.last_timestamp.isoformat()}"


def print_terminal_report(
    logfile: Path, threshold_seconds: int, stats: ParseStats, gaps: list[Gap]
) -> None:
    """Print a colorized terminal report."""
    print("=" * 78)
    print(f"{ANSI_BOLD}Evidence Protector - Log Integrity Report{ANSI_RESET}")
    print("=" * 78)
    print(f"File path    : {logfile}")
    print(f"Threshold    : {threshold_seconds}s ({human_duration(threshold_seconds)})")
    print(f"Total lines  : {stats.total_lines}")
    print(f"Parsed lines : {stats.parsed_lines}")
    print(f"Skipped lines: {stats.skipped_lines}")
    print(f"Log span     : {build_stats_span(stats)}")
    print("-" * 78)

    if not gaps:
        print(f"{ANSI_BOLD}No suspicious gaps found.{ANSI_RESET}")
        print("=" * 78)
        return

    print(f"Detected {len(gaps)} suspicious gap(s):")
    for gap in gaps:
        color = SEVERITY_COLOR.get(gap.severity, "")
        print(
            f"{color}[{gap.severity}]{ANSI_RESET} Gap #{gap.gap_id} | "
            f"lines {gap.start_line}->{gap.end_line} | "
            f"{gap.start_time.isoformat()} -> {gap.end_time.isoformat()} | "
            f"{gap.duration_human} ({gap.duration_seconds}s)"
        )
    print("-" * 78)
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for gap in gaps:
        severity_counts[gap.severity] += 1
    print("Severity counts: ", end="")
    chunks: list[str] = []
    for severity in SEVERITY_ORDER:
        count = severity_counts[severity]
        if count > 0:
            chunks.append(f"{SEVERITY_COLOR[severity]}{severity}={count}{ANSI_RESET}")
    print("  ".join(chunks))
    print("=" * 78)


def ensure_parent_dir(output_path: Path) -> None:
    """Ensure the parent directory for an output file exists."""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Failed to create output directory '{output_path.parent}': {exc}") from exc


def serialize_gap(gap: Gap) -> dict[str, object]:
    """Convert Gap dataclass into a JSON/CSV-safe mapping."""
    data = asdict(gap)
    data["start_time"] = gap.start_time.isoformat()
    data["end_time"] = gap.end_time.isoformat()
    return data


def serialize_stats(stats: ParseStats) -> dict[str, object]:
    """Convert ParseStats dataclass into a JSON-safe mapping."""
    data = asdict(stats)
    data["first_timestamp"] = (
        stats.first_timestamp.isoformat() if stats.first_timestamp is not None else None
    )
    data["last_timestamp"] = (
        stats.last_timestamp.isoformat() if stats.last_timestamp is not None else None
    )
    return data


def write_csv_report(output_path: Path, gaps: list[Gap]) -> None:
    """Write gaps to CSV report."""
    ensure_parent_dir(output_path)
    fieldnames = [
        "gap_id",
        "start_line",
        "end_line",
        "start_time",
        "end_time",
        "duration_seconds",
        "duration_human",
        "severity",
    ]
    try:
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for gap in gaps:
                writer.writerow(serialize_gap(gap))
    except OSError as exc:
        raise RuntimeError(f"Failed to write CSV report '{output_path}': {exc}") from exc
    print(f"CSV report: {output_path}")


def write_json_report(output_path: Path, logfile: Path, threshold_seconds: int, stats: ParseStats, gaps: list[Gap]) -> None:
    """Write full scan result to JSON report."""
    ensure_parent_dir(output_path)
    payload = {
        "file": str(logfile),
        "threshold_seconds": threshold_seconds,
        "stats": serialize_stats(stats),
        "gaps": [serialize_gap(gap) for gap in gaps],
    }
    try:
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except OSError as exc:
        raise RuntimeError(f"Failed to write JSON report '{output_path}': {exc}") from exc
    print(f"JSON report: {output_path}")


def default_output_path(logfile: Path, output_mode: str) -> Path:
    """Return default output report path for CSV or JSON mode."""
    output_dir = Path.cwd() / "output"
    suffix = ".csv" if output_mode == "csv" else ".json"
    return output_dir / f"{logfile.stem}_gaps{suffix}"


def resolve_output_paths(logfile: Path, output_mode: str, out_file: Optional[str]) -> tuple[Optional[Path], Optional[Path]]:
    """Resolve output target paths for CSV and JSON reports."""
    csv_path: Optional[Path] = None
    json_path: Optional[Path] = None

    if output_mode == "terminal":
        return csv_path, json_path

    if output_mode in {"csv", "json"}:
        if out_file:
            custom = Path(out_file)
            if output_mode == "csv":
                csv_path = custom
            else:
                json_path = custom
        else:
            if output_mode == "csv":
                csv_path = default_output_path(logfile, "csv")
            else:
                json_path = default_output_path(logfile, "json")
        return csv_path, json_path

    if out_file:
        base = Path(out_file)
        if base.suffix.lower() == ".csv":
            csv_path = base
            json_path = base.with_suffix(".json")
        elif base.suffix.lower() == ".json":
            csv_path = base.with_suffix(".csv")
            json_path = base
        else:
            csv_path = base.with_suffix(".csv")
            json_path = base.with_suffix(".json")
    else:
        csv_path = default_output_path(logfile, "csv")
        json_path = default_output_path(logfile, "json")
    return csv_path, json_path


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI parser."""
    parser = argparse.ArgumentParser(
        description="Evidence Protector - Automated Log Integrity Monitor"
    )
    parser.add_argument("logfile", help="Path to the log file to scan")
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=300,
        help="Gap threshold in seconds (default: 300)",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=("terminal", "csv", "json", "both"),
        default="terminal",
        help="Output mode (default: terminal)",
    )
    parser.add_argument(
        "--out-file",
        help="Custom output file path (mode-specific, or base path for --output both)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print skipped lines while parsing",
    )
    return parser


def main() -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    logfile = Path(args.logfile)
    if args.threshold <= 0:
        print("Error: threshold must be a positive integer.", file=sys.stderr)
        return 2
    if not logfile.exists():
        print(f"Error: log file not found: {logfile}", file=sys.stderr)
        return 2
    if not logfile.is_file():
        print(f"Error: path is not a file: {logfile}", file=sys.stderr)
        return 2

    try:
        entries, stats = parse_log_file(logfile, verbose=args.verbose)
        gaps = detect_gaps(entries, args.threshold)
        csv_path, json_path = resolve_output_paths(logfile, args.output, args.out_file)

        if args.output in {"terminal", "both"}:
            print_terminal_report(logfile, args.threshold, stats, gaps)
        if csv_path is not None:
            write_csv_report(csv_path, gaps)
        if json_path is not None:
            write_json_report(json_path, logfile, args.threshold, stats, gaps)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main())
