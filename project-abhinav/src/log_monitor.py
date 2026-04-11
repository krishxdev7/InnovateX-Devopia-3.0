#!/usr/bin/env python3
"""
Evidence Protector – Automated Log Integrity Monitor
Scans log files, extracts timestamps, and flags suspicious time gaps.
"""

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import List, Optional, Tuple


# ─────────────────────────────────────────────
#  Timestamp patterns (most common log formats)
# ─────────────────────────────────────────────
TIMESTAMP_PATTERNS: List[Tuple[str, str]] = [
    # ISO 8601:  2024-01-15T14:32:10  /  2024-01-15T14:32:10.123Z
    (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
     "%Y-%m-%dT%H:%M:%S"),
    # Common syslog / Apache: 15/Jan/2024:14:32:10
    (r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}",
     "%d/%b/%Y:%H:%M:%S"),
    # Standard datetime: 2024-01-15 14:32:10
    (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
     "%Y-%m-%d %H:%M:%S"),
    # US-style: 01/15/2024 14:32:10
    (r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",
     "%m/%d/%Y %H:%M:%S"),
    # Syslog short: Jan 15 14:32:10  (no year — assume current)
    (r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2}",
     "%b %d %H:%M:%S"),
    # Epoch seconds (10-digit)
    (r"\b\d{10}\b", "EPOCH"),
]


@dataclass
class LogEntry:
    line_number: int
    timestamp: datetime
    raw_line: str


@dataclass
class Gap:
    gap_id: int
    start_line: int
    end_line: int
    start_time: str
    end_time: str
    duration_seconds: float
    duration_human: str
    severity: str          # LOW / MEDIUM / HIGH / CRITICAL


@dataclass
class ParseStats:
    total_lines: int
    parsed_lines: int
    skipped_lines: int
    first_entry: Optional[str]
    last_entry: Optional[str]


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def human_duration(seconds: float) -> str:
    td = timedelta(seconds=seconds)
    days = td.days
    hours, rem = divmod(td.seconds, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def severity_label(seconds: float, threshold: float) -> str:
    ratio = seconds / threshold
    if ratio < 2:
        return "LOW"
    elif ratio < 5:
        return "MEDIUM"
    elif ratio < 20:
        return "HIGH"
    else:
        return "CRITICAL"


def extract_timestamp(line: str) -> Optional[datetime]:
    """Try each known pattern; return first successful parse."""
    for pattern, fmt in TIMESTAMP_PATTERNS:
        match = re.search(pattern, line)
        if not match:
            continue
        raw = match.group()
        try:
            if fmt == "EPOCH":
                return datetime.fromtimestamp(int(raw))
            # Strip timezone suffix for simple strptime
            clean = re.sub(r"Z$|[+-]\d{2}:\d{2}$", "", raw)
            ts = datetime.strptime(clean, fmt)
            # Inject current year for short syslog format
            if ts.year == 1900:
                ts = ts.replace(year=datetime.now().year)
            return ts
        except ValueError:
            continue
    return None


# ─────────────────────────────────────────────
#  Core scanner
# ─────────────────────────────────────────────

def scan_log(
    filepath: str,
    threshold_seconds: int,
    verbose: bool = False,
) -> Tuple[List[Gap], ParseStats]:
    """Parse the log file and detect suspicious time gaps."""
    entries: List[LogEntry] = []
    total_lines = 0
    skipped = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            total_lines += 1
            line = line.rstrip()
            ts = extract_timestamp(line)
            if ts is None:
                skipped += 1
                if verbose:
                    print(f"  [SKIP] Line {lineno}: no timestamp found")
                continue
            entries.append(LogEntry(line_number=lineno, timestamp=ts, raw_line=line))

    stats = ParseStats(
        total_lines=total_lines,
        parsed_lines=len(entries),
        skipped_lines=skipped,
        first_entry=entries[0].timestamp.isoformat() if entries else None,
        last_entry=entries[-1].timestamp.isoformat() if entries else None,
    )

    gaps: List[Gap] = []
    gap_id = 1
    threshold = timedelta(seconds=threshold_seconds)

    for i in range(1, len(entries)):
        prev = entries[i - 1]
        curr = entries[i]
        delta = curr.timestamp - prev.timestamp

        # Ignore negative deltas (out-of-order entries) silently
        if delta < timedelta(0):
            continue

        if delta > threshold:
            secs = delta.total_seconds()
            gaps.append(Gap(
                gap_id=gap_id,
                start_line=prev.line_number,
                end_line=curr.line_number,
                start_time=prev.timestamp.isoformat(),
                end_time=curr.timestamp.isoformat(),
                duration_seconds=secs,
                duration_human=human_duration(secs),
                severity=severity_label(secs, threshold_seconds),
            ))
            gap_id += 1

    return gaps, stats


# ─────────────────────────────────────────────
#  Output formatters
# ─────────────────────────────────────────────

SEVERITY_COLOR = {
    "LOW": "\033[93m",       # yellow
    "MEDIUM": "\033[33m",    # dark yellow
    "HIGH": "\033[91m",      # light red
    "CRITICAL": "\033[1;31m" # bold red
}
RESET = "\033[0m"
BOLD = "\033[1m"


def print_terminal_report(gaps: List[Gap], stats: ParseStats, threshold: int, filepath: str):
    width = 72
    print("\n" + "═" * width)
    print(f"{BOLD}  🔍 EVIDENCE PROTECTOR — Log Integrity Report{RESET}")
    print("═" * width)
    print(f"  File     : {filepath}")
    print(f"  Threshold: {human_duration(threshold)} ({threshold}s)")
    print(f"  Total lines parsed : {stats.parsed_lines:,} / {stats.total_lines:,}")
    print(f"  Malformed / skipped: {stats.skipped_lines:,}")
    if stats.first_entry:
        print(f"  Log span : {stats.first_entry}  →  {stats.last_entry}")
    print("─" * width)

    if not gaps:
        print(f"\n  {BOLD}✅  No suspicious gaps detected.{RESET}  Log appears intact.\n")
        print("═" * width + "\n")
        return

    print(f"\n  {BOLD}⚠️  {len(gaps)} suspicious gap(s) detected:{RESET}\n")

    for g in gaps:
        color = SEVERITY_COLOR.get(g.severity, "")
        print(f"  {color}[{g.severity}]{RESET}  Gap #{g.gap_id}")
        print(f"    Lines   : {g.start_line} → {g.end_line}")
        print(f"    From    : {g.start_time}")
        print(f"    To      : {g.end_time}")
        print(f"    Missing : {BOLD}{g.duration_human}{RESET}  ({g.duration_seconds:.0f}s)")
        print()

    # Summary bar
    counts = {s: sum(1 for g in gaps if g.severity == s)
              for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    print("─" * width)
    print("  Severity summary: ", end="")
    for sev, cnt in counts.items():
        if cnt:
            col = SEVERITY_COLOR[sev]
            print(f"{col}{sev}={cnt}{RESET}  ", end="")
    print()
    print("═" * width + "\n")


def write_csv(gaps: List[Gap], output_path: str):
    fields = ["gap_id", "start_line", "end_line", "start_time",
              "end_time", "duration_seconds", "duration_human", "severity"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for g in gaps:
            writer.writerow(asdict(g))
    print(f"  📄 CSV report saved → {output_path}")


def write_json(gaps: List[Gap], stats: ParseStats, output_path: str):
    payload = {
        "stats": asdict(stats),
        "gaps": [asdict(g) for g in gaps],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f"  📄 JSON report saved → {output_path}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_monitor",
        description="Evidence Protector – Automated Log Integrity Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_monitor.py system.log
  python log_monitor.py system.log --threshold 120 --output csv
  python log_monitor.py auth.log -t 300 -o json --out-file report.json
  python log_monitor.py app.log --verbose --output both
        """,
    )
    p.add_argument("logfile", help="Path to the .log file to analyse")
    p.add_argument(
        "-t", "--threshold",
        type=int, default=300,
        metavar="SECONDS",
        help="Gap threshold in seconds (default: 300 = 5 min)",
    )
    p.add_argument(
        "-o", "--output",
        choices=["terminal", "csv", "json", "both"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    p.add_argument(
        "--out-file",
        metavar="PATH",
        help="Output file path for CSV/JSON (auto-named if omitted)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print skipped lines during parsing",
    )
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── Validate input ──────────────────────────────────────────
    if not os.path.isfile(args.logfile):
        print(f"[ERROR] File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    if args.threshold <= 0:
        print("[ERROR] Threshold must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Scanning: {args.logfile} …")

    # ── Scan ────────────────────────────────────────────────────
    try:
        gaps, stats = scan_log(args.logfile, args.threshold, verbose=args.verbose)
    except PermissionError:
        print(f"[ERROR] Permission denied: {args.logfile}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error while scanning: {e}", file=sys.stderr)
        sys.exit(1)

    # ── Output ──────────────────────────────────────────────────
    base_name = os.path.splitext(args.logfile)[0]

    fmt = args.output
    if fmt in ("terminal", "both"):
        print_terminal_report(gaps, stats, args.threshold, args.logfile)

    if fmt in ("csv", "both"):
        csv_path = args.out_file if (args.out_file and fmt == "csv") else f"{base_name}_gaps.csv"
        write_csv(gaps, csv_path)

    if fmt in ("json", "both"):
        json_path = args.out_file if (args.out_file and fmt == "json") else f"{base_name}_gaps.json"
        write_json(gaps, stats, json_path)

    # ── Exit code: 1 if gaps found (useful for CI pipelines) ───
    sys.exit(1 if gaps else 0)


if __name__ == "__main__":
    main()
