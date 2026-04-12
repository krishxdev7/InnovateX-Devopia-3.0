#!/usr/bin/env python3
"""
Evidence Protector - Automated Log Integrity Monitor

This script keeps the legacy CLI contract used by the existing UI/backend pipeline
while integrating advanced forensic features from the newer monitor engine.
"""

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Deque, Dict, Iterator, List, Optional, Sequence, Tuple

TOOL_NAME = "Evidence Protector - Automated Log Integrity Monitor"
TOOL_VERSION = "2.0.0"

DEFAULT_THRESHOLD_SECONDS = 300.0
DEFAULT_CONTEXT_LINES = 2

SEVERITY_WARNING = "WARNING"
SEVERITY_SUSPICIOUS = "SUSPICIOUS"
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_ORDER = {
    SEVERITY_WARNING: 1,
    SEVERITY_SUSPICIOUS: 2,
    SEVERITY_CRITICAL: 3,
}

RISK_CLEAN = "CLEAN"
RISK_LOW = "LOW RISK"
RISK_MODERATE = "MODERATE RISK"
RISK_HIGH = "HIGH RISK"
RISK_COMPROMISED = "COMPROMISED"

ERROR_KEYWORDS = {
    "error",
    "exception",
    "traceback",
    "critical",
    "fatal",
    "fail",
    "failed",
    "failure",
    "panic",
    "alert",
    "denied",
}

# ANSI colors (standard terminal support only).
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_CYAN = "\033[36m"
ANSI_DIM = "\033[2m"

COLOR_ENABLED = bool(sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1")
if os.name == "nt" and COLOR_ENABLED:
    # Enables ANSI in most modern Windows terminals.
    os.system("")


@dataclass(frozen=True)
class TimestampParser:
    name: str
    pattern: re.Pattern
    parser: Callable[[str], dt.datetime]


@dataclass
class GapRecord:
    gap_number: int
    severity: str
    gap_start: dt.datetime
    gap_end: dt.datetime
    duration_seconds: int
    duration_human: str
    line_before_gap: str
    line_after_gap: str
    line_number_start: int
    line_number_end: int
    raw_context_before: List[Dict[str, object]]
    raw_context_after: List[Dict[str, object]]
    fingerprint: str
    tamper_confidence: float


@dataclass
class ScanStats:
    total_lines: int
    parsed_lines: int
    malformed_lines: int
    error_lines: int
    error_bursts: int
    file_size: int
    scan_seconds: float
    first_timestamp: Optional[dt.datetime]
    last_timestamp: Optional[dt.datetime]
    gaps_detected: int
    final_chain_hash: str


@dataclass
class ProgressTracker:
    interactive: bool
    last_percent: float = -1.0
    last_emit: float = 0.0


def color_text(text: str, color: str, bold: bool = False) -> str:
    if not COLOR_ENABLED:
        return text
    prefix = color
    if bold:
        prefix += ANSI_BOLD
    return f"{prefix}{text}{ANSI_RESET}"


def truncate_text(value: str, limit: int = 140) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def print_ascii_box(lines: Sequence[str], width: int = 96) -> None:
    width = max(width, 30)
    border = "+" + "=" * (width - 2) + "+"
    print(border)
    for line in lines:
        clipped = line[: width - 4]
        print("| " + clipped.ljust(width - 4) + " |")
    print(border)


def animate_banner() -> None:
    if sys.stdout.isatty():
        frames = [
            "[=         ] Booting forensic engine",
            "[==        ] Loading parser modules",
            "[===       ] Building timeline model",
            "[====      ] Profiling log integrity",
            "[=====     ] Scanning readiness checks",
            "[======    ] Verifying evidence chain",
            "[=======   ] Initializing report stack",
            "[========  ] Hardening output channels",
            "[========= ] Finalizing startup",
            "[==========] Ready",
        ]
        for frame in frames:
            message = color_text(frame, ANSI_CYAN, bold=True)
            print("\r" + message.ljust(80), end="", flush=True)
            time.sleep(0.04)
        print("\r" + " " * 84 + "\r", end="", flush=True)
    else:
        print("[1/4] Booting forensic engine")
        print("[2/4] Loading parser modules")
        print("[3/4] Building timeline model")
        print("[4/4] Starting scan")


DIRECTIVE_REGEX = {
    "%Y": r"\d{4}",
    "%y": r"\d{2}",
    "%m": r"\d{1,2}",
    "%d": r"\d{1,2}",
    "%H": r"\d{1,2}",
    "%I": r"\d{1,2}",
    "%M": r"\d{1,2}",
    "%S": r"\d{1,2}",
    "%f": r"\d{1,6}",
    "%b": r"[A-Za-z]{3}",
    "%B": r"[A-Za-z]+",
    "%p": r"(?:AM|PM|am|pm)",
    "%z": r"[+-]\d{2}:?\d{2}",
    "%Z": r"[A-Za-z_+\-/]+",
    "%j": r"\d{1,3}",
    "%a": r"[A-Za-z]{3}",
    "%A": r"[A-Za-z]+",
    "%w": r"\d",
    "%U": r"\d{1,2}",
    "%W": r"\d{1,2}",
    "%c": r".+?",
    "%x": r".+?",
    "%X": r".+?",
}


def build_regex_from_strptime(fmt: str) -> re.Pattern:
    parts: List[str] = []
    i = 0

    while i < len(fmt):
        ch = fmt[i]
        if ch == "%":
            if i + 1 >= len(fmt):
                raise ValueError("Custom format ends with an incomplete % token")
            token = fmt[i : i + 2]
            if token == "%%":
                parts.append(re.escape("%"))
                i += 2
                continue
            if token not in DIRECTIVE_REGEX:
                raise ValueError(
                    f"Unsupported directive in custom format: {token}. "
                    "Use common datetime directives like %Y, %m, %d, %H, %M, %S, etc."
                )
            parts.append(DIRECTIVE_REGEX[token])
            i += 2
        else:
            parts.append(re.escape(ch))
            i += 1

    return re.compile(r"(?P<ts>" + "".join(parts) + r")")


def normalize_datetime(parsed: dt.datetime) -> dt.datetime:
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return parsed


def build_timestamp_parsers(custom_format: Optional[str]) -> List[TimestampParser]:
    current_year = dt.datetime.now().year
    parsers: List[TimestampParser] = []

    if custom_format:
        custom_pattern = build_regex_from_strptime(custom_format)

        def parse_custom(value: str) -> dt.datetime:
            return dt.datetime.strptime(value, custom_format)

        parsers.append(TimestampParser("CUSTOM", custom_pattern, parse_custom))

    # ISO 8601 with timezone support.
    iso_tz_pattern = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)"
    )

    def parse_iso_tz(value: str) -> dt.datetime:
        normalized = value.replace("Z", "+00:00")
        return dt.datetime.fromisoformat(normalized)

    parsers.append(TimestampParser("ISO8601", iso_tz_pattern, parse_iso_tz))

    # Legacy format support from existing pipeline.
    iso_space_pattern = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
    )

    def parse_iso_space(value: str) -> dt.datetime:
        return dt.datetime.fromisoformat(value)

    parsers.append(TimestampParser("ISO_SPACE", iso_space_pattern, parse_iso_space))

    slash_pattern = re.compile(r"(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})")

    def parse_slash(value: str) -> dt.datetime:
        return dt.datetime.strptime(value, "%Y/%m/%d %H:%M:%S")

    parsers.append(TimestampParser("SLASH", slash_pattern, parse_slash))

    apache_pattern = re.compile(r"(?P<ts>\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})")

    def parse_apache(value: str) -> dt.datetime:
        return dt.datetime.strptime(value, "%d/%b/%Y:%H:%M:%S")

    parsers.append(TimestampParser("APACHE", apache_pattern, parse_apache))

    syslog_pattern = re.compile(r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

    def parse_syslog(value: str) -> dt.datetime:
        # Attach current year for year-less syslog timestamps.
        return dt.datetime.strptime(f"{current_year} {value}", "%Y %b %d %H:%M:%S")

    parsers.append(TimestampParser("SYSLOG", syslog_pattern, parse_syslog))

    return parsers


def extract_timestamp(line: str, parsers: Sequence[TimestampParser]) -> Optional[Tuple[dt.datetime, str, str]]:
    for parser in parsers:
        match = parser.pattern.search(line)
        if not match:
            continue

        raw_value = match.group("ts")
        try:
            parsed = normalize_datetime(parser.parser(raw_value))
            return parsed, raw_value, parser.name
        except Exception:
            continue
    return None


def iterate_log_lines(path: Path) -> Iterator[Tuple[int, str, int]]:
    bytes_read = 0
    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            bytes_read += len(raw_line)
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            yield line_number, line, bytes_read


def format_duration(seconds: float) -> str:
    total_seconds = int(round(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def classify_severity(duration_seconds: float) -> str:
    if duration_seconds > 2 * 3600:
        return SEVERITY_CRITICAL
    if duration_seconds >= 30 * 60:
        return SEVERITY_SUSPICIOUS
    return SEVERITY_WARNING


def compute_fingerprint(
    gap_start: dt.datetime,
    gap_end: dt.datetime,
    line_number_start: int,
    line_number_end: int,
    duration_seconds: int,
) -> str:
    base = (
        f"{gap_start.isoformat()}|{gap_end.isoformat()}|"
        f"{line_number_start}|{line_number_end}|{duration_seconds}"
    )
    return hashlib.md5(base.encode("utf-8")).hexdigest()


def compute_tamper_confidence(
    duration_seconds: float,
    threshold_seconds: float,
    line_distance: int,
    midpoint_time: dt.datetime,
    context_before_count: int,
    context_after_count: int,
) -> float:
    # Duration is the strongest signal. Long gaps raise confidence quickly.
    duration_ratio = duration_seconds / max(1.0, threshold_seconds)
    duration_score = min(58.0, duration_ratio * 10.5)
    if duration_seconds > 2 * 3600:
        duration_score = min(65.0, duration_score + 8.0)

    # If line numbers jump with almost no adjacent events, gaps are less likely natural.
    if line_distance <= 2:
        density_score = 16.0
    elif line_distance <= 5:
        density_score = 12.0
    elif line_distance <= 20:
        density_score = 7.0
    else:
        density_score = 3.0

    # Off-hours gaps are typically more suspicious for operational systems.
    hour = midpoint_time.hour
    if 0 <= hour <= 4:
        time_score = 14.0
    elif hour in (22, 23, 5):
        time_score = 8.0
    else:
        time_score = 3.0

    context_score = 6.0 if (context_before_count and context_after_count) else 2.0

    confidence = min(100.0, duration_score + density_score + time_score + context_score)
    return round(confidence, 2)


def render_progress(
    bytes_read: int,
    total_bytes: int,
    lines_processed: int,
    gaps_found: int,
    malformed_lines: int,
    start_time: float,
    tracker: ProgressTracker,
    final: bool = False,
) -> None:
    if total_bytes <= 0:
        progress = 100.0
    else:
        progress = min(100.0, (bytes_read / total_bytes) * 100.0)

    width = 30
    filled = int((progress / 100.0) * width)
    bar = "#" * filled + "-" * (width - filled)

    elapsed = max(0.001, time.perf_counter() - start_time)
    rate = lines_processed / elapsed

    prefix = color_text(f"[{bar}] {progress:6.2f}%", ANSI_CYAN, bold=True)
    stats = (
        f"lines:{lines_processed:,} "
        f"gaps:{gaps_found:,} "
        f"malformed:{malformed_lines:,} "
        f"rate:{rate:,.0f}/s"
    )

    if tracker.interactive:
        print("\r" + prefix + " " + stats, end="", flush=True)
        if final:
            print()
        return

    now = time.perf_counter()
    should_emit = (
        final
        or tracker.last_percent < 0
        or (progress - tracker.last_percent) >= 5.0
        or (now - tracker.last_emit) >= 1.0
    )
    if should_emit:
        print(prefix + " " + stats)
        tracker.last_percent = progress
        tracker.last_emit = now


def scan_log_file(
    path: Path,
    threshold_seconds: float,
    context_lines: int,
    custom_format: Optional[str],
) -> Tuple[List[GapRecord], ScanStats]:
    parsers = build_timestamp_parsers(custom_format)
    threshold_seconds = max(0.001, threshold_seconds)
    file_size = path.stat().st_size

    gaps: List[GapRecord] = []
    recent_lines: Deque[Tuple[int, str]] = deque(maxlen=max(0, context_lines))
    pending_after_context: List[Tuple[int, int]] = []

    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0
    error_lines = 0
    error_bursts = 0
    prev_was_error = False

    first_timestamp: Optional[dt.datetime] = None
    last_timestamp: Optional[dt.datetime] = None

    previous_timestamp: Optional[dt.datetime] = None
    previous_line_number: Optional[int] = None
    previous_line_text: Optional[str] = None

    # Hash chain over parsed timestamped lines.
    rolling_hash = "0" * 64

    start_time = time.perf_counter()
    last_progress_update = 0.0
    tracker = ProgressTracker(interactive=sys.stdout.isatty())

    for line_number, line, bytes_read in iterate_log_lines(path):
        total_lines += 1

        line_stripped = line.strip()
        if not line_stripped:
            prev_was_error = False
        else:
            lower = line_stripped.lower()
            is_error = any(keyword in lower for keyword in ERROR_KEYWORDS)
            if is_error:
                error_lines += 1
                if not prev_was_error:
                    error_bursts += 1
                prev_was_error = True
            else:
                prev_was_error = False

        # Keep collecting requested post-gap context for already-open gaps.
        if pending_after_context:
            next_pending: List[Tuple[int, int]] = []
            for gap_index, remaining in pending_after_context:
                if remaining > 0:
                    gaps[gap_index].raw_context_after.append(
                        {"line_number": line_number, "line": line}
                    )
                    remaining -= 1
                if remaining > 0:
                    next_pending.append((gap_index, remaining))
            pending_after_context = next_pending

        before_snapshot = list(recent_lines)

        extracted = extract_timestamp(line, parsers)
        if extracted is None:
            malformed_lines += 1
            if context_lines > 0:
                recent_lines.append((line_number, line))

            now = time.perf_counter()
            if tracker.interactive:
                if now - last_progress_update >= 0.1 or bytes_read >= file_size:
                    render_progress(
                        bytes_read=bytes_read,
                        total_bytes=file_size,
                        lines_processed=total_lines,
                        gaps_found=len(gaps),
                        malformed_lines=malformed_lines,
                        start_time=start_time,
                        tracker=tracker,
                    )
                    last_progress_update = now
            else:
                render_progress(
                    bytes_read=bytes_read,
                    total_bytes=file_size,
                    lines_processed=total_lines,
                    gaps_found=len(gaps),
                    malformed_lines=malformed_lines,
                    start_time=start_time,
                    tracker=tracker,
                )
            continue

        current_timestamp, _, parser_name = extracted
        parsed_lines += 1

        # Syslog format has no year. If logs cross year-end, adjust forward once detected.
        if (
            previous_timestamp is not None
            and current_timestamp < previous_timestamp
            and parser_name == "SYSLOG"
            and previous_timestamp.month == 12
            and current_timestamp.month == 1
        ):
            current_timestamp = current_timestamp.replace(year=previous_timestamp.year + 1)

        if first_timestamp is None:
            first_timestamp = current_timestamp
        last_timestamp = current_timestamp

        rolling_hash = hashlib.sha256((line + rolling_hash).encode("utf-8", errors="replace")).hexdigest()

        if previous_timestamp is not None and previous_line_number is not None and previous_line_text is not None:
            delta_seconds = (current_timestamp - previous_timestamp).total_seconds()
            if delta_seconds > threshold_seconds:
                severity = classify_severity(delta_seconds)
                line_distance = max(1, line_number - previous_line_number)
                midpoint = previous_timestamp + dt.timedelta(seconds=(delta_seconds / 2.0))

                before_context = [
                    {"line_number": ln, "line": text} for ln, text in before_snapshot
                ]
                after_context = [{"line_number": line_number, "line": line}]

                confidence = compute_tamper_confidence(
                    duration_seconds=delta_seconds,
                    threshold_seconds=threshold_seconds,
                    line_distance=line_distance,
                    midpoint_time=midpoint,
                    context_before_count=len(before_context),
                    context_after_count=len(after_context),
                )

                duration_seconds_int = int(round(delta_seconds))
                fingerprint = compute_fingerprint(
                    gap_start=previous_timestamp,
                    gap_end=current_timestamp,
                    line_number_start=previous_line_number,
                    line_number_end=line_number,
                    duration_seconds=duration_seconds_int,
                )

                gap = GapRecord(
                    gap_number=len(gaps) + 1,
                    severity=severity,
                    gap_start=previous_timestamp,
                    gap_end=current_timestamp,
                    duration_seconds=duration_seconds_int,
                    duration_human=format_duration(delta_seconds),
                    line_before_gap=previous_line_text,
                    line_after_gap=line,
                    line_number_start=previous_line_number,
                    line_number_end=line_number,
                    raw_context_before=before_context,
                    raw_context_after=after_context,
                    fingerprint=fingerprint,
                    tamper_confidence=confidence,
                )
                gaps.append(gap)

                if context_lines > 1:
                    pending_after_context.append((len(gaps) - 1, context_lines - 1))

        previous_timestamp = current_timestamp
        previous_line_number = line_number
        previous_line_text = line

        if context_lines > 0:
            recent_lines.append((line_number, line))

        now = time.perf_counter()
        if tracker.interactive:
            if now - last_progress_update >= 0.1 or bytes_read >= file_size:
                render_progress(
                    bytes_read=bytes_read,
                    total_bytes=file_size,
                    lines_processed=total_lines,
                    gaps_found=len(gaps),
                    malformed_lines=malformed_lines,
                    start_time=start_time,
                    tracker=tracker,
                )
                last_progress_update = now
        else:
            render_progress(
                bytes_read=bytes_read,
                total_bytes=file_size,
                lines_processed=total_lines,
                gaps_found=len(gaps),
                malformed_lines=malformed_lines,
                start_time=start_time,
                tracker=tracker,
            )

    render_progress(
        bytes_read=file_size,
        total_bytes=file_size,
        lines_processed=total_lines,
        gaps_found=len(gaps),
        malformed_lines=malformed_lines,
        start_time=start_time,
        tracker=tracker,
        final=True,
    )

    scan_seconds = time.perf_counter() - start_time
    stats = ScanStats(
        total_lines=total_lines,
        parsed_lines=parsed_lines,
        malformed_lines=malformed_lines,
        error_lines=error_lines,
        error_bursts=error_bursts,
        file_size=file_size,
        scan_seconds=scan_seconds,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
        gaps_detected=len(gaps),
        final_chain_hash=rolling_hash,
    )
    return gaps, stats


def filter_gaps_by_severity(gaps: Sequence[GapRecord], min_severity: Optional[str]) -> List[GapRecord]:
    if not min_severity:
        return list(gaps)
    min_rank = SEVERITY_ORDER[min_severity]
    return [gap for gap in gaps if SEVERITY_ORDER[gap.severity] >= min_rank]


def compute_gap_entropy_score(
    gaps: Sequence[GapRecord],
    first_timestamp: Optional[dt.datetime],
    last_timestamp: Optional[dt.datetime],
) -> float:
    if not gaps or len(gaps) < 2 or first_timestamp is None or last_timestamp is None:
        return 0.0

    span_seconds = (last_timestamp - first_timestamp).total_seconds()
    if span_seconds <= 0:
        return 0.0

    bins = max(5, min(20, len(gaps) * 2))
    counts = [0 for _ in range(bins)]

    for gap in gaps:
        offset = (gap.gap_start - first_timestamp).total_seconds()
        normalized = min(max(offset / span_seconds, 0.0), 1.0)
        index = min(bins - 1, int(normalized * bins))
        counts[index] += 1

    total = float(sum(counts))
    if total == 0:
        return 0.0

    observed = [count / total for count in counts]
    expected = [1.0 / bins for _ in range(bins)]
    midpoint = [(o + e) / 2.0 for o, e in zip(observed, expected)]

    def kl_divergence(p: Sequence[float], q: Sequence[float]) -> float:
        value = 0.0
        for pi, qi in zip(p, q):
            if pi > 0 and qi > 0:
                value += pi * math.log2(pi / qi)
        return value

    js_divergence = 0.5 * kl_divergence(observed, midpoint) + 0.5 * kl_divergence(expected, midpoint)
    normalized_score = min(1.0, max(0.0, js_divergence / math.log2(bins)))

    # Clustered gaps => high score, uniform gaps => low score.
    return round(normalized_score * 100.0, 2)


def derive_risk_assessment(
    warning_count: int,
    suspicious_count: int,
    critical_count: int,
    entropy_score: float,
    highest_confidence: float,
    error_bursts: int,
) -> str:
    if warning_count == 0 and suspicious_count == 0 and critical_count == 0 and error_bursts == 0:
        return RISK_CLEAN

    if critical_count >= 2 or highest_confidence >= 92.0:
        return RISK_COMPROMISED
    if critical_count >= 1 or suspicious_count >= 3 or entropy_score >= 70.0 or error_bursts >= 25:
        return RISK_HIGH
    if suspicious_count >= 1 or (warning_count >= 5 and entropy_score >= 45.0) or error_bursts >= 10:
        return RISK_MODERATE
    return RISK_LOW


def find_most_critical_gap(gaps: Sequence[GapRecord]) -> Optional[GapRecord]:
    if not gaps:
        return None
    return max(
        gaps,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            item.duration_seconds,
            item.tamper_confidence,
        ),
    )


def build_timeline(
    gaps: Sequence[GapRecord],
    first_timestamp: Optional[dt.datetime],
    last_timestamp: Optional[dt.datetime],
    width: int = 78,
    colorize: bool = True,
) -> str:
    if not gaps or first_timestamp is None or last_timestamp is None:
        return color_text("." * width, ANSI_GREEN) if colorize else "." * width

    span_seconds = (last_timestamp - first_timestamp).total_seconds()
    if span_seconds <= 0:
        return color_text("." * width, ANSI_GREEN) if colorize else "." * width

    levels = [0 for _ in range(width)]
    for gap in gaps:
        start_offset = (gap.gap_start - first_timestamp).total_seconds()
        end_offset = (gap.gap_end - first_timestamp).total_seconds()
        start_index = min(width - 1, max(0, int((start_offset / span_seconds) * (width - 1))))
        end_index = min(width - 1, max(0, int((end_offset / span_seconds) * (width - 1))))

        if end_index < start_index:
            end_index = start_index

        level = 1 if gap.severity == SEVERITY_WARNING else 2
        for idx in range(start_index, end_index + 1):
            levels[idx] = max(levels[idx], level)

    chunks: List[str] = []
    for level in levels:
        if level == 0:
            chunks.append(color_text(".", ANSI_GREEN) if colorize else ".")
        elif level == 1:
            chunks.append(color_text("#", ANSI_YELLOW, bold=True) if colorize else "#")
        else:
            chunks.append(color_text("#", ANSI_RED, bold=True) if colorize else "#")
    return "".join(chunks)


def build_summary(gaps: Sequence[GapRecord], stats: ScanStats) -> Dict[str, object]:
    severity_counts = Counter(gap.severity for gap in gaps)
    warning_count = severity_counts.get(SEVERITY_WARNING, 0)
    suspicious_count = severity_counts.get(SEVERITY_SUSPICIOUS, 0)
    critical_count = severity_counts.get(SEVERITY_CRITICAL, 0)

    entropy_score = compute_gap_entropy_score(
        gaps=gaps,
        first_timestamp=stats.first_timestamp,
        last_timestamp=stats.last_timestamp,
    )

    highest_confidence = max((gap.tamper_confidence for gap in gaps), default=0.0)
    risk = derive_risk_assessment(
        warning_count=warning_count,
        suspicious_count=suspicious_count,
        critical_count=critical_count,
        entropy_score=entropy_score,
        highest_confidence=highest_confidence,
        error_bursts=stats.error_bursts,
    )

    most_critical = find_most_critical_gap(gaps)
    most_critical_payload: Optional[Dict[str, object]] = None
    if most_critical is not None:
        most_critical_payload = {
            "gap_number": most_critical.gap_number,
            "severity": most_critical.severity,
            "gap_start": most_critical.gap_start.isoformat(),
            "gap_end": most_critical.gap_end.isoformat(),
            "duration_seconds": most_critical.duration_seconds,
            "duration_human": most_critical.duration_human,
            "fingerprint": most_critical.fingerprint,
            "tamper_confidence": most_critical.tamper_confidence,
        }

    return {
        "total_lines_scanned": stats.total_lines,
        "parsed_lines": stats.parsed_lines,
        "malformed_lines": stats.malformed_lines,
        "error_lines": stats.error_lines,
        "error_bursts": stats.error_bursts,
        "total_gaps_found": len(gaps),
        "severity_breakdown": {
            "WARNING": warning_count,
            "SUSPICIOUS": suspicious_count,
            "CRITICAL": critical_count,
        },
        "most_critical_gap": most_critical_payload,
        "risk_assessment": risk,
        "scan_duration_seconds": round(stats.scan_seconds, 3),
        "entropy_score": entropy_score,
        "timeline": build_timeline(
            gaps=gaps,
            first_timestamp=stats.first_timestamp,
            last_timestamp=stats.last_timestamp,
            colorize=False,
        ),
        "integrity_chain": {
            "final_hash": stats.final_chain_hash,
        },
    }


def severity_color(severity: str) -> str:
    if severity == SEVERITY_WARNING:
        return ANSI_YELLOW
    if severity in (SEVERITY_SUSPICIOUS, SEVERITY_CRITICAL):
        return ANSI_RED
    return ANSI_GREEN


def print_gap_card(gap: GapRecord) -> None:
    severity_badge = color_text(f"[{gap.severity}]", severity_color(gap.severity), bold=True)

    print("+" + "-" * 94 + "+")
    print("| Gap #{:03d} {}{}|".format(gap.gap_number, severity_badge, " " * 71))
    print("| Start: {:<84}|".format(gap.gap_start.isoformat(sep=" ")))
    print("| End  : {:<84}|".format(gap.gap_end.isoformat(sep=" ")))
    print("| Duration: {:<80}|".format(f"{gap.duration_human} ({gap.duration_seconds}s)"))
    print("| Lines: {:<83}|".format(f"{gap.line_number_start} -> {gap.line_number_end}"))
    print("| Tamper Confidence: {:<71}|".format(f"{gap.tamper_confidence}/100"))
    print("| Fingerprint (MD5): {:<68}|".format(gap.fingerprint))
    print("| Context Before Gap:{:<76}|".format(""))
    if gap.raw_context_before:
        for item in gap.raw_context_before:
            ln = item["line_number"]
            text = truncate_text(str(item["line"]), 82)
            print("|   [{:<6}] {:<82}|".format(ln, text))
    else:
        print("|   (no preceding context available){:<63}|".format(""))

    print("| Context After Gap :{:<76}|".format(""))
    if gap.raw_context_after:
        for item in gap.raw_context_after:
            ln = item["line_number"]
            text = truncate_text(str(item["line"]), 82)
            print("|   [{:<6}] {:<82}|".format(ln, text))
    else:
        print("|   (no trailing context available){:<64}|".format(""))
    print("+" + "-" * 94 + "+")


def print_terminal_report(
    file_path: Path,
    threshold_seconds: float,
    context_lines: int,
    severity_filter: str,
    custom_format: Optional[str],
    all_gaps_detected: int,
    gaps: Sequence[GapRecord],
    stats: ScanStats,
    summary: Dict[str, object],
    summary_only: bool,
) -> None:
    scan_time = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    first_time = stats.first_timestamp.isoformat(sep=" ") if stats.first_timestamp else "N/A"
    last_time = stats.last_timestamp.isoformat(sep=" ") if stats.last_timestamp else "N/A"

    header_lines = [
        TOOL_NAME,
        f"Version: {TOOL_VERSION}",
        f"Scan Time: {scan_time}",
        f"File: {file_path}",
        (
            f"Threshold: {threshold_seconds} seconds | Context: {context_lines} lines | "
            f"Severity Filter: {severity_filter}"
        ),
        f"Custom Format: {custom_format if custom_format else 'auto-detect'}",
        f"Time Span: {first_time} -> {last_time}",
    ]
    print_ascii_box(header_lines)

    if not gaps:
        print(
            color_text(
                "No gaps matched the requested severity filter. Evidence chain looks continuous.",
                ANSI_GREEN,
                bold=True,
            )
        )
    elif not summary_only:
        for gap in gaps:
            print_gap_card(gap)

    severity_breakdown = summary["severity_breakdown"]
    warning_count = int(severity_breakdown.get("WARNING", 0))
    suspicious_count = int(severity_breakdown.get("SUSPICIOUS", 0))
    critical_count = int(severity_breakdown.get("CRITICAL", 0))
    risk = str(summary["risk_assessment"])

    if risk in (RISK_COMPROMISED, RISK_HIGH):
        risk_color = ANSI_RED
    elif risk in (RISK_MODERATE, RISK_LOW):
        risk_color = ANSI_YELLOW
    else:
        risk_color = ANSI_GREEN

    print()
    print_ascii_box(
        [
            "Summary",
            f"Total lines scanned: {stats.total_lines:,}",
            f"Lines parsed: {stats.parsed_lines:,}",
            f"Malformed lines skipped: {stats.malformed_lines:,}",
            f"Error lines: {stats.error_lines:,}",
            f"Error bursts: {stats.error_bursts:,}",
            f"Total gaps detected (pre-filter): {all_gaps_detected:,}",
            f"Total gaps reported (post-filter): {len(gaps):,}",
            f"WARNING: {warning_count:,} | SUSPICIOUS: {suspicious_count:,} | CRITICAL: {critical_count:,}",
            f"Entropy Score: {summary['entropy_score']} / 100",
            f"Scan Duration: {summary['scan_duration_seconds']} seconds",
            f"Risk Assessment: {risk}",
        ],
        width=96,
    )

    print(color_text("Timeline:", ANSI_CYAN, bold=True))
    timeline_for_terminal = build_timeline(
        gaps=gaps,
        first_timestamp=stats.first_timestamp,
        last_timestamp=stats.last_timestamp,
        colorize=True,
    )
    print("  " + color_text("Start:", ANSI_CYAN, bold=True) + " " + color_text(first_time, ANSI_DIM))
    print("  " + timeline_for_terminal)
    print("  " + color_text("End  :", ANSI_CYAN, bold=True) + " " + color_text(last_time, ANSI_DIM))

    most_critical = summary.get("most_critical_gap")
    if most_critical:
        print()
        print(color_text("Most Critical Gap", ANSI_RED, bold=True))
        severity = str(most_critical.get("severity", "WARNING"))
        severity_badge = color_text(f"[{severity}]", severity_color(severity), bold=True)
        print(
            "  Gap #{gap_number} {severity_badge} {duration_human} ({duration_seconds}s)".format(
                gap_number=most_critical["gap_number"],
                severity_badge=severity_badge,
                duration_human=most_critical["duration_human"],
                duration_seconds=most_critical["duration_seconds"],
            )
        )
        print(
            "  {gap_start} -> {gap_end} | Confidence: {tamper_confidence}/100 | Fingerprint: {fingerprint}".format(
                **most_critical
            )
        )

    print()
    print(color_text(f"Final Risk: {risk}", risk_color, bold=True))


def export_csv(gaps: Sequence[GapRecord], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "gap_number",
                "severity",
                "gap_start",
                "gap_end",
                "duration_seconds",
                "duration_human",
                "line_before_gap",
                "line_after_gap",
                "line_number_start",
                "line_number_end",
                "tamper_confidence",
                "fingerprint",
            ],
        )
        writer.writeheader()

        for gap in gaps:
            writer.writerow(
                {
                    "gap_number": gap.gap_number,
                    "severity": gap.severity,
                    "gap_start": gap.gap_start.isoformat(),
                    "gap_end": gap.gap_end.isoformat(),
                    "duration_seconds": gap.duration_seconds,
                    "duration_human": gap.duration_human,
                    "line_before_gap": gap.line_before_gap,
                    "line_after_gap": gap.line_after_gap,
                    "line_number_start": gap.line_number_start,
                    "line_number_end": gap.line_number_end,
                    "tamper_confidence": gap.tamper_confidence,
                    "fingerprint": gap.fingerprint,
                }
            )

    return output_path


def serialize_gap(gap: GapRecord) -> Dict[str, object]:
    return {
        "gap_number": gap.gap_number,
        "severity": gap.severity,
        "gap_start": gap.gap_start.isoformat(),
        "gap_end": gap.gap_end.isoformat(),
        "duration_seconds": gap.duration_seconds,
        "duration_human": gap.duration_human,
        "line_before_gap": gap.line_before_gap,
        "line_after_gap": gap.line_after_gap,
        "line_number_start": gap.line_number_start,
        "line_number_end": gap.line_number_end,
        "tamper_confidence": gap.tamper_confidence,
        "fingerprint": gap.fingerprint,
        "raw_context": {
            "before": gap.raw_context_before,
            "after": gap.raw_context_after,
        },
    }


def export_json(
    file_path: Path,
    output_path: Path,
    threshold_seconds: float,
    custom_format: Optional[str],
    severity_filter: str,
    context_lines: int,
    gaps: Sequence[GapRecord],
    stats: ScanStats,
    summary: Dict[str, object],
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    json_payload = {
        "scan_metadata": {
            "tool_name": TOOL_NAME,
            "version": TOOL_VERSION,
            "scan_time": dt.datetime.now().isoformat(),
            "analyst_note": "Automated scan completed by Evidence Protector.",
        },
        "file_info": {
            "filename": file_path.name,
            "file_size": stats.file_size,
            "total_lines": stats.total_lines,
            "parsed_lines": stats.parsed_lines,
            "malformed_lines": stats.malformed_lines,
            "error_lines": stats.error_lines,
            "error_bursts": stats.error_bursts,
        },
        "configuration": {
            "threshold_seconds": threshold_seconds,
            "custom_format": custom_format,
            "severity_filter": severity_filter,
            "context_lines": context_lines,
        },
        "gaps": [serialize_gap(gap) for gap in gaps],
        "summary": summary,
    }

    with output_path.open("w", encoding="utf-8") as json_file:
        json.dump(json_payload, json_file, indent=2)

    return output_path


def determine_exit_code(gaps: Sequence[GapRecord]) -> int:
    has_warning = any(gap.severity == SEVERITY_WARNING for gap in gaps)
    has_suspicious_or_critical = any(
        gap.severity in (SEVERITY_SUSPICIOUS, SEVERITY_CRITICAL) for gap in gaps
    )

    if has_suspicious_or_critical:
        return 2
    if has_warning:
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_log = script_dir.parent / "data" / "sample" / "sample.log"
    default_csv = script_dir.parent / "data" / "reports" / "integrity_report.csv"

    parser = argparse.ArgumentParser(
        description="Evidence Protector - Automated Log Integrity Monitor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Legacy args (kept for compatibility with existing backend/frontend flow).
    parser.add_argument("--file", default=str(default_log), help="Path to input log file")
    parser.add_argument("--out", default=str(default_csv), help="CSV output path")
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD_SECONDS,
        help="Minimum gap threshold in seconds",
    )

    # Advanced forensic options.
    parser.add_argument(
        "--format",
        dest="custom_format",
        default=None,
        help="Optional custom strptime format (e.g. %%Y-%%m-%%d %%H:%%M:%%S)",
    )
    parser.add_argument(
        "--severity",
        choices=[SEVERITY_WARNING, SEVERITY_SUSPICIOUS, SEVERITY_CRITICAL],
        default=SEVERITY_WARNING,
        help="Minimum severity level to report",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show only summary in terminal output",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=DEFAULT_CONTEXT_LINES,
        help="Number of context lines before/after each gap",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional JSON output path",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Disable CSV export",
    )

    args = parser.parse_args()

    if args.threshold <= 0:
        parser.error("--threshold must be greater than 0")
    if args.context < 0:
        parser.error("--context must be 0 or greater")

    return args


def print_required_summary(stats: ScanStats, gaps: Sequence[GapRecord], summary: Dict[str, object]) -> None:
    # These exact lines are required by the frontend parser.
    print(f"Lines parsed {stats.parsed_lines}", flush=True)
    print(f"Time gaps detected {len(gaps)}", flush=True)
    print(f"Error bursts {stats.error_bursts}", flush=True)
    print(f"Risk level {summary.get('risk_assessment', RISK_CLEAN)}", flush=True)


def main() -> int:
    args = parse_args()

    file_path = Path(args.file)
    if not file_path.exists():
        print(color_text(f"Error: file not found: {file_path}", ANSI_RED, bold=True), file=sys.stderr)
        return 3
    if not file_path.is_file():
        print(color_text(f"Error: path is not a file: {file_path}", ANSI_RED, bold=True), file=sys.stderr)
        return 3

    animate_banner()

    try:
        all_gaps, stats = scan_log_file(
            path=file_path,
            threshold_seconds=args.threshold,
            context_lines=args.context,
            custom_format=args.custom_format,
        )
    except ValueError as exc:
        print(color_text(f"Configuration error: {exc}", ANSI_RED, bold=True), file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n" + color_text("Scan interrupted by user.", ANSI_RED, bold=True), file=sys.stderr)
        return 3
    except Exception as exc:
        print(color_text(f"Unexpected scan failure: {exc}", ANSI_RED, bold=True), file=sys.stderr)
        return 3

    filtered_gaps = filter_gaps_by_severity(all_gaps, args.severity)
    summary = build_summary(filtered_gaps, stats)

    print_terminal_report(
        file_path=file_path,
        threshold_seconds=args.threshold,
        context_lines=args.context,
        severity_filter=args.severity,
        custom_format=args.custom_format,
        all_gaps_detected=len(all_gaps),
        gaps=filtered_gaps,
        stats=stats,
        summary=summary,
        summary_only=args.summary,
    )

    export_paths: List[Path] = []
    if not args.no_csv:
        csv_path = export_csv(filtered_gaps, Path(args.out))
        export_paths.append(csv_path)

    if args.json_out:
        json_path = export_json(
            file_path=file_path,
            output_path=Path(args.json_out),
            threshold_seconds=args.threshold,
            custom_format=args.custom_format,
            severity_filter=args.severity,
            context_lines=args.context,
            gaps=filtered_gaps,
            stats=stats,
            summary=summary,
        )
        export_paths.append(json_path)

    if export_paths:
        print()
        print(color_text("Exported reports", ANSI_CYAN, bold=True))
        for path in export_paths:
            print("  - " + color_text(str(path), ANSI_DIM))

    print()
    print(color_text("Structured summary:", ANSI_CYAN, bold=True))
    print(json.dumps(summary, indent=2))
    print()
    print_required_summary(stats, filtered_gaps, summary)

    return determine_exit_code(filtered_gaps)


if __name__ == "__main__":
    raise SystemExit(main())