#!/usr/bin/env python3
"""
The Evidence Protector - Automated Log Integrity Monitor
=========================================================
Scans log files, extracts timestamps, and flags suspicious time gaps
that may indicate log tampering or deletion.

Usage:
    python log_integrity_monitor.py --file sample.log
    python log_integrity_monitor.py --file sample.log --threshold 300
    python log_integrity_monitor.py --file sample.log --threshold 300 --output reports/report.csv
"""

import argparse
import csv
import os
import sys
from datetime import datetime

# ── Timestamp formats to try ──────────────────────────────────────────────────
TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%b %d %H:%M:%S",
]

# ── Terminal colors (no external libs needed) ─────────────────────────────────
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
DIM     = "\033[2m"


# ─────────────────────────────────────────────────────────────────────────────
# Timestamp extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_timestamp(line: str) -> datetime | None:
    """Try all known formats against the first 25 characters of a line."""
    prefix = line[:25].strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            # Only parse as many chars as the format needs
            ts = datetime.strptime(prefix[: len(fmt) + 2], fmt)
            return ts
        except ValueError:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Core analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_log(filepath: str, threshold_seconds: int):
    """
    Parse the log file line by line.
    Returns:
        gaps        - list of dicts with gap info
        stats       - summary statistics dict
    """
    gaps = []
    stats = {
        "total_lines"    : 0,
        "parsed_lines"   : 0,
        "skipped_lines"  : 0,
        "gaps_found"     : 0,
        "first_timestamp": None,
        "last_timestamp" : None,
        "log_duration_s" : 0,
    }

    prev_ts   = None
    prev_line = None
    prev_lineno = 0

    try:
        with open(filepath, "r", errors="replace") as f:
            for lineno, raw_line in enumerate(f, start=1):
                stats["total_lines"] += 1
                line = raw_line.strip()

                if not line:
                    stats["skipped_lines"] += 1
                    continue

                ts = extract_timestamp(line)

                if ts is None:
                    stats["skipped_lines"] += 1
                    continue

                stats["parsed_lines"] += 1

                # Track first/last timestamps
                if stats["first_timestamp"] is None:
                    stats["first_timestamp"] = ts
                stats["last_timestamp"] = ts

                # Gap detection
                if prev_ts is not None:
                    delta = (ts - prev_ts).total_seconds()

                    if delta < 0:
                        # Timestamp went backwards — also suspicious
                        gaps.append({
                            "type"            : "BACKWARD",
                            "gap_start"       : prev_ts,
                            "gap_end"         : ts,
                            "duration_seconds": abs(delta),
                            "start_line"      : prev_lineno,
                            "end_line"        : lineno,
                            "start_entry"     : prev_line,
                            "end_entry"       : line,
                        })
                        stats["gaps_found"] += 1

                    elif delta > threshold_seconds:
                        gaps.append({
                            "type"            : "FORWARD",
                            "gap_start"       : prev_ts,
                            "gap_end"         : ts,
                            "duration_seconds": delta,
                            "start_line"      : prev_lineno,
                            "end_line"        : lineno,
                            "start_entry"     : prev_line,
                            "end_entry"       : line,
                        })
                        stats["gaps_found"] += 1

                prev_ts     = ts
                prev_line   = line
                prev_lineno = lineno

    except FileNotFoundError:
        print(f"{RED}[ERROR]{RESET} File not found: {filepath}")
        sys.exit(1)

    if stats["first_timestamp"] and stats["last_timestamp"]:
        stats["log_duration_s"] = (
            stats["last_timestamp"] - stats["first_timestamp"]
        ).total_seconds()

    return gaps, stats


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    h, rem  = divmod(seconds, 3600)
    m, s    = divmod(rem, 60)
    parts   = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def severity(duration_seconds: float) -> str:
    if duration_seconds >= 3600:
        return f"{RED}HIGH{RESET}"
    elif duration_seconds >= 600:
        return f"{YELLOW}MEDIUM{RESET}"
    else:
        return f"{GREEN}LOW{RESET}"


# ─────────────────────────────────────────────────────────────────────────────
# Terminal report
# ─────────────────────────────────────────────────────────────────────────────

def print_report(gaps: list, stats: dict, filepath: str, threshold: int):
    width = 70
    bar   = "─" * width

    print()
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"{BOLD}{CYAN}  THE EVIDENCE PROTECTOR — Log Integrity Report{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}")
    print()

    # ── File summary ──
    print(f"{BOLD}  File     :{RESET} {filepath}")
    print(f"{BOLD}  Threshold:{RESET} {format_duration(threshold)} ({threshold}s)")
    print(f"{BOLD}  Log span :{RESET} "
          f"{stats['first_timestamp']} → {stats['last_timestamp']} "
          f"({format_duration(stats['log_duration_s'])})")
    print()
    print(f"  {DIM}{bar}{RESET}")
    print(f"  Total lines   : {stats['total_lines']}")
    print(f"  Parsed lines  : {GREEN}{stats['parsed_lines']}{RESET}")
    print(f"  Skipped lines : {YELLOW}{stats['skipped_lines']}{RESET}  "
          f"{DIM}(malformed / empty){RESET}")
    print(f"  Gaps detected : "
          f"{RED if stats['gaps_found'] else GREEN}{stats['gaps_found']}{RESET}")
    print(f"  {DIM}{bar}{RESET}")
    print()

    if not gaps:
        print(f"  {GREEN}{BOLD}✔  No suspicious gaps found. Log appears intact.{RESET}")
        print()
        return

    # ── Gap table ──
    print(f"  {BOLD}SUSPICIOUS GAPS DETECTED:{RESET}")
    print()

    for i, gap in enumerate(gaps, start=1):
        sev   = severity(gap["duration_seconds"])
        gtype = f"{RED}⚠ BACKWARD JUMP{RESET}" if gap["type"] == "BACKWARD" else f"{RED}⚠ FORWARD GAP{RESET}"

        print(f"  {BOLD}[GAP #{i}]{RESET}  Severity: {sev}  |  {gtype}")
        print(f"  {'─' * 60}")
        print(f"  Gap Start  : {gap['gap_start']}  (line {gap['start_line']})")
        print(f"  Gap End    : {gap['gap_end']}  (line {gap['end_line']})")
        print(f"  Duration   : {RED}{BOLD}{format_duration(gap['duration_seconds'])}{RESET} "
              f"({gap['duration_seconds']:.0f}s)")
        print(f"  Last entry : {DIM}{gap['start_entry'][:70]}{RESET}")
        print(f"  Next entry : {DIM}{gap['end_entry'][:70]}{RESET}")
        print()

    print(f"{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"  {RED}{BOLD}⚠  {stats['gaps_found']} suspicious gap(s) found — possible log tampering!{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CSV export
# ─────────────────────────────────────────────────────────────────────────────

def export_csv(gaps: list, stats: dict, out_path: str):
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)

    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)

        # Header
        writer.writerow([
            "gap_number", "type", "severity",
            "gap_start", "gap_end",
            "duration_seconds", "duration_human",
            "start_line", "end_line",
            "last_log_entry", "next_log_entry",
        ])

        for i, gap in enumerate(gaps, start=1):
            sev = (
                "HIGH"   if gap["duration_seconds"] >= 3600 else
                "MEDIUM" if gap["duration_seconds"] >= 600  else
                "LOW"
            )
            writer.writerow([
                i,
                gap["type"],
                sev,
                gap["gap_start"],
                gap["gap_end"],
                f"{gap['duration_seconds']:.0f}",
                format_duration(gap["duration_seconds"]),
                gap["start_line"],
                gap["end_line"],
                gap["start_entry"],
                gap["end_entry"],
            ])

    print(f"{GREEN}[✔] CSV report saved to: {out_path}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="The Evidence Protector — Automated Log Integrity Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_integrity_monitor.py --file sample.log
  python log_integrity_monitor.py --file sample.log --threshold 300
  python log_integrity_monitor.py --file sample.log --threshold 300 --output reports/report.csv
        """,
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to the log file to analyze",
    )
    parser.add_argument(
        "--threshold", "-t",
        type=int,
        default=300,
        help="Gap threshold in seconds (default: 300 = 5 minutes)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional: path to save CSV report (e.g. reports/report.csv)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"\n{CYAN}[*] Scanning: {args.file}  |  Threshold: {args.threshold}s{RESET}")

    gaps, stats = analyze_log(args.file, args.threshold)
    print_report(gaps, stats, args.file, args.threshold)

    if args.output:
        export_csv(gaps, stats, args.output)


if __name__ == "__main__":
    main()
