import argparse
import csv
import json
import os
import re
import sys
import hashlib
from collections import defaultdict, deque
from datetime import datetime

# ── TIMESTAMP FORMAT REGISTRY ──────────────────────────────────────────────────
TIMESTAMP_REGISTRY = [
    ("%Y-%m-%dT%H:%M:%S", re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")),
    ("%Y-%m-%d %H:%M:%S", re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")),
    ("%Y/%m/%d %H:%M:%S", re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")),
    ("%d/%b/%Y:%H:%M:%S", re.compile(r"^\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}")),
    ("%b %d %H:%M:%S", re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}")),
]

LOGIN_KEYWORDS = {"login", "logout", "auth", "session", "signin", "signout", "authenticate", "password", "credential", "token", "oauth"}
ERROR_KEYWORDS = {"error", "exception", "traceback", "critical", "fatal", "fail", "failed", "failure", "panic", "alert", "denied"}

RE_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_USER = re.compile(r"(?:user[=:\s]+|username[=:\s]+|uid[=:\s]+|u[=:\s]+)([A-Za-z0-9_@.\-]+)", re.IGNORECASE)
RE_DYNPART = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d+)\b", re.IGNORECASE)

# Standard colors
RED, YELLOW, GREEN, CYAN, BOLD, DIM, RESET = "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[1m", "\033[2m", "\033[0m"

def c(color: str, text: str) -> str:
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text

def parse_line(line: str):
    for fmt, pattern in TIMESTAMP_REGISTRY:
        m = pattern.match(line)
        if not m: continue
        try:
            ts = datetime.strptime(m.group(0), fmt)
            end = m.end()
            while end < len(line) and line[end] in " [\t|-": end += 1
            return ts, line[end:].strip(), end
        except ValueError: continue
    return None, line, 0

def format_duration(sec: float) -> str:
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s" if h else f"{m}m {s}s" if m else f"{s}s"

def analyze(filepath: str, cfg: dict) -> dict:
    time_gaps, stats = [], defaultdict(int)
    prev_ts, first_ts, last_ts = None, None, None
    prev_hash = "0" * 64

    with open(filepath, "r", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            stats["total"] += 1
            line = raw.rstrip("\n")
            if not line.strip(): continue
            ts, _, _ = parse_line(line)
            if not ts: continue
            stats["parsed"] += 1
            if not first_ts: first_ts = ts
            last_ts = ts
            
            curr_hash = hashlib.sha256((line + prev_hash).encode("utf-8", errors="replace")).hexdigest()
            prev_hash = curr_hash

            if prev_ts:
                delta = (ts - prev_ts).total_seconds()
                if delta > cfg["threshold"]:
                    time_gaps.append({"from": prev_ts, "to": ts, "delta": delta, "severity": "HIGH" if delta > 3600 else "MEDIUM", "lineno": lineno})
            prev_ts = ts

    duration_hours = max((last_ts - first_ts).total_seconds() / 3600, 1.0) if first_ts and last_ts else 1.0
    return {"gaps": time_gaps, "stats": {**dict(stats), "duration_hours": round(duration_hours, 2)}, "chain": {"final_hash": prev_hash}}

def report_csv(res: dict, outpath: str):
    rows = []
    for g in res["gaps"]:
        rows.append({"type": "GAP", "severity": g["severity"], "from": g["from"].isoformat(), "to": g["to"].isoformat(), "duration": format_duration(g["delta"]), "detail": f"line {g['lineno']}"})
    
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "severity", "from", "to", "duration", "detail"])
        writer.writeheader()
        writer.writerows(rows)
    # FIXED: Replaced Unicode emoji with standard [OK] to prevent crash
    print(c(GREEN, f"\n[OK] CSV report generated successfully: {outpath}"))

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log = os.path.normpath(os.path.join(script_dir, "..", "sample-logs", "sample.log"))
    default_csv = os.path.normpath(os.path.join(script_dir, "..", "reports", "integrity_report.csv"))

    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default=default_log)
    parser.add_argument("--out", default=default_csv)
    parser.add_argument("--threshold", type=int, default=300)
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(c(RED, f"Error: Log file not found at {args.file}"))
        return

    print(c(CYAN, f"[*] Analyzing: {args.file}"))
    res = analyze(args.file, {"threshold": args.threshold})
    report_csv(res, args.out)

if __name__ == "__main__":
    main()