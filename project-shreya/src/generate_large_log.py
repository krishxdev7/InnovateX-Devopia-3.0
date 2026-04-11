"""
Large Log File Generator — Evidence Protector
Generates a realistic 100,000+ line log file with suspicious events.
"""

import argparse
import random
from datetime import datetime, timedelta
import os

# ── Config ─────────────────────────────────────────────────────────────

LEVELS = ["INFO", "INFO", "INFO", "WARNING", "ERROR", "DEBUG"]
SERVICES = ["webserver", "database", "auth", "firewall", "system"]

MESSAGES = {
    "webserver": [
        "GET /api/users/{} 200 {}ms",
        "POST /api/login 200 {}ms user_id={}",
        "GET /static/main.js 304 {}ms",
        "POST /api/data 500 {}ms - Internal Server Error",
        "GET /admin/panel 403 {}ms - Forbidden",
        "DELETE /api/session/{} 200 {}ms",
        "PUT /api/profile/{} 200 {}ms",
    ],
    "database": [
        "Query executed in {}ms: SELECT * FROM users WHERE id={}",
        "Connection pool size: {}/100",
        "Index scan on table 'logs' took {}ms",
        "Slow query detected ({}ms): SELECT * FROM events",
        "Transaction committed: txn_id={}",
        "Deadlock detected between txn {} and txn {}",
        "Backup completed: {}MB written",
    ],
    "auth": [
        "User login successful: user_id={} ip=192.168.1.{}",
        "Failed login attempt: user='admin' ip=10.0.0.{}",
        "Password reset requested for user_id={}",
        "Session created: session_id={} user_id={}",
        "Session expired: session_id={}",
        "2FA verification passed for user_id={}",
        "Account locked after {} failed attempts: user_id={}",
    ],
    "firewall": [
        "ALLOW TCP 192.168.1.{} -> 10.0.0.{} port 443",
        "BLOCK UDP 203.0.113.{} -> 10.0.0.1 port 22",
        "ALLOW TCP 10.0.0.{} -> 8.8.8.8 port 53",
        "BLOCK ICMP flood from 198.51.100.{}",
        "Rate limit applied to 192.168.1.{}: {} req/s",
        "Port scan detected from 203.0.113.{}",
        "Firewall rule applied: ALLOW port {} for ip=10.0.0.{}",
    ],
    "system": [
        "CPU usage: {}%",
        "Memory usage: {}MB / 8192MB",
        "Disk I/O: {}MB/s read, {}MB/s write",
        "Process started: pid={} name=python3",
        "Process exited: pid={} code=0",
        "Scheduled task 'backup' started",
        "System uptime: {} hours",
        "Network interface eth0: {}Mbps",
    ],
}

MALFORMED = [
    "MALFORMED LINE - corrupted entry",
    "null null null",
    "",
    "---SYSTEM RESTART---",
    "binary data: \\x00\\x01\\x02",
    "timestamp missing [INFO] something happened",
]

# ── Helpers ───────────────────────────────────────────────────────────

def rand_msg(service):
    template = random.choice(MESSAGES[service])
    filled = ""
    i = 0
    while i < len(template):
        if template[i:i+2] == "{}":
            filled += str(random.randint(1, 9999))
            i += 2
        else:
            filled += template[i]
            i += 1
    return filled


def fmt(ts, level, service, msg):
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S')} [{level}] [{service}] {msg}"

# ── Generator ─────────────────────────────────────────────────────────

def generate(total_lines: int, output: str):
    lines = []
    ts = datetime(2026, 1, 1, 0, 0, 0)
    gaps_inserted = []
    suspicious_count = 0

    # Ensure the directory exists
    directory = os.path.dirname(output)
    if directory:
        os.makedirs(directory, exist_ok=True)

    print(f"[*] Generating {total_lines:,} log lines... please wait")

    block_sizes = []
    remaining = total_lines
    num_blocks = 10

    for i in range(num_blocks - 1):
        size = random.randint(int(remaining * 0.05), int(remaining * 0.15))
        block_sizes.append(size)
        remaining -= size

    block_sizes.append(remaining)
    random.shuffle(block_sizes)

    for block_idx, block_size in enumerate(block_sizes):

        # Normal logs
        for _ in range(block_size):
            ts += timedelta(seconds=random.randint(1, 15))
            service = random.choice(SERVICES)
            level = random.choice(LEVELS)
            msg = rand_msg(service)
            lines.append(fmt(ts, level, service, msg))

        if block_idx == len(block_sizes) - 1:
            break

        # Suspicious events
        event = random.choice(["gap", "gap", "gap", "error_burst", "after_hours", "duplicate"])

        if event == "gap":
            gap_minutes = random.randint(20, 180)
            gap_start = ts
            ts += timedelta(minutes=gap_minutes)

            gaps_inserted.append({
                "type": "GAP",
                "at_line": len(lines),
                "duration": f"{gap_minutes} minutes",
                "from": gap_start,
                "to": ts,
            })
            suspicious_count += 1

        elif event == "error_burst":
            burst = random.randint(50, 200)
            for _ in range(burst):
                ts += timedelta(seconds=random.randint(0, 2))
                service = random.choice(["auth", "firewall", "webserver"])
                msg = rand_msg(service)
                lines.append(fmt(ts, "ERROR", service, msg))

            gaps_inserted.append({
                "type": "ERROR BURST",
                "at_line": len(lines),
                "duration": f"{burst} rapid ERROR lines",
                "from": ts,
                "to": ts,
            })
            suspicious_count += 1

        elif event == "after_hours":
            ts = ts.replace(hour=random.randint(2, 4), minute=random.randint(0, 59))
            for _ in range(random.randint(10, 30)):
                ts += timedelta(seconds=random.randint(5, 60))
                lines.append(fmt(ts, "WARNING", "auth",
                    f"After-hours login: user_id={random.randint(1,999)} ip=203.0.113.{random.randint(1,254)}"))
            suspicious_count += 1

        elif event == "duplicate":
            dup_ts = ts
            for _ in range(random.randint(5, 20)):
                service = random.choice(SERVICES)
                lines.append(fmt(dup_ts, "INFO", service, rand_msg(service)))
            suspicious_count += 1

        if random.random() < 0.4:
            lines.append(random.choice(MALFORMED))

    # Write file using UTF-8 encoding for safety
    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    size_mb = round(os.path.getsize(output) / (1024 * 1024), 2)

    print("\n" + "="*55)
    print("  Log file generated successfully!")
    print("="*55)
    print(f"  File             : {output}")
    print(f"  Total lines      : {len(lines):,}")
    print(f"  File size        : {size_mb} MB")
    print(f"  Log period       : 2026-01-01 -> {ts.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Suspicious events planted : {suspicious_count}")
    print("="*55)

    print("\n  Planted events breakdown:")
    for i, g in enumerate(gaps_inserted, 1):
        print(f"  [{i}] {g['type']:15} | {g['duration']} | line ~{g['at_line']:,}")

    print("\n  Now run:")
    print(f"  python log_integrity_monitor.py --file {output}")
    print()

# ── CLI ───────────────────────────────────────────────────────────────

def parse_args():
    # Find the correct path inside project-shreya/sample-logs
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_output = os.path.normpath(os.path.join(script_dir, "..", "sample-logs", "large_sample.log"))

    parser = argparse.ArgumentParser(description="Generate a large realistic log file for testing")
    parser.add_argument("--lines", type=int, default=100000)
    parser.add_argument("--output", type=str, default=default_output)
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    generate(args.lines, args.output)