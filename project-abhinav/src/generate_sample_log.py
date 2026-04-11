#!/usr/bin/env python3
"""
Generate a realistic sample log file with intentional gaps for testing.
Usage: python generate_sample_log.py
"""

import random
from datetime import datetime, timedelta

LEVELS = ["INFO", "WARNING", "ERROR", "DEBUG"]
MESSAGES = [
    "User login successful for user_id={}",
    "Request processed in {}ms — endpoint /api/data",
    "Cache miss — fetching from database",
    "Session token refreshed for session_id={}",
    "Disk usage at {}% on /dev/sda1",
    "Background job completed: task_id={}",
    "Rate limit triggered for IP 192.168.1.{}",
    "Database query executed in {}ms",
    "File uploaded: size={}KB",
    "Health check passed",
]

def generate_log(path: str = "sample.log"):
    lines = []
    ts = datetime(2024, 3, 10, 0, 0, 0)

    def add_block(count, jitter_max=30):
        nonlocal ts
        for _ in range(count):
            ts += timedelta(seconds=random.randint(1, jitter_max))
            level = random.choice(LEVELS)
            msg = random.choice(MESSAGES).format(random.randint(1, 9999))
            lines.append(f"{ts.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {msg}")

    # Normal activity for 2 hours
    add_block(400, 18)

    # ── GAP 1: 47 minutes (suspicious) ──────────────────────────
    ts += timedelta(minutes=47)

    add_block(150, 20)

    # Malformed / noisy lines (no timestamp)
    lines.append("--- Log rotated ---")
    lines.append("WARNING: disk threshold exceeded")
    lines.append("")

    add_block(100, 15)

    # ── GAP 2: 3 hours 12 minutes (critical) ────────────────────
    ts += timedelta(hours=3, minutes=12)

    add_block(200, 25)

    # ── GAP 3: 8 minutes (borderline — just over 5-min threshold) ─
    ts += timedelta(minutes=8)

    add_block(300, 12)

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"✅ Sample log written to '{path}'  ({len(lines)} lines)")
    print(f"   Known gaps: ~47 min, ~3h 12m, ~8 min")
    print(f"   Run: python log_monitor.py {path} --threshold 300\n")

if __name__ == "__main__":
    generate_log()
