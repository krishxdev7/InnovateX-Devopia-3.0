"""
Sample Log Generator for Evidence Protector
This creates a realistic sample.log file with planted suspicious gaps.
"""

import random
import os
from datetime import datetime, timedelta

# Log event templates
EVENTS = [
    "User 'admin' logged in from 192.168.1.{ip}",
    "File '/var/www/html/index.php' accessed",
    "Database query executed on table 'users'",
    "Firewall rule applied: ALLOW port 443",
    "Backup process started for '/home/data'",
    "SSH session opened for user 'root'",
    "System health check: CPU {cpu}% | RAM {ram}%",
    "API request received: GET /api/v1/users",
    "Authentication token refreshed for session {sid}",
    "Cron job executed: /etc/cron.daily/logrotate",
    "DNS query resolved: google.com -> 142.250.{x}.{y}",
    "File permission changed on '/etc/passwd'",
    "New process spawned: PID {pid}",
    "Network packet dropped from 10.0.0.{ip}",
    "Service 'nginx' restarted successfully",
]

LOG_LEVELS = ["INFO", "INFO", "INFO", "INFO", "WARNING", "ERROR"]  # weighted

def random_event():
    event = random.choice(EVENTS)
    return event.format(
        ip=random.randint(1, 255),
        cpu=random.randint(10, 95),
        ram=random.randint(20, 90),
        sid=random.randint(1000, 9999),
        pid=random.randint(1000, 99999),
        x=random.randint(1, 255),
        y=random.randint(1, 255),
    )

def generate_log(filepath):
    lines = []
    # Ensure the directory exists
    directory = os.path.dirname(filepath)
    if directory:
        os.makedirs(directory, exist_ok=True)

    # Start time: yesterday at 10:00 PM
    current_time = datetime.now().replace(hour=22, minute=0, second=0, microsecond=0)
    current_time -= timedelta(days=1)

    print(f"[*] Generating log file: {filepath}")

    # ── Block 1: Normal logs ─────────────────────────────────────────────────
    for _ in range(80):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 120))

    # ── PLANTED GAPS ─────────────────────────────────────────────────────────
    # Gap 1 (CRITICAL)
    current_time += timedelta(hours=2, minutes=17)
    # Block 2
    for _ in range(40):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 90))

    # Gap 2 (HIGH)
    current_time += timedelta(minutes=45)
    # Block 3
    for _ in range(40):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 60))

    # Gap 3 (MEDIUM)
    current_time += timedelta(minutes=12)
    # Block 4
    for _ in range(40):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 60))

    # ── Sprinkle malformed lines ──────────────────────────────────────────────
    malformed = [
        "This line has no timestamp at all",
        "ERROR something went wrong badly!!",
        "------------------------------------",
        "2024-99-99 25:61:99 [BAD] Totally broken timestamp",
        "",
        "   ",
    ]
    insert_positions = random.sample(range(len(lines)), min(6, len(lines)))
    for i, pos in enumerate(sorted(insert_positions)):
        lines.insert(pos, malformed[i % len(malformed)])

    # ── Write to file ─────────────────────────────────────────────────────────
    with open(filepath, "w", encoding='utf-8') as f:
        f.write("\n".join(lines))

    print(f"\n[OK] Done! Log generated: {filepath}")
    print(f"Now run: python log_monitor.py --log {filepath}")


if __name__ == "__main__":
    # AUTOMATIC PATH FINDER:
    # This finds the new data/sample folder no matter where you run it from.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_path = os.path.normpath(os.path.join(script_dir, "..", "data", "sample", "sample.log"))
    
    generate_log(target_path)