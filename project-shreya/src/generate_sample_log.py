"""
Sample Log Generator for Evidence Protector
Run: python generate_sample_log.py
This creates a realistic sample.log file with planted suspicious gaps.
"""

import random
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

def generate_log(filename="sample.log"):
    lines = []
    # Start time: yesterday at 10:00 PM
    current_time = datetime.now().replace(hour=22, minute=0, second=0, microsecond=0)
    current_time -= timedelta(days=1)

    print(f"[*] Generating log file: {filename}")

    # ── Block 1: Normal logs (10 PM to 2 AM) ─────────────────────────────────
    print("[*] Writing normal activity block 1...")
    for _ in range(80):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 120))

    # ── PLANTED GAP 1: 2 hour 17 min gap (hacker deletes logs!) ──────────────
    gap1_start = current_time
    current_time += timedelta(hours=2, minutes=17)
    gap1_end = current_time
    print(f"[!] Planted CRITICAL gap 1: {gap1_start.strftime('%H:%M:%S')} → {gap1_end.strftime('%H:%M:%S')} (2hr 17min)")

    # ── Block 2: Logs resume after gap ───────────────────────────────────────
    print("[*] Writing post-gap activity block 2...")
    for _ in range(40):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 90))

    # ── PLANTED GAP 2: 45 min gap (second tampering) ─────────────────────────
    gap2_start = current_time
    current_time += timedelta(minutes=45)
    gap2_end = current_time
    print(f"[!] Planted HIGH gap 2: {gap2_start.strftime('%H:%M:%S')} → {gap2_end.strftime('%H:%M:%S')} (45min)")

    # ── Block 3: More normal logs ─────────────────────────────────────────────
    print("[*] Writing normal activity block 3...")
    for _ in range(40):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 60))

    # ── PLANTED GAP 3: 12 min gap (minor/medium suspicion) ───────────────────
    gap3_start = current_time
    current_time += timedelta(minutes=12)
    gap3_end = current_time
    print(f"[!] Planted MEDIUM gap 3: {gap3_start.strftime('%H:%M:%S')} → {gap3_end.strftime('%H:%M:%S')} (12min)")

    # ── Block 4: Final normal logs ────────────────────────────────────────────
    print("[*] Writing final activity block...")
    for _ in range(40):
        level = random.choice(LOG_LEVELS)
        lines.append(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {random_event()}")
        current_time += timedelta(seconds=random.randint(5, 60))

    # ── Sprinkle malformed lines (tests error handling) ───────────────────────
    print("[*] Sprinkling malformed lines...")
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
    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"\n✅ Done! Generated {len(lines)} lines → '{filename}'")
    print(f"   🚨 3 suspicious gaps planted for detection")
    print(f"   ⚠️  6 malformed lines added to test error handling")
    print(f"\nNow run: python monitor.py --log {filename} --threshold 10")


if __name__ == "__main__":
    generate_log("sample.log")
