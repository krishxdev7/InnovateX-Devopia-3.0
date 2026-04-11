from datetime import datetime, timedelta
import random

levels = ["INFO", "WARNING", "ERROR", "DEBUG", "CRITICAL"]

messages = [
    "User login successful",
    "File accessed",
    "Disk usage normal",
    "Background job started",
    "API request received",
    "Cache cleared",
    "System health OK",
    "Backup process initiated",
    "Network packet received",
    "Service restarted",
    "Database connection established",
    "Unauthorized access attempt detected",
    "System rebooted unexpectedly"
]

start_time = datetime(2026, 4, 11, 9, 59, 50)

def generate_log(filename, lines=200):
    current_time = start_time

    with open(filename, "w") as f:
        for i in range(lines):

            # normal time progression
            if random.random() < 0.08:  
                # 💀 inject big gap (tampering simulation)
                current_time += timedelta(minutes=random.randint(20, 300))
            else:
                current_time += timedelta(seconds=random.randint(1, 10))

            log = f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} {random.choice(levels)} {random.choice(messages)}\n"
            f.write(log)

    print(f"✅ Generated {filename} with {lines} lines")

# 🔥 generate multiple files
generate_log("sample_100.log", 100)
generate_log("sample_200.log", 200)
generate_log("sample_300.log", 300)