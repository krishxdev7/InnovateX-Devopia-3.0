import csv
import sys
from datetime import datetime

def parse_timestamp(line):
    try:
        return datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
    except:
        return None

def scan_log(file_path, threshold):
    prev_time = None
    gaps = []

    with open(file_path, 'r') as f:
        for line_no, line in enumerate(f, start=1):
            
            timestamp = parse_timestamp(line)

            if timestamp is None:
                print(f"[!] Skipping malformed line {line_no}")
                continue

            if prev_time:
                gap = (timestamp - prev_time).total_seconds()

                if gap > threshold:
                    print("\n🚨 Suspicious Gap Detected!")
                    print(f"Start : {prev_time}")
                    print(f"End   : {timestamp}")
                    print(f"Gap   : {gap} seconds")

                    gaps.append((prev_time, timestamp, gap))

            prev_time = timestamp
        return gaps
        
def save_to_csv(gaps, filename="report.csv"):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)

        # header row
        writer.writerow(["Start Time", "End Time", "Gap (seconds)"])

        # data rows
        for start, end, gap in gaps:
            writer.writerow([start, end, gap])

    print(f"\n📁 Report saved to {filename}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python log_monitor.py <logfile> <threshold_seconds>")
        sys.exit(1)

    logfile = sys.argv[1]
    threshold = int(sys.argv[2])

    gaps = scan_log(logfile, threshold)

    if gaps:
        save_to_csv(gaps)
        print(f"\nTotal gaps detected: {len(gaps)}")
    else:
        print("\n✅ No suspicious gaps found")