#!/usr/bin/env python3
"""Generate a realistic sample log with intentional integrity gaps."""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

LEVELS = ("INFO", "WARNING", "ERROR", "DEBUG")
MESSAGES = (
    "User login successful for user_id={id}",
    "Request processed in {value}ms for /api/data",
    "Cache miss for key=session:{id}; fallback to database",
    "Session token refreshed for session_id={id}",
    "Disk usage at {value}% on /dev/sda1",
    "Background job completed: task_id={id}",
    "Rate limit triggered for IP 192.168.1.{octet}",
    "Database query executed in {value}ms",
    "File uploaded: size={value}KB checksum={id}",
    "Health check passed for service=auth",
)

GAP_ONE = timedelta(minutes=47)
GAP_TWO = timedelta(hours=3, minutes=12)
GAP_THREE = timedelta(minutes=8)


def build_message(rng: random.Random) -> str:
    """Build one realistic log message."""
    template = rng.choice(MESSAGES)
    return template.format(
        id=rng.randint(1000, 99999),
        value=rng.randint(5, 999),
        octet=rng.randint(2, 254),
    )


def add_block(
    lines: list[str],
    start_time: datetime,
    count: int,
    min_step_seconds: int,
    max_step_seconds: int,
    rng: random.Random,
) -> datetime:
    """Append a block of timestamped lines and return the final timestamp."""
    current = start_time
    for _ in range(count):
        current += timedelta(seconds=rng.randint(min_step_seconds, max_step_seconds))
        line = f"{current:%Y-%m-%d %H:%M:%S} [{rng.choice(LEVELS)}] {build_message(rng)}"
        lines.append(line)
    return current


def insert_malformed_lines(lines: list[str]) -> None:
    """Insert malformed lines without timestamps at natural points."""
    malformed = [
        "connection reset by peer while writing response",
        "--- log rotate boundary detected ---",
        "WARNING service watchdog heartbeat missing payload",
    ]
    insertion_points = [120, 540, 930]
    offset = 0
    for index, text in zip(insertion_points, malformed):
        safe_index = min(index + offset, len(lines))
        lines.insert(safe_index, text)
        offset += 1


def generate_sample_lines(seed: int = 42) -> list[str]:
    """Generate sample log lines including exactly three known gaps."""
    rng = random.Random(seed)
    lines: list[str] = []
    current = datetime(2024, 3, 10, 8, 0, 0)

    current = add_block(lines, current, count=320, min_step_seconds=4, max_step_seconds=14, rng=rng)
    current += GAP_ONE
    current = add_block(lines, current, count=290, min_step_seconds=5, max_step_seconds=16, rng=rng)
    current += GAP_TWO
    current = add_block(lines, current, count=260, min_step_seconds=3, max_step_seconds=12, rng=rng)
    current += GAP_THREE
    add_block(lines, current, count=170, min_step_seconds=2, max_step_seconds=11, rng=rng)

    insert_malformed_lines(lines)
    return lines


def output_log_path() -> Path:
    """Return output path relative to script location."""
    script_dir = Path(__file__).resolve().parent
    project_dir = script_dir.parent
    return project_dir / "sample-logs" / "sample.log"


def write_sample_log(lines: list[str], destination: Path) -> None:
    """Write generated log lines to disk."""
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Failed to create output directory '{destination.parent}': {exc}") from exc
    try:
        with destination.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError as exc:
        raise RuntimeError(f"Failed to write sample log '{destination}': {exc}") from exc


def main() -> int:
    """CLI entrypoint for sample log generation."""
    destination = output_log_path()
    lines = generate_sample_lines(seed=42)
    try:
        write_sample_log(lines, destination)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Generated sample log: {destination}")
    print(f"Total lines: {len(lines)}")
    print("Intentional gaps: 47m, 3h 12m, 8m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
