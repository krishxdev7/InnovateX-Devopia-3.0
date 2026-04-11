#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║       THE EVIDENCE PROTECTOR                         ║
║       Automated Log Integrity Monitor v3.0           ║
╚══════════════════════════════════════════════════════╝

Usage:
  python log_integrity.py --file system.log
  python log_integrity.py --file system.log --threshold 120 --format json
  python log_integrity.py --file system.log --format csv --out report.csv
  python log_integrity.py --file system.log --verify-hash abc123def...
  python log_integrity.py --file system.log --burst-threshold 5 --rate-threshold 50
  python log_integrity.py --file system.log --after-hours-freq 3 --context-lines 8
"""

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
# Each entry: (strptime format string, compiled regex to locate/extract it)
# The regex measures the exact timestamp span so message extraction is
# always dynamic — never a fixed slice like [25:].

TIMESTAMP_REGISTRY = [
    (
        "%Y-%m-%dT%H:%M:%S",
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
    ),
    (
        "%Y-%m-%d %H:%M:%S",
        re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"),
    ),
    (
        "%Y/%m/%d %H:%M:%S",
        re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}"),
    ),
    (
        "%d/%b/%Y:%H:%M:%S",
        re.compile(r"^\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}"),
    ),
    (
        "%b %d %H:%M:%S",
        re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}"),
    ),
]

# ── KEYWORD SETS ───────────────────────────────────────────────────────────────

LOGIN_KEYWORDS = {
    "login", "logout", "auth", "session", "signin", "signout",
    "authenticate", "password", "credential", "token", "oauth",
}

ERROR_KEYWORDS = {
    "error", "exception", "traceback", "critical", "fatal",
    "fail", "failed", "failure", "panic", "alert", "denied",
}

# ── ENTITY EXTRACTION PATTERNS ────────────────────────────────────────────────

RE_IPV4    = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_USER    = re.compile(
    r"(?:user[=:\s]+|username[=:\s]+|uid[=:\s]+|u[=:\s]+)([A-Za-z0-9_@.\-]+)",
    re.IGNORECASE,
)
# Dynamic parts: IPs, UUIDs, ISO timestamps, bare numbers — replaced for fingerprinting
RE_DYNPART = re.compile(
    r"\b(?:\d{1,3}(?:\.\d{1,3}){3}"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"|\d+)\b",
    re.IGNORECASE,
)

# ── COLORS ─────────────────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def _color_on() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def c(color: str, text: str) -> str:
    return f"{color}{text}{RESET}" if _color_on() else text

SEVERITY_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}

TOP_GAPS_SHOWN = 5

# ── PARSING HELPERS ────────────────────────────────────────────────────────────

def parse_line(line: str) -> tuple:
    """
    Returns (timestamp | None, message_str, ts_end_index).

    The message is extracted dynamically from where the timestamp ends —
    not from a fixed index — so it works for every format in the registry.
    Separator characters (spaces, brackets, pipes, dashes) between the
    timestamp and the message body are automatically skipped.
    """
    for fmt, pattern in TIMESTAMP_REGISTRY:
        m = pattern.match(line)
        if not m:
            continue
        raw_ts = m.group(0)
        try:
            ts  = datetime.strptime(raw_ts, fmt)
            end = m.end()
            # Skip separator characters that vary by log format
            while end < len(line) and line[end] in " [\t|-":
                end += 1
            return ts, line[end:].strip(), end
        except ValueError:
            continue
    return None, line, 0


def is_error_line(line: str) -> bool:
    lower = line.lower()
    return any(k in lower for k in ERROR_KEYWORDS)


def is_login_line(line: str) -> bool:
    lower = line.lower()
    return any(k in lower for k in LOGIN_KEYWORDS)


def is_after_hours(ts: datetime, start: int, end: int) -> bool:
    return ts.hour >= start or ts.hour < end


def format_duration(sec: float) -> str:
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s   = divmod(rem, 60)
    if h:  return f"{h}h {m}m {s}s"
    if m:  return f"{m}m {s}s"
    return f"{s}s"


def normalise_message(msg: str) -> str:
    """
    Replace dynamic parts (IPs, UUIDs, numbers, timestamps) with a placeholder
    so that structurally identical messages have the same fingerprint even
    when session IDs, ports, or request counters differ.
    """
    return RE_DYNPART.sub("<X>", msg).strip()


def extract_entities(msg: str) -> dict:
    """Pull IP addresses and usernames from a log message."""
    ips   = RE_IPV4.findall(msg)
    users = RE_USER.findall(msg)
    return {
        "ips":   list(set(ips)),
        "users": list(set(users)),
    }


def severity_for_gap(delta: float, signals: list) -> str:
    """
    Multi-signal severity: the more concurrent anomaly types, the higher the level.
    This replaces the old binary critical_context check.
    """
    if len(signals) >= 3:
        return "CRITICAL"
    if len(signals) >= 2 or delta > 3600:
        return "HIGH"
    if delta > 600:
        return "MEDIUM"
    return "LOW"


# ── CORE ANALYSIS ──────────────────────────────────────────────────────────────

def analyze(filepath: str, cfg: dict) -> dict:
    """
    Single-pass analysis. All thresholds come from cfg so the tool is fully
    configurable via CLI without touching any constants in the source.
    """

    threshold        = cfg["threshold"]
    burst_window     = cfg["burst_window"]
    burst_threshold  = cfg["burst_threshold"]
    rate_window_sec  = cfg["rate_window"]
    rate_threshold   = cfg["rate_threshold"]
    repeat_threshold = cfg["repeat_threshold"]
    dup_threshold    = cfg["dup_threshold"]
    ah_start         = cfg["after_hours_start"]
    ah_end           = cfg["after_hours_end"]
    ah_freq          = cfg["after_hours_freq"]
    context_n        = cfg["context_lines"]

    # ── result buckets ──
    time_gaps    = []
    duplicates   = []
    bursts       = []
    after_hours  = []
    out_of_order = []
    repeated     = []
    spikes       = []
    correlated   = []

    stats = defaultdict(int)

    # ── sliding windows (O(1) deque) ──
    error_window = deque()
    rate_win     = deque()

    # ── cooldown state ──
    in_burst = False
    in_spike = False

    # ── duplicate detection ──
    # bucket: { count, msgs: [normalised fingerprints] }
    ts_buckets = defaultdict(lambda: {"count": 0, "msgs": []})

    # ── repeated message tracking (normalised) ──
    norm_counts   = defaultdict(int)
    norm_examples = {}                  # fingerprint → first real example

    # ── after-hours frequency per entity ──
    ah_entity_counts = defaultdict(int)

    # ── entity tracking ──
    ip_activity   = defaultdict(int)
    user_activity = defaultdict(int)

    # ── rolling context buffer (bounded memory) ──
    context_buf = deque(maxlen=context_n)

    # ── hash chain ──
    prev_hash     = "0" * 64
    final_hash    = prev_hash
    lines_chained = 0

    prev_ts   = None
    prev_line = ""
    first_ts  = None
    last_ts   = None

    with open(filepath, "r", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            stats["total"] += 1
            line = raw.rstrip("\n")

            if not line.strip():
                stats["skipped"] += 1
                context_buf.append(line)
                continue

            ts, msg, ts_end = parse_line(line)
            if ts is None:
                stats["skipped"] += 1
                context_buf.append(line)
                continue

            stats["parsed"] += 1
            snap_context = list(context_buf)   # snapshot before appending this line

            if first_ts is None:
                first_ts = ts
            last_ts = ts

            # ── HASH CHAIN ────────────────────────────────────────────────────
            # Each line's hash incorporates the previous line's hash.
            # Any deletion, insertion, or modification breaks the chain.
            # Compare final_hash across runs to detect tampering.
            curr_hash     = hashlib.sha256(
                (line + prev_hash).encode("utf-8", errors="replace")
            ).hexdigest()
            prev_hash     = curr_hash
            final_hash    = curr_hash
            lines_chained += 1

            # ── ENTITY EXTRACTION ─────────────────────────────────────────────
            entities = extract_entities(msg)
            for ip in entities["ips"]:
                ip_activity[ip] += 1
            for u in entities["users"]:
                user_activity[u] += 1

            # ── TIME GAP ──────────────────────────────────────────────────────
            if prev_ts is not None:
                delta = (ts - prev_ts).total_seconds()
                if delta > threshold:
                    # Gather ALL concurrent signals for multi-signal severity
                    signals = []
                    if is_error_line(prev_line):
                        signals.append("error")
                    if is_login_line(prev_line):
                        signals.append("login")
                    if is_after_hours(ts, ah_start, ah_end):
                        signals.append("after_hours")
                    if len(error_window) > burst_threshold:
                        signals.append("burst")
                    if len(rate_win) > rate_threshold:
                        signals.append("spike")

                    sev   = severity_for_gap(delta, signals)
                    entry = {
                        "from":     prev_ts,
                        "to":       ts,
                        "delta":    delta,
                        "severity": sev,
                        "lineno":   lineno,
                        "signals":  signals,
                        "context":  snap_context,
                    }
                    time_gaps.append(entry)

                    if signals:
                        correlated.append({
                            "reason":   f"Gap + [{', '.join(signals)}]",
                            "severity": sev,
                            "lineno":   lineno,
                            "context":  snap_context,
                        })

            # ── OUT OF ORDER ──────────────────────────────────────────────────
            if prev_ts is not None and ts < prev_ts:
                out_of_order.append({
                    "prev":    prev_ts,
                    "curr":    ts,
                    "lineno":  lineno,
                    "context": snap_context,
                })

            # ── DUPLICATE TIMESTAMPS (message-aware) ──────────────────────────
            ts_key  = ts.strftime("%Y-%m-%d %H:%M:%S")
            bucket  = ts_buckets[ts_key]
            bucket["count"] += 1
            norm_msg = normalise_message(msg)
            if norm_msg not in bucket["msgs"]:
                bucket["msgs"].append(norm_msg)

            # ── ERROR BURST (deque + cooldown) ────────────────────────────────
            if is_error_line(line):
                error_window.append(ts)
            while error_window and (ts - error_window[0]).total_seconds() > burst_window:
                error_window.popleft()

            currently_bursting = len(error_window) > burst_threshold
            if currently_bursting and not in_burst:
                bursts.append({
                    "ts":      ts,
                    "count":   len(error_window),
                    "context": snap_context,
                })
            in_burst = currently_bursting

            # ── AFTER-HOURS LOGIN (frequency-filtered per entity) ─────────────
            if is_after_hours(ts, ah_start, ah_end) and is_login_line(line):
                # Identify the entity: prefer username, fall back to IP, then "unknown"
                entity = (
                    entities["users"][0] if entities["users"]
                    else entities["ips"][0] if entities["ips"]
                    else "unknown"
                )
                ah_entity_counts[entity] += 1
                # Only flag once the entity crosses the frequency threshold
                if ah_entity_counts[entity] >= ah_freq:
                    after_hours.append({
                        "ts":      ts,
                        "lineno":  lineno,
                        "entity":  entity,
                        "count":   ah_entity_counts[entity],
                        "context": snap_context,
                    })

            # ── RATE SPIKE (deque + cooldown) ─────────────────────────────────
            rate_win.append(ts)
            while rate_win and (ts - rate_win[0]).total_seconds() > rate_window_sec:
                rate_win.popleft()

            currently_spiking = len(rate_win) > rate_threshold
            if currently_spiking and not in_spike:
                spikes.append({
                    "ts":      ts,
                    "count":   len(rate_win),
                    "context": snap_context,
                })
            in_spike = currently_spiking

            # ── REPEATED MESSAGE (normalised fingerprint) ─────────────────────
            norm_counts[norm_msg] += 1
            if norm_msg not in norm_examples:
                norm_examples[norm_msg] = msg[:100]

            if norm_counts[norm_msg] == repeat_threshold:
                repeated.append({
                    "fingerprint": norm_msg[:80],
                    "example":     norm_examples[norm_msg],
                    "count":       repeat_threshold,
                })

            prev_ts   = ts
            prev_line = line
            context_buf.append(line)

    # ── DUPLICATE POST-PROCESS ────────────────────────────────────────────────
    # Use message diversity to separate real high-traffic moments from replays.
    for ts_key, bucket in ts_buckets.items():
        if bucket["count"] > dup_threshold:
            unique_msgs = len(bucket["msgs"])
            duplicates.append({
                "timestamp":   ts_key,
                "count":       bucket["count"],
                "unique_msgs": unique_msgs,
                "detail": (
                    "likely real burst (many distinct messages)"
                    if unique_msgs > 3
                    else "possible duplicate/replay (few distinct messages)"
                ),
            })

    # ── RISK SCORE — normalised by log duration ───────────────────────────────
    # Raw score grows with finding count. Dividing by log duration in hours
    # keeps scores comparable across logs of very different sizes/timeframes.
    raw_risk = (
        len(time_gaps)    * 20 +
        len(duplicates)   * 10 +
        len(bursts)       * 25 +
        len(after_hours)  * 10 +
        len(out_of_order) * 30 +
        len(spikes)       * 20 +
        len(repeated)     * 15 +
        len(correlated)   * 20   # +20 premium on top of the gap already scored
    )

    if first_ts and last_ts:
        duration_hours = max((last_ts - first_ts).total_seconds() / 3600, 1.0)
    else:
        duration_hours = 1.0

    normalised_risk = int(raw_risk / duration_hours)

    stats["raw_risk"]        = raw_risk
    stats["normalised_risk"] = normalised_risk
    stats["duration_hours"]  = round(duration_hours, 2)

    # ── TOP ENTITIES ──────────────────────────────────────────────────────────
    top_ips   = sorted(ip_activity.items(),   key=lambda x: x[1], reverse=True)[:10]
    top_users = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "gaps":        time_gaps,
        "duplicates":  duplicates,
        "bursts":      bursts,
        "after_hours": after_hours,
        "ooo":         out_of_order,
        "spikes":      spikes,
        "repeated":    repeated,
        "correlated":  correlated,
        "chain": {
            "total_lines": lines_chained,
            "final_hash":  final_hash,
        },
        "entities": {
            "top_ips":   top_ips,
            "top_users": top_users,
        },
        "stats": dict(stats),
    }


# ── TERMINAL REPORT ────────────────────────────────────────────────────────────

def _print_context(ctx: list, indent: int = 6) -> None:
    if not ctx:
        return
    pad = " " * indent
    print(c(DIM, f"{pad}┌─ context ──────────────────────────────────"))
    for ln in ctx[-3:]:
        print(c(DIM, f"{pad}│ {ln[:100]}"))
    print(c(DIM, f"{pad}└────────────────────────────────────────────"))


def report_terminal(res: dict, verify_hash: str | None = None) -> None:
    stats     = res["stats"]
    raw_risk  = stats["raw_risk"]
    norm_risk = stats["normalised_risk"]
    dur       = stats["duration_hours"]

    print()
    print(c(CYAN + BOLD, "╔══════════════════════════════════════════════╗"))
    print(c(CYAN + BOLD, "║       LOG INTEGRITY REPORT  v3.0             ║"))
    print(c(CYAN + BOLD, "╚══════════════════════════════════════════════╝"))
    print()

    # ── Summary ──
    print(c(BOLD, "── SUMMARY ──────────────────────────────────────"))
    rows = [
        ("Lines parsed",         stats.get("parsed",  0), False),
        ("Lines skipped",        stats.get("skipped", 0), False),
        ("Log span (hours)",     dur,                      False),
        ("Time gaps detected",   len(res["gaps"]),         True),
        ("Duplicate timestamps", len(res["duplicates"]),   True),
        ("Error bursts",         len(res["bursts"]),       True),
        ("After-hours logins",   len(res["after_hours"]), True),
        ("Out-of-order entries", len(res["ooo"]),          True),
        ("Rate spikes",          len(res["spikes"]),       True),
        ("Repeated messages",    len(res["repeated"]),     True),
        ("Correlated alerts",    len(res["correlated"]),   True),
    ]
    for label, val, flaggable in rows:
        flag = c(RED, "  ← ⚠") if flaggable and val > 0 else ""
        print(f"  {label:<30} {c(BOLD, str(val))}{flag}")

    # ── Hash chain ──
    print()
    print(c(BOLD, "── HASH CHAIN ───────────────────────────────────"))
    chain = res["chain"]
    print(f"  Lines chained : {chain['total_lines']}")
    print(f"  Final hash    : {c(DIM, chain['final_hash'])}")

    if verify_hash:
        if verify_hash.strip() == chain["final_hash"]:
            print(f"  {c(GREEN + BOLD, '✔ VERIFIED — hash matches baseline. Log intact.')}")
        else:
            print(f"  {c(RED + BOLD, '✘ TAMPERED — hash does NOT match baseline!')}")
            print(f"  Expected : {c(DIM, verify_hash.strip())}")
            print(f"  Got      : {c(DIM, chain['final_hash'])}")
    else:
        print(f"  {c(YELLOW, 'Tip: save this hash and pass --verify-hash on future runs to detect tampering.')}")

    # ── Entities ──
    ents = res["entities"]
    if ents["top_ips"] or ents["top_users"]:
        print()
        print(c(BOLD, "── ENTITIES DETECTED ────────────────────────────"))
        if ents["top_ips"]:
            print("  Top IPs:")
            for ip, cnt in ents["top_ips"][:5]:
                print(f"    {ip:<20} {cnt} occurrences")
        if ents["top_users"]:
            print("  Top users:")
            for u, cnt in ents["top_users"][:5]:
                print(f"    {u:<20} {cnt} occurrences")

    # ── Top gaps ──
    print()
    print(c(BOLD, "── TOP GAPS ─────────────────────────────────────"))
    if not res["gaps"]:
        print(f"  {c(GREEN, 'No gaps exceeding threshold.')}")
    else:
        worst = sorted(res["gaps"], key=lambda g: g["delta"], reverse=True)[:TOP_GAPS_SHOWN]
        for i, g in enumerate(worst, 1):
            sc      = SEVERITY_COLOR.get(g["severity"], "")
            sig_str = f"  [{', '.join(g['signals'])}]" if g["signals"] else ""
            print(
                f"  {i}. [{c(sc + BOLD, g['severity'])}] "
                f"{g['from'].strftime('%Y-%m-%d %H:%M:%S')} → "
                f"{g['to'].strftime('%Y-%m-%d %H:%M:%S')}  "
                f"({c(BOLD, format_duration(g['delta']))})"
                f"  line {g['lineno']}{c(YELLOW, sig_str)}"
            )
            _print_context(g["context"])

    # ── Duplicates detail ──
    if res["duplicates"]:
        print()
        print(c(BOLD, "── DUPLICATE TIMESTAMPS ─────────────────────────"))
        for d in res["duplicates"][:5]:
            print(
                f"  {d['timestamp']}  {d['count']} entries  "
                f"{d['unique_msgs']} distinct msg(s)  — {c(DIM, d['detail'])}"
            )

    # ── Correlated alerts ──
    if res["correlated"]:
        print()
        print(c(BOLD, "── CORRELATED ALERTS ────────────────────────────"))
        for a in res["correlated"][:5]:
            sc = SEVERITY_COLOR.get(a["severity"], "")
            print(f"  [{c(sc + BOLD, a['severity'])}] {a['reason']}  (line {a['lineno']})")
            _print_context(a["context"])

    # ── Risk score ──
    print()
    print(c(BOLD, "── RISK ASSESSMENT ──────────────────────────────"))
    print(f"  Raw score        : {raw_risk}")
    print(f"  Normalised score : {c(BOLD, str(norm_risk))}  (per hour, over {dur}h span)")

    if norm_risk > 200:
        verdict = c(RED + BOLD, "⚠  CRITICAL: Log tampering highly likely")
    elif norm_risk > 100:
        verdict = c(RED,        "⚠  HIGH: Possible attack or tampering detected")
    elif norm_risk > 40:
        verdict = c(YELLOW,     "△  MEDIUM: Anomalies present — review recommended")
    else:
        verdict = c(GREEN,      "✔  LOW: System appears normal")

    print(f"  {verdict}")
    print()


# ── CSV / JSON EXPORT ──────────────────────────────────────────────────────────

def _flatten_findings(res: dict) -> list:
    rows = []
    for g in res["gaps"]:
        rows.append({
            "type": "GAP", "severity": g["severity"],
            "from": g["from"].isoformat(), "to": g["to"].isoformat(),
            "duration": format_duration(g["delta"]),
            "detail": f"line {g['lineno']}  signals=[{', '.join(g['signals'])}]",
        })
    for d in res["duplicates"]:
        rows.append({
            "type": "DUPLICATE", "severity": "MEDIUM",
            "from": d["timestamp"], "to": "", "duration": "",
            "detail": f"{d['count']} entries, {d['unique_msgs']} distinct — {d['detail']}",
        })
    for b in res["bursts"]:
        rows.append({
            "type": "ERROR_BURST", "severity": "HIGH",
            "from": b["ts"].isoformat(), "to": "", "duration": "",
            "detail": f"{b['count']} errors in window",
        })
    for a in res["after_hours"]:
        rows.append({
            "type": "AFTER_HOURS_LOGIN", "severity": "MEDIUM",
            "from": a["ts"].isoformat(), "to": "", "duration": "",
            "detail": f"entity={a['entity']} count={a['count']} line={a['lineno']}",
        })
    for o in res["ooo"]:
        rows.append({
            "type": "OUT_OF_ORDER", "severity": "HIGH",
            "from": o["prev"].isoformat(), "to": o["curr"].isoformat(), "duration": "",
            "detail": f"line {o['lineno']}",
        })
    for r in res["repeated"]:
        rows.append({
            "type": "REPEATED_MESSAGE", "severity": "LOW",
            "from": "", "to": "", "duration": "",
            "detail": f"'{r['example'][:60]}' seen {r['count']}+ times",
        })
    return rows


def report_csv(res: dict, outpath: str) -> None:
    rows       = _flatten_findings(res)
    fieldnames = ["type", "severity", "from", "to", "duration", "detail"]
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV report written → {outpath}")


def _serialise(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Not serialisable: {type(obj)}")


def report_json(res: dict, outpath: str) -> None:
    def strip_ctx(lst):
        return [{k: v for k, v in item.items() if k != "context"} for item in lst]

    payload = {
        "summary": {
            "risk_raw":        res["stats"]["raw_risk"],
            "risk_normalised": res["stats"]["normalised_risk"],
            "duration_hours":  res["stats"]["duration_hours"],
            "lines_parsed":    res["stats"].get("parsed",  0),
            "lines_skipped":   res["stats"].get("skipped", 0),
        },
        "hash_chain": res["chain"],
        "entities":   res["entities"],
        "findings": {
            "gaps":               strip_ctx(res["gaps"]),
            "duplicates":         res["duplicates"],
            "error_bursts":       strip_ctx(res["bursts"]),
            "after_hours":        strip_ctx(res["after_hours"]),
            "out_of_order":       strip_ctx(res["ooo"]),
            "rate_spikes":        strip_ctx(res["spikes"]),
            "repeated_messages":  res["repeated"],
            "correlated_alerts":  strip_ctx(res["correlated"]),
        },
    }
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=_serialise)
    print(f"JSON report written → {outpath}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="The Evidence Protector – Log Integrity Monitor v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Core ──
    parser.add_argument("--file",         required=True,  help="Path to the log file")
    parser.add_argument("--format",       choices=["terminal", "csv", "json"], default="terminal",
                        help="Output format (default: terminal)")
    parser.add_argument("--out",          default=None,   help="Output file path for csv/json")
    parser.add_argument("--verify-hash",  default=None,
                        help="Known-good final hash; if provided, integrity is verified")

    # ── Configurable thresholds ──
    parser.add_argument("--threshold",          type=int, default=300,
                        help="Gap threshold in seconds (default: 300)")
    parser.add_argument("--burst-window",        type=int, default=60,
                        help="Error burst window in seconds (default: 60)")
    parser.add_argument("--burst-threshold",     type=int, default=10,
                        help="Errors within window to trigger burst alert (default: 10)")
    parser.add_argument("--rate-window",         type=int, default=10,
                        help="Rate spike window in seconds (default: 10)")
    parser.add_argument("--rate-threshold",      type=int, default=100,
                        help="Log lines within window to trigger spike alert (default: 100)")
    parser.add_argument("--repeat-threshold",    type=int, default=10,
                        help="Same-message occurrences before flagging (default: 10)")
    parser.add_argument("--dup-threshold",       type=int, default=5,
                        help="Same-second entries before flagging duplicate (default: 5)")
    parser.add_argument("--after-hours-start",   type=int, default=22,
                        help="After-hours period start, 0–23 (default: 22)")
    parser.add_argument("--after-hours-end",     type=int, default=6,
                        help="After-hours period end, 0–23 (default: 6)")
    parser.add_argument("--after-hours-freq",    type=int, default=1,
                        help="Min after-hours logins per entity before flagging (default: 1)")
    parser.add_argument("--context-lines",       type=int, default=5,
                        help="Context lines stored per alert for forensic detail (default: 5)")

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    cfg = {
        "threshold":         args.threshold,
        "burst_window":      args.burst_window,
        "burst_threshold":   args.burst_threshold,
        "rate_window":       args.rate_window,
        "rate_threshold":    args.rate_threshold,
        "repeat_threshold":  args.repeat_threshold,
        "dup_threshold":     args.dup_threshold,
        "after_hours_start": args.after_hours_start,
        "after_hours_end":   args.after_hours_end,
        "after_hours_freq":  args.after_hours_freq,
        "context_lines":     args.context_lines,
    }

    print(f"Analysing  : {args.file}")
    print(
        f"Thresholds : gap={cfg['threshold']}s  "
        f"burst={cfg['burst_threshold']}/{cfg['burst_window']}s  "
        f"rate={cfg['rate_threshold']}/{cfg['rate_window']}s  "
        f"repeat={cfg['repeat_threshold']}  "
        f"after-hours-freq={cfg['after_hours_freq']}"
    )

    res = analyze(args.file, cfg)

    if args.format == "terminal":
        report_terminal(res, args.verify_hash)

    elif args.format == "csv":
        out = args.out or args.file.rsplit(".", 1)[0] + "_integrity.csv"
        report_csv(res, out)
        report_terminal(res, args.verify_hash)

    elif args.format == "json":
        out = args.out or args.file.rsplit(".", 1)[0] + "_integrity.json"
        report_json(res, out)
        report_terminal(res, args.verify_hash)


if __name__ == "__main__":
    main()
