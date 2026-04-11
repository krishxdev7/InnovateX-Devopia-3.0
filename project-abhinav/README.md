# 🔍 Evidence Protector – Automated Log Integrity Monitor

A Python CLI tool that scans large log files, extracts timestamps, and
automatically flags suspicious time gaps that may indicate log tampering.

---

## Features

| Feature | Details |
|---|---|
| **Multi-format timestamps** | ISO 8601, Apache/syslog, US-style, epoch seconds |
| **Configurable threshold** | Any gap duration — default 5 min |
| **Severity rating** | LOW / MEDIUM / HIGH / CRITICAL based on gap size |
| **3 output modes** | Coloured terminal · CSV · JSON |
| **Resilient parsing** | Malformed lines skipped gracefully, never crash |
| **CI-friendly exit codes** | Exits `1` if gaps found, `0` if clean |
| **Zero dependencies** | Pure Python standard library only |

---

## Quick Start

```bash
# 1. Generate a sample log with built-in gaps
python generate_sample_log.py

# 2. Scan it (default 5-min threshold)
python log_monitor.py sample.log

# 3. Use a custom threshold (2 minutes)
python log_monitor.py sample.log --threshold 120

# 4. Export as CSV
python log_monitor.py sample.log --output csv

# 5. Export as JSON with custom filename
python log_monitor.py sample.log -t 300 -o json --out-file report.json

# 6. Both terminal + CSV at once
python log_monitor.py sample.log --output both

# 7. Verbose mode (see every skipped line)
python log_monitor.py sample.log --verbose
```

---

## Sample Output

```
════════════════════════════════════════════════════════════════════════
  🔍 EVIDENCE PROTECTOR — Log Integrity Report
════════════════════════════════════════════════════════════════════════
  File     : sample.log
  Threshold: 5m 0s (300s)
  Total lines parsed : 1,153 / 1,156
  Malformed / skipped: 3
  Log span : 2024-03-10T00:00:18  →  2024-03-10T11:44:32
────────────────────────────────────────────────────────────────────────

  ⚠️  3 suspicious gap(s) detected:

  [LOW]  Gap #1
    Lines   : 403 → 404
    From    : 2024-03-10T02:00:14
    To      : 2024-03-10T02:47:22
    Missing : 47m 8s  (2828s)

  [CRITICAL]  Gap #2
    Lines   : 657 → 658
    From    : 2024-03-10T04:50:11
    To      : 2024-03-10T08:02:19
    Missing : 3h 12m 8s  (11528s)

  [LOW]  Gap #3
    Lines   : 958 → 959
    From    : 2024-03-10T10:17:45
    To      : 2024-03-10T10:25:51
    Missing : 8m 6s  (486s)

────────────────────────────────────────────────────────────────────────
  Severity summary: LOW=2  CRITICAL=1
════════════════════════════════════════════════════════════════════════
```

---

## Severity Scale

| Rating | Gap size vs threshold |
|---|---|
| **LOW** | < 2× threshold |
| **MEDIUM** | 2× – 5× threshold |
| **HIGH** | 5× – 20× threshold |
| **CRITICAL** | > 20× threshold |

---

## Supported Log Formats

```
2024-03-10T14:32:10Z          ← ISO 8601
2024-03-10 14:32:10           ← Standard datetime
15/Mar/2024:14:32:10          ← Apache / Nginx
03/10/2024 14:32:10           ← US-style
Mar 10 14:32:10               ← Syslog short
1710074530                    ← Unix epoch
```

---

## Output Files

| Format | Contents |
|---|---|
| **CSV** | One row per gap: gap_id, start/end lines, timestamps, duration, severity |
| **JSON** | Full stats block + gaps array, machine-readable |

---

## Project Structure

```
evidence_protector/
├── log_monitor.py          ← Main CLI tool
├── generate_sample_log.py  ← Test log generator
└── README.md
```
