# <span style="color:#1E90FF;">Evidence Protector</span>  
### <span style="color:#20B2AA;">Automated Log Integrity Monitor</span>

`Evidence Protector` is a production-ready Python CLI tool for detecting suspicious time gaps in log streams.  
It is designed for incident analysis, evidence validation, and CI-style integrity checks.

---

## <span style="color:#4169E1;">Project Structure</span>

```text
project-abhinav/
├── src/
│   ├── log_monitor.py
│   └── generate_sample_log.py
├── sample-logs/
│   └── sample.log
├── output/
│   ├── Output.md
│   └── reports/
│       ├── report.csv
│       ├── report.json
│       └── sample_gaps.json
└── README.md
```

---

## <span style="color:#4169E1;">Key Features</span>

| Capability | Details |
|---|---|
| Multi-format parsing | ISO 8601, Apache/Nginx, standard datetime, US datetime, syslog short, Unix epoch |
| Gap detection | Detects timestamp gaps above configurable threshold |
| Severity classification | LOW, MEDIUM, HIGH, CRITICAL based on threshold multiples |
| Safe parsing | Malformed lines are skipped without crashing |
| Flexible output | Terminal, CSV, JSON, or both |
| CI-friendly behavior | Exit code `1` when gaps are found, `0` when clean |
| Dependency policy | Python standard library only |

---

## <span style="color:#4169E1;">Timestamp Formats Supported</span>

```text
2024-03-10T14:32:10Z      (ISO 8601)
15/Mar/2024:14:32:10      (Apache/Nginx)
2024-03-10 14:32:10       (Standard datetime)
03/10/2024 14:32:10       (US-style datetime)
Mar 10 14:32:10           (Syslog short)
1710074530                (Unix epoch, 10-digit)
```

---

## <span style="color:#4169E1;">Severity Model</span>

| Severity | Rule (gap vs threshold) |
|---|---|
| LOW | `< 2x` |
| MEDIUM | `2x - 5x` |
| HIGH | `> 5x - 20x` |
| CRITICAL | `> 20x` |

---

## <span style="color:#4169E1;">Usage</span>

Run from `project-abhinav/`:

```bash
python src/generate_sample_log.py
python src/log_monitor.py sample-logs/sample.log
python src/log_monitor.py sample-logs/sample.log --threshold 120
python src/log_monitor.py sample-logs/sample.log --output csv
python src/log_monitor.py sample-logs/sample.log -o json --out-file output/report.json
python src/log_monitor.py sample-logs/sample.log --output both --verbose
```

### CLI Options

| Option | Description | Default |
|---|---|---|
| `logfile` | Path to `.log` file | Required |
| `-t, --threshold` | Gap threshold in seconds | `300` |
| `-o, --output` | `terminal`, `csv`, `json`, `both` | `terminal` |
| `--out-file` | Custom output filename/path | Auto-derived |
| `-v, --verbose` | Print skipped line notices | Off |

---

## <span style="color:#4169E1;">Current Sample Scan Result</span>

For `sample-logs/sample.log` at threshold `300s`:

- Total lines: `1043`
- Parsed lines: `1040`
- Skipped lines: `3`
- Gaps detected: `3`
  - Gap 1: `47m 9s` (HIGH)
  - Gap 2: `3h 12m 6s` (CRITICAL)
  - Gap 3: `8m 11s` (LOW)

Detailed records are available in:

- `output/reports/report.csv`
- `output/reports/report.json`
- `output/reports/sample_gaps.json`
- `output/Output.md`

---

## <span style="color:#4169E1;">Notes</span>

- All file paths are relative to the project root unless absolute paths are provided.
- Output reports are intended to support both analyst review and machine processing.
- The tool is resilient to malformed lines and continues scanning safely.

