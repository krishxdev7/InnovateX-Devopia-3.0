# Evidence Protector - Output Report

## Scan Overview

This report summarizes the log integrity scan results generated from:

- `output/reports/report.csv`
- `output/reports/report.json`
- `output/reports/sample_gaps.json`

## Input and Configuration

| Field | Value |
|---|---|
| Input log file | `sample-logs/sample.log` |
| Threshold | `300 seconds` (`5m 0s`) |
| Total lines | `1043` |
| Parsed lines | `1040` |
| Skipped lines | `3` |
| Log span | `2024-03-10T08:00:14` -> `2024-03-10T14:39:14` |

## Gap Findings

| Gap ID | Start Line | End Line | Start Time | End Time | Duration (s) | Duration (human) | Severity |
|---|---:|---:|---|---|---:|---|---|
| 1 | 321 | 322 | 2024-03-10T08:49:20 | 2024-03-10T09:36:29 | 2829 | 47m 9s | HIGH |
| 2 | 612 | 613 | 2024-03-10T10:28:03 | 2024-03-10T13:40:09 | 11526 | 3h 12m 6s | CRITICAL |
| 3 | 872 | 873 | 2024-03-10T14:12:41 | 2024-03-10T14:20:52 | 491 | 8m 11s | LOW |

## Severity Distribution

| Severity | Count |
|---|---:|
| LOW | 1 |
| MEDIUM | 0 |
| HIGH | 1 |
| CRITICAL | 1 |

## Integrity Assessment

The scan identified **3 suspicious gaps** in chronological log flow.  
At the configured threshold (5 minutes), this indicates a **non-clean integrity status** and should be treated as a flagged dataset for further investigation.

## Output Artifacts

| File | Description |
|---|---|
| `output/reports/report.csv` | Tabular gap records for spreadsheet/BI workflows |
| `output/reports/report.json` | Structured report with stats and gaps |
| `output/reports/sample_gaps.json` | Structured gap report (same scan profile) |
