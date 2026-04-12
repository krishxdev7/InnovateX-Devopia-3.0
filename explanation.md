# Project Explanation

## Key Features
- Detects suspicious timestamp gaps that can indicate log tampering.
- Flags dense bursts of error-related events in log streams.
- Computes gap fingerprints and rolling hash chains for evidence traceability.
- Classifies risk as CLEAN, LOW RISK, MODERATE RISK, HIGH RISK, or COMPROMISED.
- Exports forensic findings to CSV and optional JSON outputs.
- Supports both web upload analysis and direct CLI execution.

## Technology Used
- Python 3 standard library for log parsing, scoring, and report generation.
- Node.js with Express, Multer, and CORS for backend upload handling.
- HTML5, CSS3, and vanilla JavaScript for the interactive frontend.
- Regex-based timestamp parsing across multiple log timestamp formats.
- CSV and JSON files for structured forensic reporting outputs.

## How the System Works
- Log Ingestion: Frontend uploads log files and threshold settings to the backend API.
- Python Analyzer: Express runs src/log_integrity.py and captures terminal output for the UI.
- Timestamp Extraction: The analyzer auto-detects and parses ISO, slash, Apache, syslog, or custom formats.
- Gap and Burst Detection: It measures timestamp deltas and counts clustered error bursts with line context.
- Risk Scoring: Severity counts, entropy, and confidence signals map to a final risk level.
- Forensic Reporting: Results are printed in terminal style and exported as CSV or JSON artifacts.

## Future Scope
- Add real-time stream monitoring instead of file-only batch analysis.
- Generate visual timelines and richer PDF-style forensic reports.
- Add policy-based scoring profiles for different environments.
- Expand parser support for more log formats and regional timestamp styles.
- Add authentication and access control for backend endpoints.

## What's Next
- Add automated tests for timestamp parsing, gap severity, and risk classification.
- Upgrade vulnerable backend dependencies, especially multer 1.x.
- Persist scan history for cross-run trend and tampering comparisons.
- Add direct API endpoints for report download and archival.
