# Runbook 02: run a scan

- **UI / API**: choose sources and a log window; `POST /api/scans {"project": "...", "sources": [...], "hours": 24}`. Only allow-listed projects and buckets are accepted.
- **CLI (local, your credentials)**: `sprawl scan <project> --bucket <bucket> --sources cloudrun_env,log_entry --hours 24`; `sprawl scan-dir ./repo` before committing.
- Exit codes: 0 clean, 1 attention, 2 critical, 3 error. Output has masked previews only.
Read "coverage" first: a source that failed or was skipped is not a clean source.
