# Runbook 04: tune detection

- False positive: add the (fake) text to `tests/test_detect_scan.py` as a benign case, adjust the rule or placeholder list in `sprawl/detectors.py`, and re-run `validation/fp_sweep.py` over your repos.
- Missed secret: add a rule (pattern + base severity) and a positive test; prefer a specific pattern over loosening the generic assignment rule.
- Remember what the generic rule skips on purpose: identifiers and attribute paths (`mint_token`, `self.token`, `random_password.x.result`), values with code punctuation, placeholders (`${X}`, `<...>`, `changeme`, `example`), and all-letter low-entropy values.
