# Architecture

```
GCP sources (read-only, bounded)               local directory (CLI)
  Cloud Run env vars  | bucket objects | logs | VM metadata        files
        \            |            |        /                      /
         v           v            v       v                      v
      [detectors]   regex rules + entropy + placeholder/identifier filtering; the raw value exists only inside this step
         |          -> masked preview + per-process salted fingerprint
      [exposure]    who can read the source (project/bucket IAM): public | broad | limited | unknown
      [key status]  for service-account keys: list the account's keys with OUR credentials (the leaked key is never used)
      [scoring]     severity from type x key state x exposure; remediation commands specific to where it was found
         |
      parallel [explainer]   model note from REDACTED metadata only (no value, preview or fingerprint); output validated
         |
      posture: critical | attention | clean   (rules only)
```

**The value never leaves the scanner.** `detectors.scan_text` returns matches that hold the raw value; `to_parts` immediately converts a match to a masked preview and
an HMAC fingerprint (salted per process, so it dedupes within a scan but cannot be matched across scans or brute-forced from a stored report). The Finding model has no
field for a value, so the API, UI, logs and the model cannot receive one. Tests assert that planted values appear in no response, no CLI output and no payload sent to a model.

**Sources and bounds.** Cloud Run services' literal env vars (Secret Manager references are skipped: that is the right pattern); objects up to 512 KB in allow-listed buckets
(text-like extensions, 200 per bucket); up to 3,000 recent log entries; VM and project metadata; local directories (skipping `.git`, virtualenvs, caches).

**Exposure** uses the project IAM policy (and the bucket's) with curated role sets: who can read Cloud Run config, logs, VM metadata or bucket objects. Public principals make a
finding "public" (+1 severity); 10 or more readers, or any group or domain, is "broad".

**Severity** starts from the secret type (private keys, Stripe live keys and refresh tokens critical; most tokens high; JWTs and generic assignments medium), then: a service-account
key is critical if it is active (or unconfirmed) and the account holds powerful roles, high if active, low if the key no longer exists; an expired JWT is low; public exposure raises one level.

**Failure handling.** A failing source is reported (`degraded`, per-source note) and the rest still run; a failing model removes only the notes.
