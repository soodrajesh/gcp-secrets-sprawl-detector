# Threat model

The scanner reads sensitive places by design. The risks are leaking what it finds, over-broad access, and acting on found credentials.

| Threat | Mitigation | Test |
|---|---|---|
| The scanner itself leaks a secret (API, UI, CLI, logs, reports) | no field holds a value; masked previews; salted fingerprints; CLI prints no raw errors; unhandled errors log the type only | `test_nothing_that_leaves_the_scanner_contains_a_secret_value`, `test_cli_never_prints_secrets...`, `test_api_scope_limits_and_masking` |
| A secret reaches a model vendor | the explainer is given redacted metadata only; the eval audits every payload for values, previews and fingerprints | `test_the_model_only_ever_sees_redacted_metadata`, `evals/run.py` |
| The model writes a secret, a link or a false claim into a note | notes are rejected if a detector matches them, if they contain a link, name a foreign resource, or claim public exposure that was not found | `test_notes_with_secrets_links...`, `test_a_note_claiming_public_exposure...` |
| The scanner uses a found credential | it never authenticates with a found value; key status is asked about with the scanner's own read-only identity | `test_service_account_key_status_comes_from_our_own_lookup` |
| Scanning projects or buckets it should not | project and bucket allow-lists (403 otherwise); bucket read is granted per bucket, not project-wide | `test_api_scope_limits_and_masking` |
| Broad read roles on the runtime identity | `run.viewer`, `logging.viewer`, `compute.viewer`, `iam.securityReviewer` are read-only; the service is private (one invoker); sources are bounded | by design |
| A report becomes a target list | reports contain locations and masked previews, not values, are in memory only (30 most recent) | by design |
| Scan cost / abuse | model calls and budget capped; hours and item counts bounded | API validation tests |

Residual risk: locations of exposed credentials are themselves sensitive; keep the invoker role tight. The scanner can only find what its patterns and sources cover.
