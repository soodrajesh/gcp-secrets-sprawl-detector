# Validation against real GCP resources and real code

## 1. Planted canaries in real GCP (ground truth)

FAKE credentials in the real formats were planted in a real project: two objects in a private canary bucket, environment variables on a real Cloud Run
service (`ss-canary`), a log entry written with `gcloud logging write`, and a fake service-account key file naming a real, permission-less throwaway account.
Real key creation is blocked by the org policy `iam.disableServiceAccountKeyCreation`, so the file is fake; the "key is active" path is covered by unit tests.
Reproduce with `terraform apply` (bucket, objects, service) and `validation/plant.sh plant`.

| Planted | Where | Expected | Found | Severity |
|---|---|---|---|---|
| Stripe live key | bucket `config/app.env` | stripe_live_key | yes | critical |
| AWS access key id | bucket `config/app.env` | aws_access_key_id | yes | high |
| Postgres URL with password | bucket `config/app.env` | database_url_with_password | yes | high |
| GitHub token | Cloud Run env `GITHUB_TOKEN` | github_token | yes | high |
| Redis URL with password | Cloud Run env `REDIS_URL` | database_url_with_password | yes | high |
| GitHub token | log entry | github_token | yes | high |
| Service-account key file | bucket `keys/deployer.json` | gcp_service_account_key | yes | low (key does not exist; nothing to rotate) |

**Recall 7/7.** Benign controls were not flagged: a README with `${API_KEY}`, a docs example key (`AKIAIOSFODNN7EXAMPLE`), `<your-password-here>`, a SHA-256 checksum, and the
env vars `LOG_LEVEL`, `REGION`, `APP_NAME`. Everything else the scan covered produced **no findings**: 47 Cloud Run environment variables across the project's services and
3,000 log entries (roughly 2,200 of them longer than a trivial line). Locally and on the deployed service the results were identical, and the API response body was checked to contain none of the planted values.

## 2. False-positive sweep over 1,335 real files

Every repo under `gcp-projects/` (16 repos, code, scripts, Terraform, docs) was scanned with `validation/fp_sweep.py` (counts by type only, no values).

| Run | Findings outside deliberate fixtures | Notes |
|---|---|---|
| First version of the generic rule | 18 `generic_secret_assignment`, **all false positives** | code such as `token = mint_token(...)`, `TOKEN="$(curl ...)"`, Terraform `password = random_password.x.result`, `token = google.oauth2.id_token.fetch_id_token(...)` |
| After requiring a literal-looking value (no code punctuation, not an identifier or attribute path) | **0 false positives** | each real case became a regression test |
| Remaining | 1 true positive, the rest are known fixtures | `gcp-mcp-gateway-gke/.secrets/realm-key.pem` is a real private key; it sits in a gitignored, mode-600 `.secrets/` directory and was never committed |

The tightening costs recall for low-entropy secrets made only of letters (for example a passphrase); those are not caught by the generic rule.

## 3. Findings from running it that were fixed

1. A key that was already dead still received "rotate at the issuer" advice.
2. Key status looked up with `keys.get` returned "unknown" on Cloud Run (the runtime role lacks it); it now lists keys, which the role allows.
3. A model note called a private bucket "publicly readable" and another was rejected only because of a regex artifact; the validator now rejects public-exposure claims unless exposure is public, and the resource matcher ignores trailing punctuation.
4. "The key is active" was printed when the status was unknown.
