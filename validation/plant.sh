#!/usr/bin/env bash
# Plant the canaries that Terraform cannot: a log entry with a FAKE token, and a FAKE service-account key file
# that names a real, permission-less throwaway account (so key lookups hit real IAM). Real key creation is blocked
# by the org policy constraints/iam.disableServiceAccountKeyCreation, so the "key is active" path is covered by unit tests only.
#   ./validation/plant.sh plant      create the throwaway SA, upload the fake key file, write the fake log line
#   ./validation/plant.sh cleanup    delete the SA and the uploaded file
set -euo pipefail
P="${PROJECT_ID:-claude-code-507112}"; B="${P}-ss-canary"; SA="ss-canary-sa@${P}.iam.gserviceaccount.com"
case "${1:-}" in
  plant)
    gcloud iam service-accounts describe "$SA" --project "$P" >/dev/null 2>&1 || gcloud iam service-accounts create ss-canary-sa --project "$P" --display-name "scanner canary (no permissions)" >/dev/null 2>&1
    tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
    python3 - "$SA" "$P" > "$tmp" <<'PY'
import json, secrets, sys
sa, project = sys.argv[1:3]
print(json.dumps({"type": "service_account", "project_id": project, "private_key_id": secrets.token_hex(20),
                  "private_key": "-----BEGIN PRIVATE KEY-----\nFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n-----END PRIVATE KEY-----\n",
                  "client_email": sa, "client_id": "1234567890"}, indent=2))
PY
    gcloud storage cp "$tmp" "gs://$B/keys/deployer.json" --project "$P" >/dev/null 2>&1
    gcloud logging write ss-canary "retry failed for upstream, auth header was token=ghp_Zx9Yw8Vv7Uu6Tt5Ss4Rr3Qq2Pp1Oo0Nn9Mm8" --severity=ERROR --project "$P" >/dev/null 2>&1
    echo "planted: fake key file in gs://$B/keys/deployer.json, fake token in a log entry";;
  cleanup)
    gcloud storage rm "gs://$B/keys/deployer.json" --project "$P" >/dev/null 2>&1 || true
    gcloud iam service-accounts delete "$SA" --project "$P" --quiet >/dev/null 2>&1 || true
    echo "cleaned up";;
  *) echo "usage: $0 plant|cleanup"; exit 2;;
esac
