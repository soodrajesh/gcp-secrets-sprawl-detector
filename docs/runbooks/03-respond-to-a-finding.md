# Runbook 03: respond to a finding

1. Treat the credential as compromised if its exposure is public or broad, or if you cannot rule out that the readers include someone who should not have it.
2. **Rotate at the issuer first** (the cloud console, GitHub, Stripe, the database), then fix the source. Removing the file does not un-expose a value that has been readable.
3. Fix the source with the command shown: Secret Manager reference for Cloud Run (`--update-secrets`), delete or restrict the object, stop logging the value, move VM secrets to Secret Manager.
4. For a service-account key: delete the key (`gcloud iam service-accounts keys delete ...`) and move to workload identity or impersonation so no key file exists.
5. Check audit logs for use of the credential between when it was exposed and when it was rotated.
6. Re-scan; the finding should be gone.
