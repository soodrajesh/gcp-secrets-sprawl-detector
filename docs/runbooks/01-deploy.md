# Runbook 01: deploy

1. `cp deploy.env.example deploy.env`; `gcloud auth login`.
2. `./scripts/up.sh` (foundation, image, services; saved plans; destroys need `ALLOW_DESTROY=1`). Terraform also creates the canary bucket, objects and `ss-canary` service.
3. `gcloud run services proxy secrets-sprawl --region us-central1 --port 8081`.
4. Optional: `./validation/plant.sh plant` for the log canary and key file, then scan and compare with `docs/validation-results.md`.
5. For real use remove the canary resources and set `SPRAWL_BUCKETS` to the buckets you want scanned (bucket-level `objectViewer` for the runtime service account on each).
