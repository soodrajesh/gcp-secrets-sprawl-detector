# Runbook 05: tear down

`./validation/plant.sh cleanup` (removes the throwaway service account and key file), then `./scripts/down.sh` (type the project id): prints the destroy plan and applies that saved plan, which also removes the canary bucket and service.
