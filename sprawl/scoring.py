"""Severity and remediation. Deterministic; models never touch either."""

from __future__ import annotations

from .models import SEV_RANK, SEVS, Exposure, Item, KeyStatus


def bump(sev: str, by: int = 1) -> str:
    return SEVS[max(0, min(4, SEV_RANK[sev] + by))]


def severity(base: str, parts: dict, exposure: Exposure, key: KeyStatus | None) -> tuple[str, str]:
    """Returns (severity, why)."""
    why = [parts["why"]]
    sev = base
    if key is not None:
        if key.state == "deleted_or_disabled":
            sev, note = (
                "low",
                "the key no longer works (deleted or disabled); remove the file, nothing to rotate",
            )
        elif key.powerful:
            powers = ", ".join(r.split("/")[-1] for r in key.roles if r in _POWER)
            state = (
                "the key is active"
                if key.state == "active"
                else "the key may still be active (status could not be checked)"
            )
            sev, note = "critical", f"{state} and the account holds powerful roles ({powers})"
        elif key.state == "active":
            sev, note = "high", "the key is active"
        else:
            sev, note = "high", "could not confirm whether the key is still active"
        why.append(note)
    if parts.get("expired"):
        sev = "low"
        why.append("the token has already expired")
    if exposure.level == "public":
        sev = bump(sev)
        why.append("readable by the public internet")
    elif exposure.level == "broad":
        why.append(f"readable by {exposure.reader_count} principals including groups/domains")
    return sev, "; ".join(why)


_POWER = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/storage.admin",
    "roles/secretmanager.admin",
    "roles/compute.admin",
}


def remediation(item: Item, parts: dict, key: KeyStatus | None) -> list[str]:
    out: list[str] = []
    t = parts["secret_type"]
    if key and key.state == "deleted_or_disabled":
        pass  # the key is already dead: nothing to rotate, only a file to remove (added below)
    elif key and key.key_id:
        out.append(
            f"gcloud iam service-accounts keys delete {key.key_id} --iam-account={key.service_account}"
        )
        out.append(
            "Replace the key with workload identity or service-account impersonation so no key file exists"
        )
    elif t not in ("jwt",):
        out.append(
            "Rotate the credential at its issuer: assume it has been seen by everyone who can read this source"
        )
    if item.kind == "cloudrun_env":
        name = item.location.removeprefix("env ")
        svc = item.resource.removeprefix("run:")
        out.append(
            f"Store it in Secret Manager and reference it: gcloud run services update {svc} --update-secrets={name}=<secret-name>:latest"
        )
    elif item.kind == "bucket_object":
        out.append(
            f"Remove or restrict the object: gcloud storage rm {item.resource}   (and check the bucket's IAM for public access)"
        )
    elif item.kind == "log_entry":
        out.append(
            "Find the code path that logs this value and stop logging it; consider a log exclusion for the pattern"
        )
        out.append(
            "Delete or let the affected log entries expire; they are readable by everyone with log access"
        )
    elif item.kind == "instance_metadata":
        out.append(
            "Move it to Secret Manager and have the VM fetch it at boot with its own service account"
        )
    elif item.kind == "file":
        out.append(
            "Remove it from the file and from git history if committed (git filter-repo / BFG), then rotate"
        )
    return out
