"""Who can read the place a secret was found, and what can a leaked service-account key do."""

from __future__ import annotations

from typing import Any

from .models import Exposure, Item

RUN_READ = {
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/run.viewer",
    "roles/run.developer",
    "roles/run.admin",
}
LOG_READ = {
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/logging.viewer",
    "roles/logging.privateLogViewer",
    "roles/logging.admin",
}
COMPUTE_READ = {
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/compute.viewer",
    "roles/compute.admin",
    "roles/compute.instanceAdmin.v1",
}
BUCKET_READ = {
    "roles/owner",
    "roles/editor",
    "roles/viewer",
    "roles/storage.admin",
    "roles/storage.objectAdmin",
    "roles/storage.objectViewer",
    "roles/storage.objectUser",
    "roles/storage.legacyObjectReader",
    "roles/storage.legacyBucketReader",
}
KIND_ROLES = {
    "cloudrun_env": RUN_READ,
    "log_entry": LOG_READ,
    "instance_metadata": COMPUTE_READ,
    "bucket_object": BUCKET_READ,
}
POWERFUL = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.serviceAccountUser",
    "roles/storage.admin",
    "roles/secretmanager.admin",
    "roles/compute.admin",
}
BROAD_THRESHOLD = 10


def members_with(policy: dict[str, Any], roles: set[str]) -> list[str]:
    out: list[str] = []
    for b in policy.get("bindings", []):
        if b["role"] in roles:
            out += b.get("members", [])
    return sorted(set(out))


def assess(
    item: Item, project_policy: dict[str, Any] | None, bucket_pol: dict[str, Any] | None = None
) -> Exposure:
    if item.kind == "file":
        return Exposure(
            level="unknown", why="local file: exposure depends on where it is stored or committed"
        )
    if item.public:
        return Exposure(
            level="public",
            reader_count=-1,
            readers=["allUsers"],
            why="the bucket grants access to allUsers/allAuthenticatedUsers",
        )
    if project_policy is None:
        return Exposure(level="unknown", why="project IAM policy was not available")
    roles = KIND_ROLES[item.kind]
    readers = members_with(project_policy, roles)
    if item.kind == "bucket_object" and bucket_pol:
        readers = sorted(set(readers) | set(members_with(bucket_pol, roles)))
    public = [m for m in readers if m in ("allUsers", "allAuthenticatedUsers")]
    if public:
        return Exposure(
            level="public",
            readers=public,
            reader_count=len(readers),
            why="a public principal can read this source",
        )
    broad = len(readers) >= BROAD_THRESHOLD or any(
        m.startswith(("group:", "domain:")) for m in readers
    )
    return Exposure(
        level="broad" if broad else "limited",
        readers=readers[:10],
        reader_count=len(readers),
        why=f"{len(readers)} principal(s) hold a role that can read this source",
    )


def sa_roles(project_policy: dict[str, Any] | None, email: str) -> list[str]:
    if not project_policy:
        return []
    me = f"serviceAccount:{email}"
    return sorted(
        {b["role"] for b in project_policy.get("bindings", []) if me in b.get("members", [])}
    )
