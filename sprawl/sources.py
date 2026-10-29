"""Where secrets leak. Each source yields `Item`s (text + where it came from). All reads are read-only and
bounded (item counts, sizes, time windows). The sources never persist what they read."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import Item, SourceStat

RUN = "https://run.googleapis.com/v2"
STORAGE = "https://storage.googleapis.com/storage/v1"
LOGGING = "https://logging.googleapis.com/v2/entries:list"
COMPUTE = "https://compute.googleapis.com/compute/v1"

TEXT_EXT = {
    ".env",
    ".json",
    ".tfstate",
    ".yaml",
    ".yml",
    ".txt",
    ".conf",
    ".cfg",
    ".ini",
    ".sh",
    ".py",
    ".js",
    ".ts",
    ".tf",
    ".tfvars",
    ".pem",
    ".key",
    ".properties",
    ".xml",
    ".toml",
    ".md",
    ".log",
    ".csv",
    ".sql",
    ".backup",
    ".bak",
    "",
}
MAX_OBJECT_BYTES = 512_000
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "site-packages",
    "__pycache__",
    ".terraform",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}
MAX_OBJECTS_PER_BUCKET = 200
MAX_LOG_ENTRIES = 3000


class SourceError(RuntimeError):
    pass


def session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return AuthorizedSession(creds)


def _get(s, url: str, **kw) -> dict[str, Any]:
    r = s.get(url, timeout=60, **kw)
    if r.status_code != 200:
        raise SourceError(f"GET {url.split('//')[1][:60]} -> {r.status_code}: {r.text[:120]}")
    return r.json()


def cloud_run_env(s, project: str, stat: SourceStat) -> Iterator[Item]:
    """Environment variables of every Cloud Run service. Values that reference Secret Manager are the right
    pattern and are not scanned; literal values are."""
    page = ""
    while True:
        d = _get(
            s,
            f"{RUN}/projects/{project}/locations/-/services",
            params={"pageSize": 100, "pageToken": page},
        )
        for svc in d.get("services", []):
            name = svc["name"].split("/")[-1]
            for c in svc.get("template", {}).get("containers") or []:
                for env in c.get("env", []) or []:
                    stat.scanned += 1
                    if "valueSource" in env:
                        stat.skipped += 1
                        continue
                    yield Item(
                        kind="cloudrun_env",
                        resource=f"run:{name}",
                        location=f"env {env.get('name', '?')}",
                        text=f"{env.get('name', '')}={env.get('value', '')}",
                    )
        page = d.get("nextPageToken", "")
        if not page:
            break


def buckets(s, project: str, stat: SourceStat, only: list[str] | None = None) -> Iterator[Item]:
    names = only or [
        b["name"] for b in _get(s, f"{STORAGE}/b", params={"project": project}).get("items", [])
    ]
    for bucket in names:
        public = False
        try:
            pol = _get(s, f"{STORAGE}/b/{bucket}/iam")
            public = any(
                m in ("allUsers", "allAuthenticatedUsers")
                for b in pol.get("bindings", [])
                for m in b.get("members", [])
            )
        except SourceError:
            pass
        d = _get(s, f"{STORAGE}/b/{bucket}/o", params={"maxResults": MAX_OBJECTS_PER_BUCKET})
        for o in d.get("items", []):
            name = o["name"]
            ext = Path(name).suffix.lower()
            if (
                int(o.get("size", 0)) > MAX_OBJECT_BYTES
                or ext not in TEXT_EXT
                or name.endswith("/")
            ):
                stat.skipped += 1
                continue
            r = s.get(
                f"{STORAGE}/b/{bucket}/o/{name.replace('/', '%2F')}",
                params={"alt": "media"},
                timeout=60,
            )
            if r.status_code != 200:
                stat.skipped += 1
                continue
            stat.scanned += 1
            yield Item(
                kind="bucket_object",
                resource=f"gs://{bucket}/{name}",
                location="",
                text=r.content.decode("utf-8", "ignore"),
                public=public,
            )


def logs(s, project: str, stat: SourceStat, hours: int = 24) -> Iterator[Item]:
    since = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    token, n = "", 0
    while n < MAX_LOG_ENTRIES:
        body = {
            "resourceNames": [f"projects/{project}"],
            "filter": f'timestamp>="{since}"',
            "orderBy": "timestamp desc",
            "pageSize": 500,
        }
        if token:
            body["pageToken"] = token
        r = s.post(LOGGING, json=body, timeout=60)
        if r.status_code != 200:
            raise SourceError(f"logging -> {r.status_code}: {r.text[:120]}")
        d = r.json()
        for e in d.get("entries", []):
            n += 1
            stat.scanned += 1
            text = e.get("textPayload") or json.dumps(
                e.get("jsonPayload") or e.get("protoPayload", {}).get("request") or "", default=str
            )
            if len(text) < 12:
                stat.skipped += 1
                continue
            yield Item(
                kind="log_entry",
                resource=e.get("logName", "").split("/logs/")[-1],
                location=e.get("timestamp", ""),
                text=text[:20000],
            )
        token = d.get("nextPageToken", "")
        if not token:
            break


def instance_metadata(s, project: str, stat: SourceStat) -> Iterator[Item]:
    d = _get(s, f"{COMPUTE}/projects/{project}/aggregated/instances")
    for scope in d.get("items", {}).values():
        for inst in scope.get("instances", []):
            for it in inst.get("metadata", {}).get("items", []) or []:
                stat.scanned += 1
                yield Item(
                    kind="instance_metadata",
                    resource=f"vm:{inst['name']}",
                    location=f"metadata {it.get('key')}",
                    text=f"{it.get('key')}={it.get('value', '')}",
                )
    proj = _get(s, f"{COMPUTE}/projects/{project}")
    for it in proj.get("commonInstanceMetadata", {}).get("items", []) or []:
        stat.scanned += 1
        yield Item(
            kind="instance_metadata",
            resource=f"project:{project}",
            location=f"metadata {it.get('key')}",
            text=f"{it.get('key')}={it.get('value', '')}",
        )


def directory(path: str, stat: SourceStat) -> Iterator[Item]:
    root = Path(path)
    for f in sorted(root.rglob("*")):
        if (
            not f.is_file()
            or f.stat().st_size > MAX_OBJECT_BYTES
            or f.suffix.lower() not in TEXT_EXT
            or any(p in SKIP_DIRS or p.endswith("-venv") for p in f.parts)
        ):
            stat.skipped += 1
            continue
        stat.scanned += 1
        yield Item(
            kind="file",
            resource=str(f.relative_to(root)),
            location="",
            text=f.read_text("utf-8", "ignore"),
        )


def project_policy(s, project: str) -> dict[str, Any]:
    r = s.post(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy",
        json={"options": {"requestedPolicyVersion": 3}},
        timeout=60,
    )
    if r.status_code != 200:
        raise SourceError(f"getIamPolicy -> {r.status_code}")
    return r.json()


def bucket_policy(s, bucket: str) -> dict[str, Any]:
    return _get(s, f"{STORAGE}/b/{bucket}/iam")


def key_state(s, project: str, email: str, key_id: str) -> str:
    """Is this service-account key still active? Asked with OUR credentials by LISTING the account's user-managed
    keys (roles/iam.securityReviewer can list but not get): the leaked key is never used."""
    r = s.get(
        f"https://iam.googleapis.com/v1/projects/{project or '-'}/serviceAccounts/{email}/keys",
        params={"keyTypes": "USER_MANAGED"},
        timeout=30,
    )
    if r.status_code == 404:  # the service account itself no longer exists
        return "deleted_or_disabled"
    if r.status_code != 200:
        return "unknown"
    for k in r.json().get("keys", []):
        if k.get("name", "").rsplit("/", 1)[-1] == key_id:
            return "deleted_or_disabled" if k.get("disabled") else "active"
    return "deleted_or_disabled"


ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
