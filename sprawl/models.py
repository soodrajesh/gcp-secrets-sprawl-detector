"""Models. Note what is NOT here: there is no field that holds a raw secret. The scanning layer returns a
masked preview and a salted fingerprint, so nothing downstream (API, UI, logs, models) can leak the value."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVS = ["info", "low", "medium", "high", "critical"]
SourceKind = Literal["cloudrun_env", "bucket_object", "log_entry", "instance_metadata", "file"]


class Item(BaseModel):
    """A chunk of text from somewhere in the project, plus where it came from and who can read it."""

    kind: SourceKind
    resource: str  # e.g. service name, gs://bucket/path, log name, instance name
    location: str = ""  # e.g. env var name, line number, log timestamp
    text: str
    readers_hint: list[str] = Field(default_factory=list)
    public: bool = False
    truncated: bool = False


class Exposure(BaseModel):
    level: Literal["public", "broad", "limited", "unknown"] = "unknown"
    readers: list[str] = Field(
        default_factory=list
    )  # capped list of principals that can read the source
    reader_count: int = 0
    why: str = ""


class KeyStatus(BaseModel):
    """For GCP service-account keys: is that key still active, and what can the account do? (looked up with
    our own read-only credentials; the leaked key is never used)."""

    service_account: str
    key_id: str = ""
    state: Literal["active", "deleted_or_disabled", "unknown"] = "unknown"
    roles: list[str] = Field(default_factory=list)
    powerful: bool = False


class Finding(BaseModel):
    id: str = ""
    rule: str
    secret_type: str
    severity: Severity
    kind: SourceKind
    resource: str
    location: str = ""
    preview: str  # masked, e.g. "AKIA…XY (20 chars)"
    fingerprint: str  # salted per scan: dedupes within a scan, cannot be used to guess the secret
    occurrences: int = 1
    exposure: Exposure = Field(default_factory=Exposure)
    key: KeyStatus | None = None
    why: str = ""
    remediation: list[str] = Field(default_factory=list)
    note: str = ""  # validated model explanation (written from redacted metadata only)


class TraceStep(BaseModel):
    agent: str
    action: str
    status: Literal["ok", "skipped", "error"] = "ok"
    start_ms: int = 0
    duration_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    note: str = ""


class SourceStat(BaseModel):
    kind: str
    scanned: int = 0
    skipped: int = 0
    note: str = ""


class Report(BaseModel):
    id: str
    created_at: str
    project: str
    provider: str
    model: str
    posture: Literal["clean", "attention", "critical"]
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    sources: list[SourceStat] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    dropped: list[dict[str, str]] = Field(default_factory=list)
    degraded: list[str] = Field(default_factory=list)
    trace: list[TraceStep] = Field(default_factory=list)
    duration_ms: int = 0
