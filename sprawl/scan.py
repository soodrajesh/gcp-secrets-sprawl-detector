"""items -> findings. The raw secret exists only between `scan_text` and `to_parts` (same loop iteration)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from . import detectors, exposure, scoring, sources
from .models import SEV_RANK, Finding, Item, KeyStatus


def findings_from_items(
    items: Iterable[Item],
    *,
    project: str = "",
    policy: dict[str, Any] | None = None,
    s=None,
    bucket_policies: dict[str, dict] | None = None,
    lookup_keys: bool = True,
) -> list[Finding]:
    bucket_policies = bucket_policies or {}
    out: dict[tuple[str, str, str], Finding] = {}
    key_cache: dict[tuple[str, str], str] = {}
    for item in items:
        for m in detectors.scan_text(item.text):
            parts = detectors.to_parts(
                m
            )  # masks and fingerprints; `m` (and the raw value) is dropped after this iteration
            bucket_pol = (
                bucket_policies.get(item.resource.split("/")[2])
                if item.kind == "bucket_object" and item.resource.startswith("gs://")
                else None
            )
            expo = exposure.assess(item, policy, bucket_pol)
            key = None
            if parts["sa"]:
                email, kid = parts["sa"]["service_account"], parts["sa"]["key_id"]
                state = "unknown"
                if lookup_keys and s is not None:
                    state = key_cache.setdefault(
                        (email, kid), sources.key_state(s, project, email, kid)
                    )
                roles = exposure.sa_roles(policy, email)
                key = KeyStatus(
                    service_account=email,
                    key_id=kid,
                    state=state,
                    roles=roles,
                    powerful=bool(set(roles) & exposure.POWERFUL),
                )
            sev, why = scoring.severity(parts["base"], parts, expo, key)
            dedupe = (parts["fingerprint"], item.resource, item.location)
            if dedupe in out:
                out[dedupe].occurrences += 1
                continue
            out[dedupe] = Finding(
                rule=parts["rule"],
                secret_type=parts["secret_type"],
                severity=sev,
                kind=item.kind,
                resource=item.resource,
                location=item.location,
                preview=parts["preview"],
                fingerprint=parts["fingerprint"],
                exposure=expo,
                key=key,
                why=why,
                remediation=scoring.remediation(item, parts, key),
            )
    result = sorted(
        out.values(), key=lambda f: (-SEV_RANK[f.severity], f.kind, f.resource, f.location)
    )
    by_fp: dict[str, int] = {}
    for f in result:
        by_fp[f.fingerprint] = by_fp.get(f.fingerprint, 0) + 1
    counters: dict[str, int] = {}
    for f in result:
        counters[f.rule] = counters.get(f.rule, 0) + 1
        f.id = f"{f.rule}-{counters[f.rule]}"
        if by_fp[f.fingerprint] > 1:
            f.why += f"; the same secret appears in {by_fp[f.fingerprint]} places in this scan"
    return result
