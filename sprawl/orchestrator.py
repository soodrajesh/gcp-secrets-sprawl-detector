"""sources -> [scan] findings (masked) -> [exposure + key status + severity] -> parallel [explainer x N] -> posture"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from . import agents, sources
from .llm import LLM, Budget
from .models import SEV_RANK, Finding, Item, Report, SourceStat, TraceStep
from .scan import findings_from_items

TOP_EXPLAINED = 8
ALL_SOURCES = ("cloudrun_env", "bucket_object", "log_entry", "instance_metadata")


def collect_gcp(
    project: str, wanted: list[str], hours: int, only_buckets: list[str] | None, s=None
) -> tuple[list[Item], list[SourceStat], dict[str, Any] | None, dict[str, dict], list[str]]:
    s = s or sources.session()
    items: list[Item] = []
    stats: list[SourceStat] = []
    degraded: list[str] = []
    try:
        policy = sources.project_policy(s, project)
    except sources.SourceError as e:
        policy = None
        degraded.append(f"project IAM policy unavailable ({e}); exposure will be 'unknown'")
    bucket_pols: dict[str, dict] = {}
    plan = {
        "cloudrun_env": lambda st: sources.cloud_run_env(s, project, st),
        "bucket_object": lambda st: sources.buckets(s, project, st, only_buckets),
        "log_entry": lambda st: sources.logs(s, project, st, hours),
        "instance_metadata": lambda st: sources.instance_metadata(s, project, st),
    }
    for kind in wanted:
        stat = SourceStat(kind=kind)
        stats.append(stat)
        try:
            items.extend(plan[kind](stat))
        except sources.SourceError as e:
            stat.note = f"failed: {e}"[:200]
            degraded.append(f"{kind}: {stat.note}")
    for it in items:
        if it.kind == "bucket_object" and it.resource.startswith("gs://"):
            b = it.resource.split("/")[2]
            if b not in bucket_pols:
                try:
                    bucket_pols[b] = sources.bucket_policy(s, b)
                except sources.SourceError:
                    bucket_pols[b] = {}
    return items, stats, policy, bucket_pols, degraded


def posture(findings: list[Finding]) -> str:
    sev = {f.severity for f in findings}
    return (
        "critical"
        if "critical" in sev
        else "attention"
        if "high" in sev or "medium" in sev
        else "clean"
    )


def summary(post: str, findings: list[Finding], stats: list[SourceStat]) -> str:
    n = {k: sum(f.severity == k for f in findings) for k in ("critical", "high", "medium", "low")}
    scanned = sum(st.scanned for st in stats)
    if not findings:
        return f"No credentials found in {scanned} scanned item(s)."
    kinds = sorted({f.kind for f in findings})
    return (
        f"{len(findings)} exposed credential(s) in {scanned} scanned item(s): {n['critical']} critical, {n['high']} high, "
        f"{n['medium']} medium, {n['low']} low. Found in: {', '.join(kinds)}."
    )


async def build_report(
    project: str,
    findings: list[Finding],
    stats: list[SourceStat],
    llm: LLM,
    *,
    degraded: list[str] | None = None,
    budget: Budget | None = None,
    timeout: float = 30.0,
    t0: float | None = None,
) -> Report:
    t0 = t0 or time.perf_counter()
    budget = budget or Budget()
    degraded = list(degraded or [])
    trace = [
        TraceStep(
            agent="scan",
            action="detect",
            duration_ms=int((time.perf_counter() - t0) * 1000),
            note=f"{sum(s.scanned for s in stats)} items scanned, {len(findings)} findings",
        )
    ]
    dropped: list[dict[str, str]] = []
    if llm.name != "none" and findings:
        top = sorted(findings, key=lambda f: -SEV_RANK[f.severity])[:TOP_EXPLAINED]
        for f, (note, step, why) in zip(
            top,
            await asyncio.gather(*(agents.explain(f, llm, budget, t0, timeout) for f in top)),
            strict=True,
        ):
            trace.append(step)
            if note:
                f.note = note
            elif why:
                dropped.append({"agent": "explainer", "item": f"note for {f.id}", "reason": why})
            elif step.status == "error":
                degraded.append(f"explainer {f.id}: {step.note}")
    else:
        trace.append(
            TraceStep(
                agent="explainer",
                action="explain",
                status="skipped",
                note="no model configured or nothing to explain",
            )
        )
    post = posture(findings)
    counts = {
        k: sum(f.severity == k for f in findings)
        for k in ("critical", "high", "medium", "low", "info")
    }
    return Report(
        id=uuid.uuid4().hex[:12],
        created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        project=project,
        provider=llm.name,
        model=llm.model,
        posture=post,
        summary=summary(post, findings, stats),
        findings=findings,
        sources=stats,
        counts=counts,
        dropped=dropped,
        degraded=degraded,
        trace=trace,
        duration_ms=int((time.perf_counter() - t0) * 1000),
    )


async def scan_project(
    project: str,
    llm: LLM,
    *,
    wanted: list[str] | None = None,
    hours: int = 24,
    only_buckets: list[str] | None = None,
    budget: Budget | None = None,
    s=None,
) -> Report:
    t0 = time.perf_counter()
    wanted = wanted or list(ALL_SOURCES)
    items, stats, policy, bucket_pols, degraded = await asyncio.to_thread(
        collect_gcp, project, wanted, hours, only_buckets, s
    )
    findings = await asyncio.to_thread(
        findings_from_items,
        items,
        project=project,
        policy=policy,
        s=s or sources.session(),
        bucket_policies=bucket_pols,
    )
    return await build_report(
        project, findings, stats, llm, degraded=degraded, budget=budget, t0=t0
    )


async def scan_directory(path: str, llm: LLM, budget: Budget | None = None) -> Report:
    t0 = time.perf_counter()
    stat = SourceStat(kind="file")
    items: Iterable[Item] = list(sources.directory(path, stat))
    findings = await asyncio.to_thread(findings_from_items, items, lookup_keys=False)
    return await build_report(path, findings, [stat], llm, budget=budget, t0=t0)
