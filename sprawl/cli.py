"""CLI.  Exit codes: 0 clean, 1 attention, 2 critical, 3 error.

    sprawl scan my-project --sources cloudrun_env,log_entry --hours 24
    sprawl scan-dir ./repo            # scan files locally (e.g. before committing)
Output contains masked previews only. Secret values are never printed."""

from __future__ import annotations

import argparse
import asyncio
import sys

from .llm import Budget, LLMError, make_llm
from .models import Report
from .orchestrator import ALL_SOURCES, scan_directory, scan_project
from .sources import SourceError

EXIT = {"clean": 0, "attention": 1, "critical": 2}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}


def render(r: Report, color: bool) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    out = [
        c(
            {"clean": "32", "attention": "33", "critical": "1;31"}[r.posture],
            f"POSTURE: {r.posture.upper()}",
        ),
        r.summary,
        "",
    ]
    out += [
        f"  source {s.kind:18} scanned {s.scanned:5} skipped {s.skipped:4} {s.note}"
        for s in r.sources
    ] + [""]
    for f in r.findings:
        out.append(
            f"{c(COLOR[f.severity], f.severity.upper().ljust(8))} {f.id:9} {f.secret_type:26} {f.preview}"
        )
        out.append(
            f"          {f.kind} · {f.resource} {f.location} · exposure: {f.exposure.level} ({f.exposure.reader_count} readers)"
        )
        out.append(f"          {f.why}")
        if f.note:
            out.append(f"          note: {f.note}")
        out += [f"          $ {x}" for x in f.remediation[:2]]
    return "\n".join(out + [f"! {d}" for d in r.degraded])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sprawl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan a GCP project (read-only)")
    sc.add_argument("project")
    sc.add_argument("--sources", default=",".join(ALL_SOURCES))
    sc.add_argument("--hours", type=int, default=24)
    sc.add_argument("--bucket", action="append", help="bucket to scan (repeatable); default: none")
    sd = sub.add_parser("scan-dir", help="scan a local directory")
    sd.add_argument("path")
    for p in (sc, sd):
        p.add_argument("--llm", default="none", choices=["none", "mock", "vertex", "openai"])
        p.add_argument("--format", default="text", choices=["text", "json"])
    a = ap.parse_args(argv)
    try:
        llm = make_llm(a.llm)
        if a.cmd == "scan":
            wanted = [x for x in a.sources.split(",") if x]
            if a.bucket is None:
                wanted = [w for w in wanted if w != "bucket_object"]
            rep = asyncio.run(
                scan_project(
                    a.project,
                    llm,
                    wanted=wanted,
                    hours=a.hours,
                    only_buckets=a.bucket,
                    budget=Budget(),
                )
            )
        else:
            rep = asyncio.run(scan_directory(a.path, llm, Budget()))
    except (OSError, ValueError, LLMError, SourceError) as e:
        print(
            f"error: {type(e).__name__}", file=sys.stderr
        )  # not the message: it could echo scanned content
        return 3
    print(rep.model_dump_json(indent=1) if a.format == "json" else render(rep, sys.stdout.isatty()))
    return EXIT[rep.posture]


if __name__ == "__main__":
    sys.exit(main())
