from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(name, default).split(",") if x.strip())


@dataclass
class Settings:
    provider: str = field(default_factory=lambda: os.environ.get("SPRAWL_LLM", "mock"))
    model: str | None = field(default_factory=lambda: os.environ.get("SPRAWL_MODEL") or None)
    allowed_providers: tuple[str, ...] = field(
        default_factory=lambda: _list("SPRAWL_ALLOWED_PROVIDERS", "mock,none")
    )
    projects: tuple[str, ...] = field(
        default_factory=lambda: _list("SPRAWL_PROJECTS")
    )  # projects that may be scanned
    buckets: tuple[str, ...] = field(
        default_factory=lambda: _list("SPRAWL_BUCKETS")
    )  # buckets that may be scanned (empty = none)
    max_hours: int = 72
    daily_budget_usd: float = field(
        default_factory=lambda: float(os.environ.get("SPRAWL_DAILY_BUDGET_USD", 0.5))
    )
    max_llm_calls: int = 10
    review_budget_usd: float = 0.05
    max_body_bytes: int = 200_000
