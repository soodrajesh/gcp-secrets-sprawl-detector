"""Secret detectors. `scan_text` returns Matches that carry the raw value ONLY inside this module's
return type; `to_finding_parts` masks and fingerprints it immediately, and nothing outside the scanner
keeps the value."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
from dataclasses import dataclass

SALT = os.urandom(
    16
)  # per process: fingerprints dedupe within a scan but cannot be matched across scans or guessed

# Values that are documentation placeholders, not secrets.
PLACEHOLDER = re.compile(
    r"(example|sample|placeholder|changeme|change_me|your[_-]?|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|x{6,}|\*{4,}|\.{3,}|dummy|fake|redacted|insert|todo|"
    r"^(password|secret|token|key|none|null|true|false|test)$)",
    re.I,
)
KNOWN_FAKES = {"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}


@dataclass
class Rule:
    id: str
    secret_type: str
    pattern: re.Pattern
    base: str  # base severity
    group: int = 0
    min_entropy: float = 0.0
    why: str = ""


def _r(rule_id, secret_type, pat, base, group=0, min_entropy=0.0, why="", flags=0):
    return Rule(rule_id, secret_type, re.compile(pat, flags), base, group, min_entropy, why)


RULES: list[Rule] = [
    _r(
        "S001",
        "aws_access_key_id",
        r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b",
        "high",
        1,
        0.0,
        "AWS access key id (the secret key usually sits next to it)",
    ),
    _r(
        "S002",
        "aws_secret_access_key",
        r"(?i)aws_?secret_?(?:access_?)?key[\s\"']*[:=][\s\"']*([A-Za-z0-9/+=]{40})\b",
        "critical",
        1,
        3.5,
        "AWS secret access key",
    ),
    _r("S003", "gcp_api_key", r"\b(AIza[0-9A-Za-z_\-]{35})\b", "high", 1, 0.0, "Google API key"),
    _r(
        "S004",
        "gcp_oauth_token",
        r"\b(ya29\.[0-9A-Za-z_\-]{40,})\b",
        "high",
        1,
        0.0,
        "Google OAuth access token (short-lived but powerful)",
    ),
    _r(
        "S005",
        "gcp_refresh_token",
        r"\b(1//0[0-9A-Za-z_\-]{40,})\b",
        "critical",
        1,
        0.0,
        "Google OAuth refresh token (long-lived)",
    ),
    _r(
        "S006",
        "private_key",
        r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        "critical",
        1,
        0.0,
        "private key material",
    ),
    _r(
        "S007",
        "github_token",
        r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b",
        "high",
        1,
        0.0,
        "GitHub token",
    ),
    _r("S008", "gitlab_token", r"\b(glpat-[A-Za-z0-9_\-]{20,})\b", "high", 1, 0.0, "GitLab token"),
    _r("S009", "slack_token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", "high", 1, 0.0, "Slack token"),
    _r(
        "S010",
        "slack_webhook",
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)",
        "medium",
        1,
        0.0,
        "Slack incoming webhook",
    ),
    _r(
        "S011",
        "stripe_live_key",
        r"\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b",
        "critical",
        1,
        0.0,
        "Stripe live secret key",
    ),
    _r(
        "S012",
        "openai_api_key",
        r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b",
        "high",
        1,
        3.0,
        "OpenAI-style API key",
    ),
    _r(
        "S013",
        "anthropic_api_key",
        r"\b(sk-ant-[A-Za-z0-9_\-]{30,})\b",
        "high",
        1,
        0.0,
        "Anthropic API key",
    ),
    _r(
        "S014",
        "sendgrid_key",
        r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b",
        "high",
        1,
        0.0,
        "SendGrid API key",
    ),
    _r("S015", "npm_token", r"\b(npm_[A-Za-z0-9]{36})\b", "high", 1, 0.0, "npm token"),
    _r(
        "S016",
        "jwt",
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
        "medium",
        1,
        0.0,
        "JSON Web Token (may be a live credential)",
    ),
    _r(
        "S017",
        "database_url_with_password",
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^\s:/@\"']+:([^\s@\"']{4,})@[^\s/\"']+",
        "high",
        1,
        0.0,
        "database connection string with an embedded password",
    ),
    _r(
        "S018",
        "url_with_credentials",
        r"\bhttps?://[^\s:/@\"']+:([^\s@\"']{4,})@[^\s/\"']+",
        "medium",
        1,
        0.0,
        "URL with embedded credentials",
    ),
    _r(
        "S019",
        "generic_secret_assignment",
        r"(?i)\b(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|token)\b[\s\"']*[:=][\s\"']*([^\s\"',;`()\[\]$<>{}\\]{10,})",
        "medium",
        1,
        3.3,
        "high-entropy value assigned to a secret-looking name",
    ),
]

GCP_SA_KEY_HINT = re.compile(r'"type"\s*:\s*"service_account"')


@dataclass
class Match:
    rule: Rule
    value: str  # RAW: consumed by to_parts() and dropped
    start: int
    extra: dict


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


IDENT = re.compile(r"[A-Za-z_][A-Za-z_.]*")
ATTR_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")


def looks_like_code(v: str) -> bool:
    """An identifier, attribute path or constant name (`mint_token`, `self._audience`, `random_password.x.result`,
    `CLIENT_SECRET`) is a reference to a secret, not the secret. Real secrets nearly always mix in digits or symbols."""
    if ATTR_PATH.fullmatch(
        v
    ):  # a.b.c, even with digits in a segment (google.oauth2.id_token.fetch_id_token)
        return True
    return bool(IDENT.fullmatch(v)) and (v.islower() or v.isupper() or "_" in v or "." in v)


def is_placeholder(v: str) -> bool:
    return v in KNOWN_FAKES or bool(PLACEHOLDER.search(v))


def scan_text(text: str, max_matches: int = 50) -> list[Match]:
    out: list[Match] = []
    seen: set[tuple[str, str]] = set()
    sa = _service_account_key(text)
    if sa:
        out.append(Match(_SA_RULE, sa["private_key_id"], 0, sa))
        seen.add((_SA_RULE.id, sa["private_key_id"]))
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            val = m.group(rule.group)
            if (
                rule.id == "S006" and sa
            ):  # the SA key's own PEM is already reported as the service-account key
                continue
            if is_placeholder(val) or (rule.min_entropy and entropy(val) < rule.min_entropy):
                continue
            if rule.id == "S019" and (
                looks_like_code(val) or any((r.id, val) in seen for r in RULES if r.id != "S019")
            ):
                continue
            key = (rule.id, val)
            if key in seen:
                continue
            seen.add(key)
            extra = {"expired": _jwt_expired(val)} if rule.id == "S016" else {}
            out.append(Match(rule, val, m.start(rule.group), extra))
            if len(out) >= max_matches:
                return out
    # a value matched by a specific rule should not also be reported by the generic assignment rule
    specific = {m.value for m in out if m.rule.id != "S019"}
    return [
        m
        for m in out
        if m.rule.id != "S019" or not any(m.value in v or v in m.value for v in specific)
    ]


_SA_RULE = Rule(
    "S020",
    "gcp_service_account_key",
    re.compile("x"),
    "critical",
    0,
    0.0,
    "Google Cloud service-account key (JSON)",
)


def _jwt_expired(token: str) -> bool:
    import base64
    import time

    try:
        body = token.split(".")[1]
        exp = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))).get("exp")
        return isinstance(exp, (int, float)) and exp < time.time()
    except (ValueError, IndexError):
        return False


def _service_account_key(text: str) -> dict | None:
    if not GCP_SA_KEY_HINT.search(text) or "private_key" not in text:
        return None
    start = text.find("{")
    while start != -1:
        try:
            obj, _ = json.JSONDecoder().raw_decode(text[start:])
            if (
                isinstance(obj, dict)
                and obj.get("type") == "service_account"
                and obj.get("private_key")
                and obj.get("client_email")
            ):
                return {
                    "client_email": obj["client_email"],
                    "private_key_id": str(obj.get("private_key_id", "")),
                    "project_id": obj.get("project_id", ""),
                }
        except ValueError:
            pass
        start = text.find("{", start + 1)
    return None


def mask(value: str, secret_type: str) -> str:
    if secret_type in ("private_key", "gcp_service_account_key"):
        return f"{secret_type.replace('_', ' ')} (value withheld)"
    n = len(value)
    if n <= 8:
        return f"{'*' * n} ({n} chars)"
    return f"{value[:4]}…{value[-2:]} ({n} chars)"


def fingerprint(value: str) -> str:
    return hmac.new(SALT, value.encode(), hashlib.sha256).hexdigest()[:12]


def to_parts(m: Match) -> dict:
    """Everything the rest of the system may know about a match. The raw value does not leave here."""
    return {
        "rule": m.rule.id,
        "secret_type": m.rule.secret_type,
        "base": m.rule.base,
        "why": m.rule.why,
        "preview": mask(m.value, m.rule.secret_type),
        "fingerprint": fingerprint(m.value + m.rule.secret_type),
        "sa": (
            {"service_account": m.extra["client_email"], "key_id": m.extra["private_key_id"]}
            if "client_email" in m.extra
            else None
        ),
        "expired": bool(m.extra.get("expired")),
    }
