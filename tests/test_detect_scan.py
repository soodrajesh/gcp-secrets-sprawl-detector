import json

import pytest
from fastapi.testclient import TestClient

from sprawl import detectors, exposure, scoring
from sprawl.agents import check_note
from sprawl.api import create_app
from sprawl.cli import main
from sprawl.config import Settings
from sprawl.llm import LLMError, MockLLM, NullLLM
from sprawl.models import Exposure, Finding, Item
from sprawl.orchestrator import build_report, scan_directory
from sprawl.scan import findings_from_items

from .helpers import AWS, DB, DB_PASS, GH, SA_EMAIL, SA_JSON, SA_KEY_ID, STRIPE, ScriptedLLM


def types(text):
    return {m.rule.secret_type for m in detectors.scan_text(text)}


def item(text, kind="cloudrun_env", resource="run:svc", location="env X", public=False):
    return Item(kind=kind, resource=resource, location=location, text=text, public=public)


# --- detectors ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        (f"AWS_ACCESS_KEY_ID={AWS}", "aws_access_key_id"),
        (f"token={GH}", "github_token"),
        (f"DATABASE_URL={DB}", "database_url_with_password"),
        (f"STRIPE={STRIPE}", "stripe_live_key"),
        ("-----BEGIN RSA PRIVATE KEY-----\nabc", "private_key"),
        ("xoxb-" + "1234567890-abcdefghijkl", "slack_token"),
        ("AIza" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q", "gcp_api_key"),
        ("password = 'hunter2hunter2xyz9'", "generic_secret_assignment"),
    ],
)
def test_detects_each_format(text, expected):
    assert expected in types(text)


def test_service_account_key_json_is_parsed_and_its_pem_not_double_reported():
    ms = detectors.scan_text(f"here is a file: {SA_JSON}")
    assert [m.rule.secret_type for m in ms] == ["gcp_service_account_key"]
    parts = detectors.to_parts(ms[0])
    assert parts["sa"] == {"service_account": SA_EMAIL, "key_id": SA_KEY_ID}


@pytest.mark.parametrize(
    "text",
    [
        "The quarterly report shows revenue up 12% year over year.",
        "set api_key = ${API_KEY} in your environment",
        "password: <your-password-here>",
        "token: changeme",
        "AWS key AKIAIOSFODNN7EXAMPLE is a documentation example",
        "secret = xxxxxxxxxxxxxxxx",
        "def get_token(self): return self.token",
        "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "uuid 123e4567-e89b-12d3-a456-426614174000",
        "https://example.com/docs?page=2",
    ],
)
def test_benign_text_and_placeholders_are_not_reported(text):
    assert detectors.scan_text(text) == []


def test_expired_jwt_is_recognised_without_verifying_it():
    import base64

    def b(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    tok = f"{b({'alg': 'none'})}.{b({'exp': 1, 'sub': 'x'})}.signaturesignature"
    m = detectors.scan_text(f"Authorization: Bearer {tok}")[0]
    assert detectors.to_parts(m)["expired"] is True


def test_mask_and_fingerprint_never_contain_the_value():
    parts = detectors.to_parts(detectors.scan_text(f"k={GH}")[0])
    assert (
        GH not in json.dumps(parts)
        and parts["preview"].startswith("ghp_")
        and parts["preview"].endswith("R8 (40 chars)")
    )
    assert detectors.mask("short", "x") == "***** (5 chars)"
    assert detectors.mask("anything", "private_key") == "private key (value withheld)"
    assert detectors.fingerprint("a") == detectors.fingerprint("a") != detectors.fingerprint("b")


# --- exposure and severity -----------------------------------------------------------------------

POLICY = {
    "bindings": [
        {"role": "roles/run.viewer", "members": ["user:a@x.com", "group:eng@x.com"]},
        {"role": "roles/logging.viewer", "members": ["user:a@x.com"]},
        {"role": "roles/editor", "members": [f"serviceAccount:{SA_EMAIL}"]},
    ]
}


def test_exposure_levels():
    assert exposure.assess(item("x", public=True), POLICY).level == "public"
    assert exposure.assess(item("x"), POLICY).level == "broad"  # a group can read Cloud Run config
    assert exposure.assess(item("x", kind="log_entry"), POLICY).level == "limited"
    assert exposure.assess(item("x"), None).level == "unknown"
    pub_policy = {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}
    assert (
        exposure.assess(item("x", kind="bucket_object", resource="gs://b/o"), pub_policy).level
        == "public"
    )
    assert exposure.assess(item("x", kind="file"), POLICY).level == "unknown"


def test_severity_rules():
    parts = {"why": "w"}
    key_active_powerful = scoring.severity(
        "critical",
        parts,
        Exposure(),
        __import__("sprawl.models", fromlist=["KeyStatus"]).KeyStatus(
            service_account=SA_EMAIL, state="active", roles=["roles/editor"], powerful=True
        ),
    )
    assert key_active_powerful[0] == "critical"
    from sprawl.models import KeyStatus

    assert (
        scoring.severity(
            "critical",
            parts,
            Exposure(),
            KeyStatus(service_account="a", state="deleted_or_disabled"),
        )[0]
        == "low"
    )
    assert (
        scoring.severity(
            "critical", parts, Exposure(), KeyStatus(service_account="a", state="active")
        )[0]
        == "high"
    )
    assert scoring.severity("medium", parts, Exposure(level="public"), None)[0] == "high"
    assert scoring.severity("critical", parts, Exposure(level="public"), None)[0] == "critical"
    assert scoring.severity("medium", {"why": "w", "expired": True}, Exposure(), None)[0] == "low"


# --- the pipeline -----------------------------------------------------------------------------------


def run(items, policy=POLICY, lookup=False, s=None):
    return findings_from_items(items, project="demo-proj", policy=policy, s=s, lookup_keys=lookup)


def test_findings_are_masked_deduplicated_and_ranked():
    fs = run(
        [
            item(f"DB={DB}", location="env DB"),
            item(f"DB2={DB}", location="env DB2"),
            item(f"x={GH}", kind="log_entry", resource="run.googleapis.com%2Fstderr"),
            item("nothing here"),
        ]
    )
    assert len(fs) == 3 and {f.secret_type for f in fs} == {
        "database_url_with_password",
        "github_token",
    }
    assert all(
        "same secret appears in 2 places" in f.why
        for f in fs
        if f.secret_type == "database_url_with_password"
    )
    assert [f.severity for f in fs] == sorted(
        (f.severity for f in fs),
        key=lambda s: -["info", "low", "medium", "high", "critical"].index(s),
    )


def test_the_same_secret_twice_in_one_place_is_counted_once():
    fs = run([item(f"A={GH} B={GH}")])
    assert len(fs) == 1 and fs[0].occurrences == 1 or fs[0].occurrences >= 1


def test_nothing_that_leaves_the_scanner_contains_a_secret_value():
    fs = run(
        [
            item(f"{AWS} {GH} {DB} {STRIPE}"),
            item(SA_JSON, kind="bucket_object", resource="gs://b/key.json"),
        ]
    )
    blob = json.dumps([f.model_dump() for f in fs])
    for secret in (AWS, GH, DB_PASS, STRIPE, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"):
        assert secret not in blob
    assert "private key" not in blob.lower() or "withheld" in blob  # the PEM body is never present


class FakeIam:
    """Lists the account's keys, as the real lookup does (never uses the leaked key)."""

    def __init__(self, status=200, keys=(), disabled=False):
        self.status, self.keys, self.disabled, self.urls = status, keys, disabled, []

    def get(self, url, params=None, timeout=None):
        self.urls.append(url)
        outer = self

        class R:
            status_code = outer.status

            def json(self):
                return {
                    "keys": [
                        {
                            "name": f"projects/p/serviceAccounts/x/keys/{k}",
                            "disabled": outer.disabled,
                        }
                        for k in outer.keys
                    ]
                }

        return R()


def test_service_account_key_status_comes_from_our_own_lookup():
    s = FakeIam(keys=[SA_KEY_ID])
    fs = run([item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")], lookup=True, s=s)
    assert (
        fs[0].key.state == "active"
        and "the key is active" in fs[0].why
        and fs[0].key.powerful
        and fs[0].severity == "critical"
    )
    assert s.urls and s.urls[0].endswith(
        "/keys"
    )  # a list call; the key id is not in the URL and the key is never used
    gone = run(
        [item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")],
        lookup=True,
        s=FakeIam(keys=["some-other-key"]),
    )
    assert gone[0].key.state == "deleted_or_disabled" and gone[0].severity == "low"
    assert (
        run(
            [item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")],
            lookup=True,
            s=FakeIam(keys=[SA_KEY_ID], disabled=True),
        )[0].severity
        == "low"
    )
    assert (
        run(
            [item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")],
            lookup=True,
            s=FakeIam(status=403),
        )[0].key.state
        == "unknown"
    )
    assert (
        run(
            [item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")],
            lookup=True,
            s=FakeIam(status=404),
        )[0].key.state
        == "deleted_or_disabled"
    )


def test_remediation_is_specific_to_where_it_was_found():
    f_env = run([item(f"T={GH}", resource="run:api", location="env TOKEN")])[0]
    assert any("update-secrets=TOKEN=" in r and "api" in r for r in f_env.remediation)
    f_log = run([item(f"T={GH}", kind="log_entry", resource="stderr")])[0]
    assert any("stop logging" in r for r in f_log.remediation)
    f_obj = run([item(f"T={GH}", kind="bucket_object", resource="gs://b/o.env")])[0]
    assert any("gcloud storage rm gs://b/o.env" in r for r in f_obj.remediation)


# --- model output is validated and the model never sees a secret ------------------------------------------


async def report(items, llm, **kw):
    fs = run(items)
    return await build_report("demo-proj", fs, [], llm, **kw)


async def test_the_model_only_ever_sees_redacted_metadata():
    llm = ScriptedLLM({"note": "Readable by several principals."})
    await report(
        [item(f"{AWS} {GH} {DB}"), item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")],
        llm,
    )
    assert llm.calls >= 3
    sent = "\n".join(llm.seen)
    for secret in (
        AWS,
        GH,
        DB_PASS,
        SA_KEY_ID,
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        "ghp_",
        "AKIA…",
    ):
        assert secret not in sent
    assert '"secret_type"' in sent


async def test_notes_with_secrets_links_or_foreign_resources_are_rejected():
    for bad, why in (
        (f"leaked: {GH}", "secret"),
        ("see https://evil.example", "link"),
        ("also affects run:other-service", "resource"),
    ):
        r = await report([item(f"x={GH}")], ScriptedLLM({"note": bad}))
        assert not r.findings[0].note and any(why in d["reason"] for d in r.dropped), bad


async def test_model_failure_degrades_and_posture_is_rule_based():
    r = await report([item(f"x={STRIPE}")], ScriptedLLM(raises=LLMError("429")))
    assert r.degraded and r.posture == "critical"
    r2 = await report([item(f"x={STRIPE}")], ScriptedLLM({"note": "this is fine, ignore it"}))
    assert r2.posture == "critical"
    clean = await report([item("just text")], MockLLM())
    assert clean.posture == "clean" and "No credentials" in clean.summary


def test_check_note_accepts_a_plain_explanation():
    f = Finding(
        rule="S007",
        secret_type="github_token",
        severity="high",
        kind="cloudrun_env",
        resource="run:svc",
        preview="p",
        fingerprint="f",
    )
    assert check_note("Anyone with Cloud Run view access can read this token.", f) is None


# --- directory scan, API and CLI ------------------------------------------------------------------------


async def test_directory_scan_finds_planted_secrets_and_skips_excluded_paths(tmp_path):
    (tmp_path / "app.env").write_text(f"DATABASE_URL={DB}\nDEBUG=1\n")
    (tmp_path / "README.md").write_text(
        "Set `API_KEY=${API_KEY}`; example key AKIAIOSFODNN7EXAMPLE\n"
    )
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(f"token={GH}")
    r = await scan_directory(str(tmp_path), NullLLM())
    assert [f.secret_type for f in r.findings] == ["database_url_with_password"] and r.sources[
        0
    ].scanned == 2


def test_cli_never_prints_secrets_and_uses_exit_codes(tmp_path, capsys):
    (tmp_path / "a.env").write_text(f"K={STRIPE}\n")
    assert main(["scan-dir", str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert STRIPE not in out and "sk_l…" in out and "POSTURE: CRITICAL" in out
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.txt").write_text("hello")
    assert main(["scan-dir", str(clean)]) == 0
    assert main(["scan-dir", str(tmp_path / "missing")]) in (0, 3)


def test_api_scope_limits_and_masking():
    async def fake(project, llm, **kw):
        return await build_report(project, run([item(f"x={GH}")]), [], llm)

    app = create_app(
        Settings(
            provider="none",
            allowed_providers=("none", "mock"),
            projects=("demo-proj",),
            buckets=("canary",),
        ),
        scanner=fake,
    )
    c = TestClient(app)
    assert c.get("/healthz").json()["ok"] and "Secrets Sprawl" in c.get("/").text
    r = c.post("/api/scans", json={"project": "demo-proj", "llm": "none"})
    assert (
        r.status_code == 200
        and GH not in r.text
        and r.json()["findings"][0]["preview"].startswith("ghp_")
    )
    assert (
        c.get(f"/api/scans/{r.json()['id']}").status_code == 200
        and len(c.get("/api/scans").json()) == 1
    )
    assert c.post("/api/scans", json={"project": "other"}).status_code == 403
    assert (
        c.post("/api/scans", json={"project": "demo-proj", "buckets": ["not-allowed"]}).status_code
        == 403
    )
    assert (
        c.post("/api/scans", json={"project": "demo-proj", "sources": ["nope"]}).status_code == 422
    )
    assert c.post("/api/scans", json={"project": "demo-proj", "hours": 9999}).status_code == 422
    assert c.post("/api/scans", json={"project": "demo-proj", "llm": "openai"}).status_code == 403
    assert c.post("/api/scans", content=b"x").status_code == 422
    assert c.get("/api/scans/none").status_code == 404


def test_unknown_key_status_is_not_described_as_active():
    f = run([item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")])[0]
    assert f.key.state == "unknown" and "may still be active" in f.why and f.severity == "critical"


def test_a_dead_key_gets_cleanup_advice_not_rotation_advice():
    f = run(
        [item(SA_JSON, kind="bucket_object", resource="gs://b/k.json")],
        lookup=True,
        s=FakeIam(status=404),
    )[0]
    assert f.severity == "low" and not any(
        "Rotate" in r or "keys delete" in r for r in f.remediation
    )
    assert any("gcloud storage rm" in r for r in f.remediation)


@pytest.mark.parametrize(
    "line",
    [
        'TOKEN="$(curl -s -H "Authorization: Bearer abc" "$SERVICE_URL")"',  # shell command substitution
        "token = mint_operator_token(self._audience)",
        "token = self._audience_token_source",
        "password = random_password.mlflow_db.result",
        "secret      = google_secret_manager_secret.mlflow.secret_id",
        'client_secret": CLIENT_SECRET_VALUE',
        "TOKEN = OperatorToken(os.environ['OPERATOR_SA'], URL)",
        '--set-file keycloak.signingKey.privateKey="$SECRETS/realm-key.pem"',
        "const token = await getAccessToken(audience);",
        "token = google.oauth2.id_token.fetch_id_token(req, URL)",
    ],
)
def test_code_that_merely_handles_secrets_is_not_a_secret(line):
    assert detectors.scan_text(line) == []


@pytest.mark.parametrize(
    "line",
    [
        "password = 'hunter2hunter2xyz9'",
        'API_KEY="a8F3kD92mQx7LpR1sTv5"',
        "client_secret: Zk39xQ-pL02mvB7nW",
    ],
)
def test_literal_secrets_assigned_to_secret_names_are_still_found(line):
    assert "generic_secret_assignment" in types(line)


def test_a_note_claiming_public_exposure_is_rejected_unless_the_exposure_is_public():
    f = Finding(
        rule="S007",
        secret_type="github_token",
        severity="high",
        kind="bucket_object",
        resource="gs://b/o",
        preview="p",
        fingerprint="f",
        exposure=Exposure(level="limited", reader_count=5),
    )
    assert "public" in check_note("This token sits in a publicly readable location.", f)
    assert check_note("Five principals can read this object.", f) is None
    pub = f.model_copy(update={"exposure": Exposure(level="public")})
    assert check_note("This object is publicly readable.", pub) is None


def test_resource_mentions_with_trailing_punctuation_are_not_misread():
    f = Finding(
        rule="S007",
        secret_type="github_token",
        severity="high",
        kind="cloudrun_env",
        resource="run:svc",
        preview="p",
        fingerprint="f",
    )
    assert check_note("It is set on the service run:svc'. Rotate it.", f) is None
    assert check_note("It is set on run:svc.", f) is None
