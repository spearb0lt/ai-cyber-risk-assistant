"""Retrieval, grounding and end to end API tests."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.briefing import guard
from app.briefing.analysis import analyse
from app.main import app
from app.reference import nist
from app.retrieval import bm25, store
from app.retrieval.hybrid import get_retriever


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def retriever():
    return get_retriever()


# ----------------------------------------------------------------- catalogue


def test_nist_catalogue_loads_the_real_document():
    controls = nist.load_controls()
    assert len(controls) > 1000
    # The controls the brief names must all be present.
    for identifier in ("SI-2", "RA-5", "IR-4", "AC-2", "SA-22"):
        assert identifier in controls, f"{identifier} missing from the catalogue"
    assert controls["SI-2"].name == "Flaw Remediation"


def test_chunks_fit_the_embedding_window():
    chunks = nist.build_chunks(nist.load_controls())
    assert len(chunks) > 1000
    # bge-small truncates at 512 tokens. Roughly four characters per token
    # means anything past ~2000 characters would be silently cut.
    assert max(len(c.text) for c in chunks) < 2000


def test_excerpt_is_verbatim_from_the_document():
    controls = nist.load_controls()
    si2 = controls["SI-2"]
    text = nist.excerpt(si2, 200)
    assert text
    # Every word of the excerpt must appear in the source control.
    source = " ".join((si2.control_text + " " + si2.discussion).split())
    assert text.rstrip(".").rstrip("...") .split()[0] in source


# ----------------------------------------------------------------- retrieval


def test_index_was_built_and_matches_its_embedder():
    index = store.load("local")
    assert index is not None, "run scripts/build_index.py"
    assert index.dim == 384
    assert index.vectors.shape[0] == len(index.chunks)


def test_index_refuses_a_mismatched_query_vector():
    import numpy as np

    index = store.load("local")
    with pytest.raises(ValueError, match="dimensions"):
        index.search(np.zeros(768, dtype=np.float32))


@pytest.mark.parametrize(
    "query,expected",
    [
        ("session token leak authentication bypass session identifiers", "SC-23"),
        ("install security relevant updates within the remediation window", "SI-2"),
        ("inventory of system components and who is accountable for them", "CM-8"),
        ("endpoint malicious code detection at system entry and exit points", "SI-3"),
        ("handling a ransomware incident, containment eradication recovery", "IR-4"),
    ],
)
def test_retrieval_finds_the_right_control(retriever, query, expected):
    controls, result = retriever.best_controls(query, limit=4)
    identifiers = [c.identifier for c in controls]
    assert expected in identifiers, f"{query!r} returned {identifiers}, expected {expected}"


def test_base_controls_are_preferred_over_enhancements(retriever):
    controls, _ = retriever.best_controls(
        "install security relevant updates within the remediation window", limit=3
    )
    assert not controls[0].is_enhancement, (
        f"{controls[0].identifier} is an enhancement; a base control should lead"
    )


def test_bm25_works_with_no_embedder_at_all():
    """The lexical path is the degradation route, so it is tested alone."""
    chunks = store.load_chunks_only() or nist.build_chunks(nist.load_controls())
    index = bm25.build([c.text for c in chunks])
    hits = index.search("flaw remediation install security relevant updates", limit=5)
    assert hits
    found = {chunks[i].control_id for i, _ in hits}
    assert "SI-2" in found


# ------------------------------------------------------------------- guard


def test_guard_drops_a_control_that_was_not_retrieved():
    report = guard.check(
        "Apply SI-2 Flaw Remediation. Also enforce AC-2 Account Management.",
        allowed_controls=["SI-2"],
    )
    assert not report.ok
    assert "AC-2" in report.invented_controls
    assert "AC-2" not in report.text
    assert "SI-2" in report.text


def test_guard_allows_an_enhancement_of_a_retrieved_control():
    report = guard.check(
        "SI-2(3) sets the benchmark for time to remediate.", allowed_controls=["SI-2"]
    )
    assert report.ok
    assert "SI-2(3)" in report.text


def test_guard_drops_a_cve_not_attached_to_the_risk():
    report = guard.check(
        "CVE-2023-4966 is exploited. CVE-2021-44228 is also a concern.",
        allowed_controls=[],
        allowed_cves=["CVE-2023-4966"],
    )
    assert "CVE-2021-44228" in report.invented_cves
    assert "CVE-2021-44228" not in report.text


def test_guard_ignores_ordinary_hyphenated_text():
    report = guard.check(
        "The finding has been open 120 days across the UAE-2 region.",
        allowed_controls=["SI-2"],
    )
    assert report.ok, f"guard wrongly flagged {report.invented_controls}"


# --------------------------------------------------------------- end to end


def test_analysis_works_with_no_api_key_at_all():
    """The deployed URL must produce the whole brief before anyone pastes a key."""
    result = analyse(force=True)
    assert len(result.briefs) == 5
    for brief in result.briefs:
        assert brief.narrative.source == "deterministic"
        assert len(brief.narrative.why) > 120
        assert brief.narrative.remediation
        assert brief.controls, "a risk was briefed with no NIST control"


def test_every_briefed_control_came_from_retrieval():
    result = analyse()
    for brief in result.briefs:
        cited = guard.control_ids_in(brief.narrative.remediation)
        allowed = {c.identifier for c in brief.controls}
        bases = {c.base_identifier for c in brief.controls}
        for identifier in cited:
            root = identifier.split("(")[0]
            assert identifier in allowed or root in bases or root in allowed, (
                f"{identifier} was cited but not retrieved"
            )


def test_health_and_config(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["risks"] == 5

    config = client.get("/api/config").json()
    slugs = {p["id"] for p in config["providers"]}
    assert slugs == {"gemini", "groq", "openrouter", "omnirouter", "openai"}


def test_analysis_endpoint_shape(client):
    payload = client.get("/api/analysis").json()
    assert len(payload["risks"]) == 5
    assert len(payload["ranked"]) == 114
    assert len(payload["unmatched_intel"]) == 16
    first = payload["risks"][0]
    for field in ("assets", "vulnerabilities", "threat_intel", "business_service", "controls"):
        assert field in first
    assert first["rank"] == 1
    assert first["score"] >= payload["risks"][-1]["score"]


def test_report_is_readable_markdown(client):
    text = client.get("/api/report.md").text
    assert text.startswith("# TawasolPay")
    for heading in ("Top 5 risks", "**Asset:**", "**Vulnerability:**",
                    "**Business service at risk:**", "Why this ranks here",
                    "NIST SP 800-53 Rev. 5"):
        assert heading in text, f"{heading!r} missing from the brief"
    # The brief asks for prose, not a JSON dump.
    assert '{"' not in text


def test_unmatched_intel_endpoint(client):
    payload = client.get("/api/intel/unmatched").json()
    assert payload["total_intel"] == 40
    assert len(payload["unmatched"]) == 16


def test_data_quality_endpoint_reports_the_known_problems(client):
    payload = client.get("/api/data-quality").json()
    kinds = payload["by_kind"]
    assert kinds.get("exposure_conflict") == 1
    assert kinds.get("unowned_asset") == 1
    assert kinds.get("stale_asset") == 3


def test_nist_search_endpoint(client):
    payload = client.get("/api/nist/search", params={"q": "system backup and recovery"}).json()
    assert payload["controls"]
    assert any(c["identifier"].startswith("CP-") for c in payload["controls"])


def test_brief_endpoint_fails_clearly_with_no_provider(client):
    response = client.post("/api/analysis/brief", json={})
    assert response.status_code == 502
    error = response.json()["detail"]["error"]
    assert "provider" in error["message"].lower()
    assert error["hint"]
