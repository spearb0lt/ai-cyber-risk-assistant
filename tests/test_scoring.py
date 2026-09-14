"""Tests that assert behaviour, not that imports resolve.

The point of these is the brief's own claim: the ranking must not be driven by
CVSS. That is a property of the output over the real dataset, so it is checked
against the real dataset.
"""
from __future__ import annotations

import statistics

import pytest

from app.ingest.loaders import load_pack
from app.reference import kev
from app.scoring.engine import RAW_TOTAL, index_intel, score_all
from app.scoring.grouping import group, top_risks


@pytest.fixture(scope="module")
def pack():
    return load_pack()


@pytest.fixture(scope="module")
def catalogue():
    return kev.load()


@pytest.fixture(scope="module")
def scored(pack, catalogue):
    risks, unmatched = score_all(pack, catalogue)
    return risks, unmatched


def test_every_vulnerability_is_scored(pack, scored):
    risks, _ = scored
    assert len(risks) == len(pack.vulnerabilities) == 114


def test_the_briefs_own_example_holds(scored):
    """A high CVSS finding on an internal, non production box must rank below
    an internet facing finding under an active ransomware campaign.

    This is the requirement the brief states in its own words, so it is worth
    asserting directly rather than inferring from the weights.
    """
    risks, _ = scored

    exposed_under_campaign = [
        r
        for r in risks
        if r.internet_reachable
        and r.primary_intel is not None
        and r.primary_intel.ransomware_association
    ]
    internal_non_prod_high_cvss = [
        r
        for r in risks
        if not r.internet_reachable
        and not r.asset.is_production
        and r.vulnerability.cvss >= 9.0
    ]

    assert exposed_under_campaign, "fixture should contain exposed campaign matches"
    assert internal_non_prod_high_cvss, "fixture should contain internal high CVSS findings"

    worst_exposed = min(r.score for r in exposed_under_campaign)
    best_internal = max(r.score for r in internal_non_prod_high_cvss)
    assert best_internal < worst_exposed, (
        f"an internal non production CVSS>=9 finding scored {best_internal}, which is not "
        f"below the weakest internet facing ransomware campaign match at {worst_exposed}"
    )


def test_ranking_is_not_cvss_ordering(scored):
    risks, _ = scored
    by_score = [r.vulnerability.vuln_id for r in risks[:5]]
    by_cvss = [
        r.vulnerability.vuln_id
        for r in sorted(risks, key=lambda x: (-x.vulnerability.cvss, x.vulnerability.vuln_id))[:5]
    ]
    assert by_score != by_cvss, "the ranking reproduced a plain CVSS ordering"

    # A CVSS 10 that this model rates low is the clearest demonstration.
    cvss_tens = [r for r in risks if r.vulnerability.cvss >= 10.0]
    assert cvss_tens
    assert min(r.score for r in cvss_tens) < 50, (
        "no CVSS 10 finding was deprioritised, so context is not outweighing severity"
    )


def test_score_correlates_with_cvss_but_is_not_governed_by_it(scored):
    risks, _ = scored
    scores = [r.score for r in risks]
    cvss = [r.vulnerability.cvss for r in risks]
    mean_s, mean_c = statistics.mean(scores), statistics.mean(cvss)
    covariance = sum((s - mean_s) * (c - mean_c) for s, c in zip(scores, cvss))
    denominator = (
        sum((s - mean_s) ** 2 for s in scores) * sum((c - mean_c) ** 2 for c in cvss)
    ) ** 0.5
    r = covariance / denominator
    # Some correlation is correct: CVSS is real signal. Domination is not.
    assert 0.2 < r < 0.7, f"pearson(score, cvss) = {r:.3f} is outside the intended band"


def test_cvss_cannot_exceed_its_share_of_the_total(scored):
    risks, _ = scored
    for risk in risks:
        assert risk.factors["cvss"] <= 10.0
    assert 10 / RAW_TOTAL < 0.09


def test_unmatched_intel_contributes_nothing(pack, catalogue, scored):
    """The 16 noise records must not touch any score."""
    risks, unmatched = scored
    assert len(unmatched) == 16

    matched_by_cve, _ = index_intel(pack)
    unmatched_refs = {r.matched_cve_or_control.strip().upper() for r in unmatched}

    # No scored risk may carry an intel record from the unmatched set.
    for risk in risks:
        for record in risk.intel:
            assert record not in unmatched
    # And none of the unmatched references may appear as a scoring key.
    assert not (unmatched_refs & set(matched_by_cve))


def test_campaign_points_only_come_from_matched_intel(scored):
    risks, _ = scored
    for risk in risks:
        if not risk.intel:
            assert risk.factors["campaign"] == 0, (
                f"{risk.vulnerability.vuln_id} scored campaign points with no matched intel"
            )


def test_kev_join_is_real(scored):
    """CitrixBleed must resolve against the live KEV catalogue."""
    risks, _ = scored
    citrix = [r for r in risks if r.vulnerability.cve == "CVE-2023-4966"]
    assert citrix
    for risk in citrix:
        assert risk.kev is not None
        assert risk.kev.known_ransomware is True
        assert risk.kev.date_added


def test_synthetic_ids_are_flagged_as_unverifiable_not_as_safe(scored):
    """Absence from KEV means 'not confirmed', which is not 'not exploited'.

    This is the failure mode the brief asks about, so the system has to say
    which of the two it means.
    """
    risks, _ = scored
    synthetic = [r for r in risks if r.vulnerability.is_synthetic_id]
    assert synthetic
    for risk in synthetic:
        assert risk.kev is None
        assert any("cannot be checked against CISA KEV" in w for w in risk.warnings), (
            f"{risk.vulnerability.vuln_id} carries no unverifiable-identifier caveat"
        )


def test_exposure_conflict_is_reported_not_hidden(scored):
    risks, _ = scored
    conflicted = [r for r in risks if any("disagree about exposure" in w for w in r.warnings)]
    assert conflicted, "the known exposure contradiction was not surfaced"


def test_scoring_is_deterministic(pack, catalogue):
    first, _ = score_all(pack, catalogue)
    second, _ = score_all(pack, catalogue)
    assert [(r.vulnerability.vuln_id, r.score) for r in first] == [
        (r.vulnerability.vuln_id, r.score) for r in second
    ]


def test_grouping_collapses_one_intrusion_into_one_risk(scored):
    """The Fortinet chain spans two CVEs and three appliances but is one risk."""
    risks, _ = scored
    top = top_risks(group(risks), limit=5, max_per_service=1)
    assert len(top) == 5

    fortinet = [g for g in top if "Gateway Breaker" in g.title]
    assert len(fortinet) == 1, "the Fortinet exploit chain did not collapse into one entry"
    entry = fortinet[0]
    assert len(entry.assets) >= 2
    assert {"CVE-2024-21762", "CVE-2024-55591"} <= set(entry.cves)


def test_diversity_cap_prevents_one_service_dominating(scored):
    risks, _ = scored
    top = top_risks(group(risks), limit=5, max_per_service=1)
    services = [g.service_name for g in top]
    assert len(set(services)) == len(services), f"a service repeated in the top 5: {services}"


def test_every_top_risk_carries_the_four_required_facts(scored):
    """The brief requires asset, vulnerability, intel, service and a rationale."""
    risks, _ = scored
    for entry in top_risks(group(risks), limit=5, max_per_service=1):
        payload = entry.as_dict()
        assert payload["assets"], "no asset"
        assert payload["vulnerabilities"], "no vulnerability"
        assert payload["business_service"], "no business service"
        # Intel may legitimately be absent; the field must still exist.
        assert "threat_intel" in payload
        assert payload["evidence"], "no scoring evidence"


def test_kev_cves_are_deduplicated(scored):
    risks, _ = scored
    for entry in group(risks):
        assert len(entry.kev_cves) == len(set(entry.kev_cves))
