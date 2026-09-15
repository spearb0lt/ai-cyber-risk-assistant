"""Tests that assert behaviour, not that imports resolve.

The point of these is the brief's own claim: the ranking must not be driven by
CVSS. That is a property of the output over the real dataset, so it is checked
against the real dataset.
"""
from __future__ import annotations

import statistics

import pytest

from app.ingest.advisory import parse as parse_advisory
from app.ingest.loaders import load_pack
from app.reference import kev
from app.scoring.engine import index_intel, score_all
from app.scoring.grouping import group, top_risks
from app.scoring.weights import DEFAULTS, Weights


@pytest.fixture(scope="module")
def pack():
    return load_pack()


@pytest.fixture(scope="module")
def catalogue():
    return kev.load()


@pytest.fixture(scope="module")
def advisory(pack):
    return parse_advisory(pack.advisory)


@pytest.fixture(scope="module")
def scored(pack, catalogue, advisory):
    risks, unmatched = score_all(pack, catalogue, advisory)
    return risks, unmatched


def test_every_vulnerability_is_scored(pack, scored):
    risks, _ = scored
    assert len(risks) == len(pack.vulnerabilities) == 114


def test_the_briefs_own_example_holds(scored):
    """The brief's stated requirement, asserted literally.

    Its words: "A vulnerability sitting on an internal-only dev server with a
    CVSS of 10 should rank lower than a CVSS 8 on an internet-exposed payment
    gateway with an active ransomware campaign pointing at it."

    The comparison is deliberately against a *critical revenue* service rather
    than any exposed asset at all. A looser reading of this fails, and it fails
    for a defensible reason worth recording: CVE-2024-23897 on an internal dev
    build server is KEV confirmed and named in today's advisory as part of
    SilentForge's CI/CD campaign, so it outscores a synthetic-identifier
    finding on a well patched internet facing Jira box by about two points.
    That is the model working, not failing: corroborated exploitation of the
    exact technology under attack outweighs mere reachability. The README
    records the two point margin as a genuine sensitivity concern.
    """
    risks, _ = scored

    payment_gateway_under_campaign = [
        r
        for r in risks
        if r.internet_reachable
        and r.service is not None
        and r.service.revenue_impact.lower() == "critical"
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

    assert payment_gateway_under_campaign, "fixture should contain the brief's example"
    assert internal_non_prod_high_cvss, "fixture should contain internal high CVSS findings"

    worst_exposed = min(r.score for r in payment_gateway_under_campaign)
    best_internal = max(r.score for r in internal_non_prod_high_cvss)
    assert best_internal < worst_exposed, (
        f"an internal non production CVSS>=9 finding scored {best_internal}, which is not "
        f"below the weakest exposed critical revenue ransomware match at {worst_exposed}"
    )


def test_exposure_outranks_severity_all_else_equal(pack, catalogue, advisory):
    """A controlled comparison: the same CVE, exposed against not exposed.

    The brief's example mixes several variables at once. This isolates one:
    holding the vulnerability fixed, reachability must raise the score.
    """
    risks, _ = score_all(pack, catalogue, advisory)
    by_cve: dict[str, list] = {}
    for risk in risks:
        by_cve.setdefault(risk.vulnerability.cve, []).append(risk)

    compared = 0
    for cve, group_of in by_cve.items():
        exposed = [r for r in group_of if r.internet_reachable]
        internal = [r for r in group_of if not r.internet_reachable]
        if not exposed or not internal:
            continue
        compared += 1
        assert max(r.score for r in exposed) > min(r.score for r in internal), (
            f"{cve} did not score higher when internet facing"
        )
    assert compared, "fixture should contain a CVE on both exposed and internal assets"


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
        assert risk.factors["cvss"] <= DEFAULTS.cap_cvss
    assert DEFAULTS.cap_cvss / DEFAULTS.raw_total < 0.09


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


def test_scoring_is_deterministic(pack, catalogue, advisory):
    first, _ = score_all(pack, catalogue, advisory)
    second, _ = score_all(pack, catalogue, advisory)
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


# ---------------------------------------------------------------- the advisory


def test_advisory_is_parsed_not_merely_stored(advisory):
    """The brief requires ingesting the threat report, so it must be used."""
    assert len(advisory.campaigns) == 5
    actors = {c.actor for c in advisory.campaigns}
    assert {"CrimsonJackal", "RedMantis", "SilentForge", "IronVeil", "WinterViper"} == actors

    # The four part synthetic form must survive the identifier regex. Matching
    # CVE-SYN-2026-0004 as CVE-SYN-2026 would silently drop a campaign link.
    chain = advisory.campaign_for("CVE-SYN-2026-0004")
    assert chain is not None and chain.actor == "RedMantis"


def test_every_advisory_identifier_exists_in_the_estate(pack, advisory):
    present = {(v.cve or "").upper() for v in pack.vulnerabilities}
    assert set(advisory.by_identifier) <= present


def test_advisory_covers_a_cve_that_kev_cannot(scored):
    """WinterViper's CVE-SYN-2026-0011 can never appear in CISA KEV.

    Without the advisory there would be nothing at all to corroborate that it
    is being exploited, which is the exact blind spot the README calls out.
    """
    risks, _ = scored
    hits = [r for r in risks if r.vulnerability.cve == "CVE-SYN-2026-0011"]
    assert hits
    for risk in hits:
        assert risk.kev is None
        assert risk.advisory is not None
        assert risk.factors["campaign"] > 0


def test_advisory_contributes_score(pack, catalogue, advisory):
    """Turning the advisory off must lower the risks it names, and only those."""
    with_advisory, _ = score_all(pack, catalogue, advisory)
    without, _ = score_all(pack, catalogue, None)
    by_id = {r.vulnerability.vuln_id: r.score for r in without}

    named = [r for r in with_advisory if r.advisory]
    assert named
    for risk in named:
        assert risk.score >= by_id[risk.vulnerability.vuln_id]
    assert any(r.score > by_id[r.vulnerability.vuln_id] for r in named)

    for risk in (r for r in with_advisory if not r.advisory):
        assert risk.score == by_id[risk.vulnerability.vuln_id]


# ------------------------------------------------------------------- weights


def test_zeroing_a_factor_removes_it_from_both_sides(pack, catalogue, advisory):
    """A disabled factor must not drag every score toward zero."""
    no_cvss = Weights.from_dict({"cap_cvss": 0})
    risks, _ = score_all(pack, catalogue, advisory, no_cvss)
    assert all(r.factors["cvss"] == 0 for r in risks)
    # The denominator shrank with it, so the top score stays in range.
    assert max(r.score for r in risks) > 80
    assert no_cvss.raw_total == DEFAULTS.raw_total - DEFAULTS.cap_cvss


def test_weights_change_the_ranking(pack, catalogue, advisory):
    default_order = [r.vulnerability.vuln_id for r in score_all(pack, catalogue, advisory)[0][:10]]
    business_only = Weights.from_dict(
        {
            "cap_exploitability": 0,
            "cap_exposure": 0,
            "cap_campaign": 0,
            "cap_missing_controls": 0,
            "cap_cvss": 0,
        }
    )
    tuned_order = [
        r.vulnerability.vuln_id
        for r in score_all(pack, catalogue, advisory, business_only)[0][:10]
    ]
    assert default_order != tuned_order


def test_all_caps_zero_does_not_divide_by_zero(pack, catalogue, advisory):
    everything_off = Weights.from_dict(
        {f"cap_{name}": 0 for name in
         ("exploitability", "exposure", "campaign", "business_impact",
          "missing_controls", "cvss")}
    )
    assert everything_off.raw_total == 1.0
    risks, _ = score_all(pack, catalogue, advisory, everything_off)
    assert all(r.score == 0 for r in risks)


def test_weights_reject_junk_and_clamp_extremes():
    w = Weights.from_dict(
        {"cap_cvss": 10**9, "cap_exposure": "abc", "nonsense": 4,
         "cap_campaign": None, "top_n": 900}
    )
    assert w.cap_cvss == 100.0
    assert w.cap_exposure == DEFAULTS.cap_exposure
    assert w.cap_campaign == DEFAULTS.cap_campaign
    assert w.top_n == 25.0
    assert not hasattr(w, "nonsense")


def test_band_thresholds_are_tunable():
    strict = Weights.from_dict({"band_critical": 95})
    assert strict.band_for(93) == "High"
    assert DEFAULTS.band_for(93) == "Critical"


def test_changed_from_default_reports_only_real_changes():
    w = Weights.from_dict({"cap_cvss": 0, "cap_exposure": DEFAULTS.cap_exposure})
    changed = w.changed_from_default()
    assert set(changed) == {"cap_cvss"}
    assert changed["cap_cvss"] == (DEFAULTS.cap_cvss, 0.0)


def test_top_n_and_service_cap_are_honoured(scored):
    risks, _ = scored
    w = Weights.from_dict({"top_n": 3, "max_risks_per_service": 2})
    chosen = top_risks(group(risks, w), weights=w)
    assert len(chosen) == 3
    from collections import Counter

    counts = Counter(g.service_name for g in chosen)
    assert max(counts.values()) <= 2


def test_assets_with_no_findings_are_reported_not_assumed_clean(pack):
    """An asset with no vulnerability rows is invisible in a risk-only report.

    The pack has no scan date, so "clean" and "never scanned" are the same
    absence. Ingest must say so rather than let the reader infer safety.
    """
    from app.ingest import quality

    issues = quality.inspect(pack)
    silent = [i for i in issues if i.kind == "no_findings_recorded"]
    with_findings = {v.asset_id for v in pack.vulnerabilities}
    expected = [a for a in pack.assets.values() if a.asset_id not in with_findings]
    assert len(silent) == len(expected) == 19

    # An internet exposed or high criticality asset must be raised to a
    # warning, not filed as an informational note.
    warned = {i.subject for i in silent if i.severity == "warning"}
    for asset in expected:
        notable = asset.internet_exposed or asset.criticality.lower() in {"critical", "high"}
        assert (asset.asset_id in warned) == notable, (
            f"{asset.asset_id} severity does not match its exposure and criticality"
        )
    # The internet facing staging gateway is the clearest case.
    assert "A-1036" in warned
