"""The risk scoring model.

Deterministic. No language model touches a score, so the same data and the same
weights always produce the same ranking, and every point traces to a named
record. The model's job comes later and is confined to prose.

Six factors, each capped, summed to a raw total and normalised to 0 to 100:

    exploitability      is it actually being exploited, in the wild
    exposure            can an attacker reach it, and without credentials
    campaign            is a named actor using it against this sector now
    business impact     what breaks, who is liable, how fast must it return
    missing controls    what would have caught or contained it, and is absent
    CVSS                technical severity, as an anchor only

Every number lives in `weights.py` and can be overridden per request. CVSS
defaults to 10 of a raw 114, under 9 per cent, on purpose: the brief requires
a CVSS 10 on an internal development box to rank below a CVSS 8 on an internet
facing payment gateway under an active campaign, and a model that let severity
dominate could not do that.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ingest.advisory import Advisory, AdvisoryCampaign
from ..ingest.loaders import Asset, BusinessService, DataPack, ThreatIntel, Vulnerability
from ..reference.kev import KevCatalogue, KevEntry
from .weights import DEFAULTS, Weights

# Regions and sectors that describe TawasolPay: a Gulf fintech processing
# payments and identity. Intel outside both is real but less urgent here.
_OUR_REGIONS = {"middle east", "global"}
_OUR_SECTORS = {
    "financial services",
    "fintech",
    "technology",
    "payments",
    "banking",
    "retail and saas",
}


@dataclass(frozen=True)
class Evidence:
    """One scored observation, with the record it came from."""

    factor: str
    points: float
    detail: str
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "factor": self.factor,
            "points": round(self.points, 1),
            "detail": self.detail,
            "source": self.source,
        }


@dataclass
class ScoredRisk:
    vulnerability: Vulnerability
    asset: Asset
    service: BusinessService | None
    kev: KevEntry | None
    intel: list[ThreatIntel]
    primary_intel: ThreatIntel | None
    advisory: AdvisoryCampaign | None
    factors: dict[str, float]
    evidence: list[Evidence]
    score: float
    weights: Weights = field(default=DEFAULTS)
    warnings: list[str] = field(default_factory=list)
    hint: Any = None  # RemediationHint, attached by the briefing layer

    @property
    def band(self) -> str:
        return self.weights.band_for(self.score)

    @property
    def internet_reachable(self) -> bool:
        return self.vulnerability.internet_facing or self.asset.internet_exposed

    @property
    def service_name(self) -> str:
        return self.asset.business_service

    @property
    def campaign_name(self) -> str:
        if self.primary_intel:
            return self.primary_intel.campaign_name
        return self.advisory.campaign if self.advisory else ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "vuln_id": self.vulnerability.vuln_id,
            "cve": self.vulnerability.cve,
            "vulnerability_name": self.vulnerability.vulnerability_name,
            "cvss": self.vulnerability.cvss,
            "severity": self.vulnerability.severity,
            "days_open": self.vulnerability.days_open,
            "asset_id": self.asset.asset_id,
            "asset_name": self.asset.asset_name,
            "environment": self.asset.environment,
            "business_service": self.service_name,
            "score": round(self.score, 1),
            "band": self.band,
            "factors": {k: round(v, 1) for k, v in self.factors.items()},
            "evidence": [e.as_dict() for e in self.evidence],
            "warnings": list(self.warnings),
            "in_advisory": self.advisory is not None,
        }


def _intel_relevance(record: ThreatIntel) -> float:
    """How much a campaign record applies to this organisation.

    A campaign against a different sector in a different region is still a
    fact, but it is not this company's fact. Downweighting rather than
    discarding keeps it visible without letting it drive the ranking.
    """
    region = (record.target_region or "").strip().lower()
    sector = (record.target_sector or "").strip().lower()
    region_match = region in _OUR_REGIONS
    sector_match = any(token in sector for token in _OUR_SECTORS) or sector in _OUR_SECTORS
    if region_match and sector_match:
        return 1.0
    if region_match or sector_match:
        return 0.6
    return 0.3


def _maturity_points(maturity: str, w: Weights) -> float:
    key = (maturity or "").strip().lower()
    return {
        "weaponized": w.maturity_weaponized,
        "weaponised": w.maturity_weaponized,
        "active exploitation": w.maturity_active,
        "commodity exploit": w.maturity_commodity,
        "proof of concept": w.maturity_proof_of_concept,
        "social engineering": w.maturity_social,
        "not applicable": 0.0,
    }.get(key, 0.0)


def score_vulnerability(
    vuln: Vulnerability,
    pack: DataPack,
    kev_catalogue: KevCatalogue,
    intel_by_cve: dict[str, list[ThreatIntel]],
    advisory: Advisory | None = None,
    weights: Weights = DEFAULTS,
) -> ScoredRisk | None:
    asset = pack.asset_for(vuln)
    if asset is None:
        return None
    w = weights
    service = pack.service_for(asset)
    evidence: list[Evidence] = []
    warnings: list[str] = []

    kev_entry = kev_catalogue.get(vuln.cve)
    matched_intel = intel_by_cve.get(vuln.cve.strip().upper(), [])
    advisory_hit = advisory.campaign_for(vuln.cve) if advisory else None

    def add(factor: str, points: float, detail: str, source: str) -> float:
        """Record a contribution, skipping it when its factor is switched off."""
        if w.cap_for(factor) <= 0 or points <= 0:
            return 0.0
        evidence.append(Evidence(factor, points, detail, source))
        return points

    # ---------------------------------------------------------------- exploit
    exploit = 0.0
    if kev_entry:
        exploit += add(
            "exploitability",
            w.kev_listed,
            f"{vuln.cve} is in the CISA Known Exploited Vulnerabilities catalogue, "
            f"added {kev_entry.date_added}. Confirmed exploitation in the wild.",
            "CISA KEV",
        )
        if kev_entry.known_ransomware:
            exploit += add(
                "exploitability",
                w.kev_ransomware,
                "CISA records this CVE as used in known ransomware campaigns.",
                "CISA KEV",
            )
    elif vuln.is_synthetic_id:
        warnings.append(
            f"{vuln.cve} is not a public CVE identifier, so it cannot be checked "
            "against CISA KEV. Its exploitation status rests on the vulnerability "
            "feed's own exploit_available flag"
            + (", and on the MDR advisory naming it." if advisory_hit else ".")
        )
    else:
        warnings.append(
            f"{vuln.cve} is not in the KEV snapshot in use. That means it is not "
            "confirmed as exploited, which is not the same as being safe."
        )

    if vuln.exploit_available:
        exploit += add(
            "exploitability",
            w.exploit_available,
            "A working exploit is recorded as publicly available.",
            "vulnerabilities.csv",
        )

    if matched_intel:
        best = max(matched_intel, key=lambda i: _maturity_points(i.exploit_maturity, w))
        points = _maturity_points(best.exploit_maturity, w)
        if points:
            exploit += add(
                "exploitability",
                points,
                f"Threat intel rates the exploit as '{best.exploit_maturity}'.",
                f"threat_intelligence.csv {best.intel_id}",
            )
    exploit = min(exploit, w.cap_exploitability)

    # --------------------------------------------------------------- exposure
    exposure = 0.0
    reachable = vuln.internet_facing or asset.internet_exposed
    if reachable:
        exposure += add(
            "exposure",
            w.internet_reachable,
            f"{asset.asset_name} is reachable from the internet, so an attacker "
            "needs no prior foothold.",
            "assets.csv / vulnerabilities.csv",
        )
        if vuln.internet_facing and asset.internet_exposed:
            exposure += add(
                "exposure",
                w.exposure_sources_agree,
                "Both the asset inventory and the vulnerability feed agree the "
                "exposure is internet facing.",
                "assets.csv / vulnerabilities.csv",
            )
        elif vuln.internet_facing != asset.internet_exposed:
            warnings.append(
                f"The asset inventory and the vulnerability feed disagree about "
                f"exposure for {vuln.vuln_id}. Scored as internet facing, the more "
                "severe reading."
            )
    elif w.cap_exposure > 0:
        evidence.append(
            Evidence(
                "exposure",
                0.0,
                f"{asset.asset_name} is internal only, so an attacker needs an "
                "existing foothold to reach it.",
                "assets.csv",
            )
        )

    if not vuln.auth_required:
        exposure += add(
            "exposure",
            w.no_auth_required,
            "Exploitation requires no authentication.",
            "vulnerabilities.csv",
        )
    exposure = min(exposure, w.cap_exposure)

    # --------------------------------------------------------------- campaign
    campaign = 0.0
    primary: ThreatIntel | None = None
    if matched_intel:
        scored_intel = []
        for record in matched_intel:
            relevance = _intel_relevance(record)
            points = w.campaign_matched
            if (record.target_region or "").strip().lower() == "middle east":
                points += w.campaign_targets_our_region
            if record.ransomware_association:
                points += w.campaign_ransomware
            points += {
                "high": w.campaign_confidence_high,
                "medium": w.campaign_confidence_medium,
            }.get((record.confidence or "").lower(), 0.0)
            scored_intel.append((points * relevance, relevance, record))
        scored_intel.sort(key=lambda item: -item[0])
        points, relevance, primary = scored_intel[0]

        descriptor = (
            f"Campaign '{primary.campaign_name}' by {primary.threat_actor} is active "
            f"against {primary.target_sector} in {primary.target_region}"
        )
        if primary.ransomware_association:
            descriptor += ", with ransomware deployment observed"
        descriptor += (
            f". Confidence {primary.confidence.lower()}, last seen {primary.active_last_seen}."
        )
        if relevance < 1.0:
            descriptor += (
                f" Scored at {int(relevance * 100)} per cent weight because the "
                "campaign's target profile only partly matches TawasolPay."
            )
        campaign += add(
            "campaign", points, descriptor, f"threat_intelligence.csv {primary.intel_id}"
        )

    # The advisory is separate evidence from the feed: it is dated, addressed
    # to this company, and reflects an analyst's judgement about what matters
    # here. A CVE named in it counts even when the feed says nothing.
    if advisory_hit:
        campaign += add(
            "campaign",
            w.advisory_named,
            f"Named in this morning's MDR advisory as part of the "
            f"{advisory_hit.actor} '{advisory_hit.campaign}' exploit chain "
            f"({advisory_hit.exploit_chain}).",
            "synthetic_threat_report.md",
        )
        if advisory_hit.is_ransomware:
            campaign += add(
                "campaign",
                w.advisory_ransomware,
                f"The advisory records ransomware in this chain: {advisory_hit.ransomware}.",
                "synthetic_threat_report.md",
            )
    campaign = min(campaign, w.cap_campaign)

    # --------------------------------------------------------------- business
    business = 0.0
    if service is not None:
        parts: list[str] = []
        revenue = {
            "critical": w.revenue_critical,
            "high": w.revenue_high,
            "medium": w.revenue_medium,
        }.get((service.revenue_impact or "").lower(), 0.0)
        business += revenue
        parts.append(f"revenue impact {service.revenue_impact.lower()}")

        if service.customer_facing:
            business += w.customer_facing
            parts.append("customer facing")

        frameworks = service.compliance_frameworks
        joined = " ".join(frameworks).upper()
        if "PCI" in joined:
            business += w.compliance_pci
        elif "GDPR" in joined or "PDPL" in joined:
            business += w.compliance_privacy
        elif "SOC" in joined or "ISO" in joined:
            business += w.compliance_other
        if frameworks and frameworks != ["None"]:
            parts.append(f"in scope for {', '.join(frameworks)}")

        if service.rto_hours <= 2:
            business += w.rto_under_2h
            parts.append(f"{service.rto_hours}h recovery objective")
        elif service.rto_hours <= 8:
            business += w.rto_under_8h
            parts.append(f"{service.rto_hours}h recovery objective")

        dependents = pack.dependents.get(service.business_service, [])
        if dependents:
            business += min(w.dependency_each * len(dependents), w.dependency_cap)
            parts.append(
                f"{len(dependents)} other service{'s' if len(dependents) != 1 else ''} "
                f"depend on it ({', '.join(dependents[:3])})"
            )

        if business > 0 and w.cap_business_impact > 0:
            evidence.append(
                Evidence(
                    "business_impact",
                    business,
                    f"Supports '{service.business_service}', owned by "
                    f"{service.business_owner}: " + "; ".join(parts) + ".",
                    "business_services.csv",
                )
            )
    else:
        warnings.append(
            f"No business service record for '{asset.business_service}', so business "
            "impact was scored at the floor and this risk may be understated."
        )

    criticality = {
        "critical": w.asset_criticality_critical,
        "high": w.asset_criticality_high,
    }.get((asset.criticality or "").lower(), 0.0)
    if criticality:
        business += add(
            "business_impact",
            criticality,
            f"The asset itself is classified {asset.criticality.lower()} criticality, "
            f"holding {asset.data_classification.lower()}.",
            "assets.csv",
        )
    business = min(business, w.cap_business_impact)

    # ------------------------------------------------------- missing controls
    controls = 0.0
    if not asset.edr_installed:
        controls += add(
            "missing_controls",
            w.no_edr,
            f"No EDR agent on {asset.asset_name}, so post exploitation activity "
            "would likely go undetected.",
            "assets.csv",
        )
    if not vuln.patch_available:
        controls += add(
            "missing_controls",
            w.no_patch_available,
            "No vendor patch is available, so mitigation has to be compensating "
            "rather than corrective.",
            "vulnerabilities.csv",
        )
    if vuln.days_open > 90:
        controls += add(
            "missing_controls",
            w.open_over_90_days,
            f"Open for {vuln.days_open} days, far past any reasonable remediation "
            "window for this severity.",
            "vulnerabilities.csv",
        )
    elif vuln.days_open > 30:
        controls += add(
            "missing_controls",
            w.open_over_30_days,
            f"Open for {vuln.days_open} days.",
            "vulnerabilities.csv",
        )
    if asset.is_stale:
        controls += add(
            "missing_controls",
            w.stale_asset,
            f"Last seen {asset.last_seen_days} days ago, so its recorded state may "
            "no longer reflect reality.",
            "assets.csv",
        )
    if asset.is_unowned:
        controls += add(
            "missing_controls",
            w.unowned_asset,
            "No owning team is assigned, so there is no one accountable for fixing it.",
            "assets.csv",
        )
    controls = min(controls, w.cap_missing_controls)

    # ------------------------------------------------------------------- cvss
    cvss_points = 0.0
    if w.cap_cvss > 0:
        cvss_points = min(max(vuln.cvss, 0.0), 10.0) * (w.cap_cvss / 10.0)
        share = w.cap_cvss / w.raw_total * 100
        evidence.append(
            Evidence(
                "cvss",
                cvss_points,
                f"CVSS {vuln.cvss:.1f} ({vuln.severity.lower()}). Contributes at most "
                f"{w.cap_cvss:.0f} of {w.raw_total:.0f} raw points, {share:.0f} per cent "
                "of the total, so severity alone cannot drive the ranking.",
                "vulnerabilities.csv",
            )
        )

    factors = {
        "exploitability": exploit,
        "exposure": exposure,
        "campaign": campaign,
        "business_impact": business,
        "missing_controls": controls,
        "cvss": cvss_points,
    }
    total = sum(factors.values()) / w.raw_total * 100.0

    return ScoredRisk(
        vulnerability=vuln,
        asset=asset,
        service=service,
        kev=kev_entry,
        intel=matched_intel,
        primary_intel=primary,
        advisory=advisory_hit,
        factors=factors,
        evidence=evidence,
        score=round(min(total, 100.0), 1),
        weights=w,
        warnings=warnings,
    )


def index_intel(pack: DataPack) -> tuple[dict[str, list[ThreatIntel]], list[ThreatIntel]]:
    """Split the intel feed into records that match this estate and noise.

    The pack contains campaigns with no presence here at all. They must not
    influence any score, and they must still be reportable, because "we checked
    and it does not affect us" is a real answer a board wants.
    """
    present = {(v.cve or "").strip().upper() for v in pack.vulnerabilities}
    matched: dict[str, list[ThreatIntel]] = {}
    unmatched: list[ThreatIntel] = []
    for record in pack.intel:
        key = (record.matched_cve_or_control or "").strip().upper()
        if key and key in present:
            matched.setdefault(key, []).append(record)
        else:
            unmatched.append(record)
    return matched, unmatched


def score_all(
    pack: DataPack,
    kev_catalogue: KevCatalogue,
    advisory: Advisory | None = None,
    weights: Weights = DEFAULTS,
) -> tuple[list[ScoredRisk], list[ThreatIntel]]:
    """Score every open vulnerability, highest first."""
    intel_by_cve, unmatched = index_intel(pack)
    scored = [
        risk
        for risk in (
            score_vulnerability(vuln, pack, kev_catalogue, intel_by_cve, advisory, weights)
            for vuln in pack.vulnerabilities
        )
        if risk is not None
    ]
    # Sort by score, then by vuln id so ties are stable and reproducible.
    scored.sort(key=lambda r: (-r.score, r.vulnerability.vuln_id))
    return scored, unmatched
