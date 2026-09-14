"""The risk scoring model.

Deliberately deterministic. No LLM touches a score, so the same data always
produces the same ranking and every point is traceable to a named record. The
LLM's job comes later and is confined to prose.

Six factors, each capped, summed to a raw total that is normalised to 0-100:

    exploitability      30   is it actually being exploited, in the wild
    exposure            22   can an attacker reach it, and without credentials
    campaign            20   is a named actor using it against this sector now
    business impact     20   what breaks, who is liable, how fast must it return
    missing controls    12   what would have caught or contained it, and is absent
    CVSS                10   technical severity, as an anchor only

CVSS is capped at 10 of a possible 114 on purpose. The brief requires that a
CVSS 10 on an internal development box rank below a CVSS 8 on an internet
facing payment gateway under an active campaign, and a model that let severity
dominate could not do that. Everything above CVSS in that list is context the
score cannot be reached without.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ingest.loaders import Asset, BusinessService, DataPack, ThreatIntel, Vulnerability
from ..reference.kev import KevCatalogue, KevEntry

# Factor ceilings.
CAP_EXPLOIT = 30
CAP_EXPOSURE = 22
CAP_CAMPAIGN = 20
CAP_BUSINESS = 20
CAP_CONTROLS = 12
CAP_CVSS = 10
RAW_TOTAL = CAP_EXPLOIT + CAP_EXPOSURE + CAP_CAMPAIGN + CAP_BUSINESS + CAP_CONTROLS + CAP_CVSS

# How mature an exploit the intel reports.
_MATURITY_POINTS = {
    "weaponized": 6,
    "weaponised": 6,
    "active exploitation": 6,
    "commodity exploit": 4,
    "proof of concept": 2,
    "social engineering": 1,
    "not applicable": 0,
}

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

BANDS = ((70.0, "Critical"), (55.0, "High"), (40.0, "Medium"), (0.0, "Low"))


@dataclass(frozen=True)
class Evidence:
    """One scored observation, with the record it came from."""

    factor: str
    points: float
    detail: str
    source: str  # which file or catalogue asserted this

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
    factors: dict[str, float]
    evidence: list[Evidence]
    score: float
    warnings: list[str] = field(default_factory=list)

    @property
    def band(self) -> str:
        for threshold, name in BANDS:
            if self.score >= threshold:
                return name
        return "Low"

    @property
    def internet_reachable(self) -> bool:
        return self.vulnerability.internet_facing or self.asset.internet_exposed

    @property
    def service_name(self) -> str:
        return self.asset.business_service

    @property
    def campaign_name(self) -> str:
        return self.primary_intel.campaign_name if self.primary_intel else ""

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


def score_vulnerability(
    vuln: Vulnerability,
    pack: DataPack,
    kev_catalogue: KevCatalogue,
    intel_by_cve: dict[str, list[ThreatIntel]],
) -> ScoredRisk | None:
    asset = pack.asset_for(vuln)
    if asset is None:
        return None
    service = pack.service_for(asset)
    evidence: list[Evidence] = []
    warnings: list[str] = []

    kev_entry = kev_catalogue.get(vuln.cve)
    matched_intel = intel_by_cve.get(vuln.cve.strip().upper(), [])

    # ---------------------------------------------------------------- exploit
    exploit = 0.0
    if kev_entry:
        exploit += 14
        evidence.append(
            Evidence(
                "exploitability",
                14,
                f"{vuln.cve} is in the CISA Known Exploited Vulnerabilities catalogue, "
                f"added {kev_entry.date_added}. Confirmed exploitation in the wild.",
                "CISA KEV",
            )
        )
        if kev_entry.known_ransomware:
            exploit += 8
            evidence.append(
                Evidence(
                    "exploitability",
                    8,
                    "CISA records this CVE as used in known ransomware campaigns.",
                    "CISA KEV",
                )
            )
    elif vuln.is_synthetic_id:
        # Absence from KEV is only meaningful for a real CVE id.
        warnings.append(
            f"{vuln.cve} is not a public CVE identifier, so it cannot be checked "
            "against CISA KEV. Its exploitation status rests on the vulnerability "
            "feed's own exploit_available flag."
        )
    else:
        warnings.append(
            f"{vuln.cve} is not in the KEV snapshot in use. That means it is not "
            "confirmed as exploited, which is not the same as being safe."
        )

    if vuln.exploit_available:
        exploit += 6
        evidence.append(
            Evidence(
                "exploitability",
                6,
                "A working exploit is recorded as publicly available.",
                "vulnerabilities.csv",
            )
        )

    if matched_intel:
        maturity = max(
            (_MATURITY_POINTS.get((i.exploit_maturity or "").strip().lower(), 0) for i in matched_intel),
            default=0,
        )
        if maturity:
            best = max(
                matched_intel,
                key=lambda i: _MATURITY_POINTS.get((i.exploit_maturity or "").strip().lower(), 0),
            )
            exploit += maturity
            evidence.append(
                Evidence(
                    "exploitability",
                    maturity,
                    f"Threat intel rates the exploit as '{best.exploit_maturity}'.",
                    f"threat_intelligence.csv {best.intel_id}",
                )
            )
    exploit = min(exploit, CAP_EXPLOIT)

    # --------------------------------------------------------------- exposure
    exposure = 0.0
    reachable = vuln.internet_facing or asset.internet_exposed
    if reachable:
        exposure += 14
        evidence.append(
            Evidence(
                "exposure",
                14,
                f"{asset.asset_name} is reachable from the internet, so an attacker "
                "needs no prior foothold.",
                "assets.csv / vulnerabilities.csv",
            )
        )
        if vuln.internet_facing and asset.internet_exposed:
            exposure += 3
            evidence.append(
                Evidence(
                    "exposure",
                    3,
                    "Both the asset inventory and the vulnerability feed agree the "
                    "exposure is internet facing.",
                    "assets.csv / vulnerabilities.csv",
                )
            )
        elif vuln.internet_facing != asset.internet_exposed:
            warnings.append(
                f"The asset inventory and the vulnerability feed disagree about "
                f"exposure for {vuln.vuln_id}. Scored as internet facing, the more "
                "severe reading."
            )
    else:
        evidence.append(
            Evidence(
                "exposure",
                0,
                f"{asset.asset_name} is internal only, so an attacker needs an "
                "existing foothold to reach it.",
                "assets.csv",
            )
        )

    if not vuln.auth_required:
        exposure += 5
        evidence.append(
            Evidence(
                "exposure",
                5,
                "Exploitation requires no authentication.",
                "vulnerabilities.csv",
            )
        )
    exposure = min(exposure, CAP_EXPOSURE)

    # --------------------------------------------------------------- campaign
    campaign = 0.0
    primary: ThreatIntel | None = None
    if matched_intel:
        scored_intel = []
        for record in matched_intel:
            relevance = _intel_relevance(record)
            points = 8.0
            if (record.target_region or "").strip().lower() == "middle east":
                points += 5
            if record.ransomware_association:
                points += 5
            points += {"high": 2, "medium": 1}.get((record.confidence or "").lower(), 0)
            scored_intel.append((points * relevance, relevance, record))
        scored_intel.sort(key=lambda item: -item[0])
        campaign, relevance, primary = scored_intel[0]

        descriptor = (
            f"Campaign '{primary.campaign_name}' by {primary.threat_actor} is active "
            f"against {primary.target_sector} in {primary.target_region}"
        )
        if primary.ransomware_association:
            descriptor += ", with ransomware deployment observed"
        descriptor += f". Confidence {primary.confidence.lower()}, last seen {primary.active_last_seen}."
        if relevance < 1.0:
            descriptor += (
                f" Scored at {int(relevance * 100)}% weight because the campaign's "
                "target profile only partly matches TawasolPay."
            )
        evidence.append(
            Evidence("campaign", campaign, descriptor, f"threat_intelligence.csv {primary.intel_id}")
        )
    campaign = min(campaign, CAP_CAMPAIGN)

    # --------------------------------------------------------------- business
    business = 0.0
    if service is not None:
        revenue = {"critical": 6, "high": 4, "medium": 2}.get(
            (service.revenue_impact or "").lower(), 0
        )
        business += revenue
        parts = [f"revenue impact {service.revenue_impact.lower()}"]

        if service.customer_facing:
            business += 4
            parts.append("customer facing")

        frameworks = service.compliance_frameworks
        joined = " ".join(frameworks).upper()
        if "PCI" in joined:
            compliance = 4
        elif "GDPR" in joined or "PDPL" in joined:
            compliance = 3
        elif "SOC" in joined or "ISO" in joined:
            compliance = 2
        else:
            compliance = 0
        business += compliance
        if frameworks and frameworks != ["None"]:
            parts.append(f"in scope for {', '.join(frameworks)}")

        if service.rto_hours <= 2:
            business += 3
            parts.append(f"{service.rto_hours}h recovery objective")
        elif service.rto_hours <= 8:
            business += 2
            parts.append(f"{service.rto_hours}h recovery objective")

        dependents = pack.dependents.get(service.business_service, [])
        if dependents:
            blast = min(len(dependents), 3)
            business += blast
            parts.append(
                f"{len(dependents)} other service{'s' if len(dependents) != 1 else ''} "
                f"depend on it ({', '.join(dependents[:3])})"
            )

        evidence.append(
            Evidence(
                "business_impact",
                business,
                f"Supports '{service.business_service}', owned by {service.business_owner}: "
                + "; ".join(parts)
                + ".",
                "business_services.csv",
            )
        )
    else:
        warnings.append(
            f"No business service record for '{asset.business_service}', so business "
            "impact was scored at the floor and this risk may be understated."
        )

    criticality = {"critical": 3, "high": 2}.get((asset.criticality or "").lower(), 0)
    if criticality:
        business += criticality
        evidence.append(
            Evidence(
                "business_impact",
                criticality,
                f"The asset itself is classified {asset.criticality.lower()} criticality, "
                f"holding {asset.data_classification.lower()}.",
                "assets.csv",
            )
        )
    business = min(business, CAP_BUSINESS)

    # ------------------------------------------------------- missing controls
    controls = 0.0
    if not asset.edr_installed:
        controls += 5
        evidence.append(
            Evidence(
                "missing_controls",
                5,
                f"No EDR agent on {asset.asset_name}, so post exploitation activity "
                "would likely go undetected.",
                "assets.csv",
            )
        )
    if not vuln.patch_available:
        controls += 4
        evidence.append(
            Evidence(
                "missing_controls",
                4,
                "No vendor patch is available, so mitigation has to be compensating "
                "rather than corrective.",
                "vulnerabilities.csv",
            )
        )
    if vuln.days_open > 90:
        controls += 3
        evidence.append(
            Evidence(
                "missing_controls",
                3,
                f"Open for {vuln.days_open} days, far past any reasonable remediation "
                "window for this severity.",
                "vulnerabilities.csv",
            )
        )
    elif vuln.days_open > 30:
        controls += 2
        evidence.append(
            Evidence(
                "missing_controls",
                2,
                f"Open for {vuln.days_open} days.",
                "vulnerabilities.csv",
            )
        )
    if asset.is_stale:
        controls += 2
        evidence.append(
            Evidence(
                "missing_controls",
                2,
                f"Last seen {asset.last_seen_days} days ago, so its recorded state may "
                "no longer reflect reality.",
                "assets.csv",
            )
        )
    if asset.is_unowned:
        controls += 2
        evidence.append(
            Evidence(
                "missing_controls",
                2,
                "No owning team is assigned, so there is no one accountable for fixing it.",
                "assets.csv",
            )
        )
    controls = min(controls, CAP_CONTROLS)

    # ------------------------------------------------------------------- cvss
    cvss_points = min(max(vuln.cvss, 0.0), 10.0) * (CAP_CVSS / 10.0)
    evidence.append(
        Evidence(
            "cvss",
            cvss_points,
            f"CVSS {vuln.cvss:.1f} ({vuln.severity.lower()}). Contributes at most "
            f"{CAP_CVSS} of {RAW_TOTAL} raw points, so severity alone cannot drive "
            "the ranking.",
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
    total = sum(factors.values()) / RAW_TOTAL * 100.0

    return ScoredRisk(
        vulnerability=vuln,
        asset=asset,
        service=service,
        kev=kev_entry,
        intel=matched_intel,
        primary_intel=primary,
        factors=factors,
        evidence=evidence,
        score=round(total, 1),
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
    pack: DataPack, kev_catalogue: KevCatalogue
) -> tuple[list[ScoredRisk], list[ThreatIntel]]:
    """Score every open vulnerability, highest first."""
    intel_by_cve, unmatched = index_intel(pack)
    scored = [
        risk
        for risk in (
            score_vulnerability(vuln, pack, kev_catalogue, intel_by_cve)
            for vuln in pack.vulnerabilities
        )
        if risk is not None
    ]
    # Sort by score, then by vuln id so ties are stable and the output is
    # reproducible run to run.
    scored.sort(key=lambda r: (-r.score, r.vulnerability.vuln_id))
    return scored, unmatched
