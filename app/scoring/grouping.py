"""Turn scored vulnerabilities into the risks a person would actually brief.

The five highest scoring rows are not the five best things to tell a board.
Run ungrouped, the top five here is four separate entries for the same Fortinet
exploit chain across a pair of VPN appliances. That is accurate and useless:
one decision, one owner, one change window, reported four times.

So rows are collapsed into a risk when they describe the same attack against
the same business service, and the number of distinct assets affected becomes
an amplifier rather than a repeat. Grouping by service rather than by asset is
deliberate: the service is what has an owner, a recovery objective and a
compliance obligation, which is what makes it the unit of a decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..ingest.advisory import AdvisoryCampaign
from ..ingest.loaders import Asset, ThreatIntel
from .engine import ScoredRisk
from .weights import DEFAULTS, Weights


@dataclass
class RiskGroup:
    key: tuple[str, str]
    lead: ScoredRisk
    members: list[ScoredRisk]
    score: float
    amplifier: float
    rank: int = 0
    weights: Weights = DEFAULTS
    # populated later by the briefing layer
    narrative: str = ""
    controls: list[Any] = field(default_factory=list)
    retrieval: Any = None

    @property
    def title(self) -> str:
        if self.lead.campaign_name:
            return f"{self.lead.campaign_name}: {self.lead.vulnerability.vulnerability_name}"
        return self.lead.vulnerability.vulnerability_name

    @property
    def band(self) -> str:
        return self.weights.band_for(self.score)

    @property
    def advisory(self) -> AdvisoryCampaign | None:
        """The MDR advisory campaign this risk belongs to, if any."""
        for member in self.members:
            if member.advisory:
                return member.advisory
        return None

    @property
    def service_name(self) -> str:
        return self.key[0]

    @property
    def assets(self) -> list[Asset]:
        seen: dict[str, Asset] = {}
        for member in self.members:
            seen.setdefault(member.asset.asset_id, member.asset)
        return list(seen.values())

    @property
    def cves(self) -> list[str]:
        out: list[str] = []
        for member in self.members:
            if member.vulnerability.cve not in out:
                out.append(member.vulnerability.cve)
        return out

    @property
    def intel(self) -> list[ThreatIntel]:
        seen: dict[str, ThreatIntel] = {}
        for member in self.members:
            for record in member.intel:
                seen.setdefault(record.intel_id, record)
        return list(seen.values())

    @property
    def warnings(self) -> list[str]:
        out: list[str] = []
        for member in self.members:
            for warning in member.warnings:
                if warning not in out:
                    out.append(warning)
        return out

    @property
    def kev_cves(self) -> list[str]:
        """Distinct CVEs in this risk that CISA confirms are exploited.

        Deduplicated because the same CVE commonly appears once per affected
        asset, and a count of rows is not a count of vulnerabilities.
        """
        out: list[str] = []
        for member in self.members:
            if member.kev and member.vulnerability.cve not in out:
                out.append(member.vulnerability.cve)
        return out

    @property
    def ransomware_linked(self) -> bool:
        return any(m.kev and m.kev.known_ransomware for m in self.members) or any(
            record.ransomware_association for record in self.intel
        )

    def as_dict(self) -> dict[str, Any]:
        lead = self.lead
        return {
            "rank": self.rank,
            "id": f"{self.key[0]}|{self.key[1]}".replace(" ", "-").lower(),
            "title": self.title,
            "score": round(self.score, 1),
            "band": self.band,
            "amplifier": round(self.amplifier, 1),
            "business_service": self.service_name,
            "service_owner": lead.service.business_owner if lead.service else "",
            "service_impact": lead.service.business_impact if lead.service else "",
            "compliance_scope": lead.service.compliance_scope if lead.service else "",
            "rto_hours": lead.service.rto_hours if lead.service else None,
            "lead": lead.as_dict(),
            "assets": [
                {
                    "asset_id": a.asset_id,
                    "asset_name": a.asset_name,
                    "asset_type": a.asset_type,
                    "environment": a.environment,
                    "owner_team": a.owner_team,
                    "internet_exposed": a.internet_exposed,
                    "edr_installed": a.edr_installed,
                    "criticality": a.criticality,
                    "vendor_product": a.vendor_product,
                    "location": a.location,
                }
                for a in self.assets
            ],
            "vulnerabilities": [
                {
                    "vuln_id": m.vulnerability.vuln_id,
                    "cve": m.vulnerability.cve,
                    "name": m.vulnerability.vulnerability_name,
                    "cvss": m.vulnerability.cvss,
                    "severity": m.vulnerability.severity,
                    "days_open": m.vulnerability.days_open,
                    "patch_available": m.vulnerability.patch_available,
                    "asset_id": m.asset.asset_id,
                    "asset_name": m.asset.asset_name,
                    "in_kev": bool(m.kev),
                    "kev_ransomware": bool(m.kev and m.kev.known_ransomware),
                    "kev_date_added": m.kev.date_added if m.kev else "",
                    "kev_required_action": m.kev.required_action if m.kev else "",
                }
                for m in self.members
            ],
            "threat_intel": [
                {
                    "intel_id": r.intel_id,
                    "threat_actor": r.threat_actor,
                    "campaign_name": r.campaign_name,
                    "target_sector": r.target_sector,
                    "target_region": r.target_region,
                    "matched_cve": r.matched_cve_or_control,
                    "exploit_maturity": r.exploit_maturity,
                    "ransomware_association": r.ransomware_association,
                    "confidence": r.confidence,
                    "active_last_seen": r.active_last_seen,
                    "summary": r.summary,
                }
                for r in self.intel
            ],
            "factors": {k: round(v, 1) for k, v in lead.factors.items()},
            "evidence": [e.as_dict() for e in lead.evidence],
            "warnings": self.warnings,
            "narrative": self.narrative,
            "controls": self.controls,
            "advisory": self.advisory.as_dict() if self.advisory else None,
        }


def _group_key(risk: ScoredRisk) -> tuple[str, str]:
    """What makes two rows the same risk.

    A named campaign is the strongest signal: CVE-2024-21762 and CVE-2024-55591
    are two CVEs but one intrusion, because CrimsonJackal chains them. Without
    intel, the affected component is the next best proxy for "the same fix".
    """
    service = risk.asset.business_service or "Unassigned service"
    if risk.campaign_name:
        return (service, f"campaign:{risk.campaign_name}")
    return (service, f"component:{risk.vulnerability.affected_component}")


def group(scored: list[ScoredRisk], weights: Weights = DEFAULTS) -> list[RiskGroup]:
    """Collapse scored rows into risks, highest first."""
    buckets: dict[tuple[str, str], list[ScoredRisk]] = {}
    for risk in scored:
        buckets.setdefault(_group_key(risk), []).append(risk)

    groups: list[RiskGroup] = []
    for key, members in buckets.items():
        # `scored` arrives sorted, so the first member is the lead.
        lead = members[0]
        distinct_assets = len({m.asset.asset_id for m in members})
        amplifier = min(
            weights.asset_amplifier * (distinct_assets - 1), weights.amplifier_cap
        )
        groups.append(
            RiskGroup(
                key=key,
                lead=lead,
                members=members,
                score=min(lead.score + amplifier, 100.0),
                amplifier=amplifier,
                weights=weights,
            )
        )

    groups.sort(key=lambda g: (-g.score, g.key))
    return groups


def top_risks(
    groups: list[RiskGroup],
    limit: int | None = None,
    max_per_service: int | None = None,
    weights: Weights = DEFAULTS,
) -> list[RiskGroup]:
    """The highest risks, with a cap on how many may share a business service.

    Without the cap a single service can occupy most of the list. The cap is
    configurable because the right answer depends on the audience: a board
    wants breadth, the team that owns one service wants depth.
    """
    limit = int(weights.top_n) if limit is None else limit
    max_per_service = (
        int(weights.max_risks_per_service) if max_per_service is None else max_per_service
    )

    chosen: list[RiskGroup] = []
    per_service: dict[str, int] = {}
    for candidate in groups:
        if len(chosen) >= limit:
            break
        used = per_service.get(candidate.service_name, 0)
        if max_per_service > 0 and used >= max_per_service:
            continue
        per_service[candidate.service_name] = used + 1
        chosen.append(candidate)

    # If the diversity cap left the list short, backfill by score so the brief
    # always has the requested number of entries.
    if len(chosen) < limit:
        taken = {id(g) for g in chosen}
        for candidate in groups:
            if len(chosen) >= limit:
                break
            if id(candidate) not in taken:
                chosen.append(candidate)

    chosen.sort(key=lambda g: -g.score)
    for position, risk in enumerate(chosen, start=1):
        risk.rank = position
    return chosen
