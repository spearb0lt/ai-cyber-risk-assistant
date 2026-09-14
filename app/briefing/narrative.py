"""Plain English explanations for each risk.

Two paths produce the same shape of output:

- Deterministic. Composed from the scored evidence. Always available, needs no
  key, and is what the public deployment serves by default.
- Model written. Better prose, but constrained to the same evidence and put
  through `guard.check` before it is shown.

The deterministic path is not a stub. A reviewer opening the deployed URL with
no key must still get a complete, readable brief, so the template output is
written to stand on its own.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..llm import LLMError, generate
from ..reference.nist import Control, excerpt
from ..scoring.grouping import RiskGroup
from . import guard

SYSTEM = (
    "You are a security analyst writing the evidence section of a board level "
    "cyber risk brief for TawasolPay, a Gulf fintech.\n"
    "You will be given a scored risk and the exact NIST SP 800-53 control text "
    "that was retrieved for it.\n"
    "Rules you must not break:\n"
    "- Use only the facts in the supplied evidence. Never add a CVE, a control "
    "id, an asset name, a date or a number that is not there.\n"
    "- Never cite a NIST control that is not in the retrieved controls list.\n"
    "- Do not restate the score. Explain what makes this dangerous in business "
    "terms a non specialist can act on.\n"
    "- No headings, no bullet points, no preamble."
)


@dataclass
class Narrative:
    why: str
    remediation: str
    source: str  # "model" or "deterministic"
    provider: str = ""
    model: str = ""
    guard_report: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "why": self.why,
            "remediation": self.remediation,
            "source": self.source,
            "provider": self.provider,
            "model": self.model,
            "guard": self.guard_report,
            "error": self.error,
        }


def _join(parts: list[str]) -> str:
    parts = [p for p in parts if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def deterministic_why(risk: RiskGroup) -> str:
    """Compose the ranking rationale from the scored evidence alone."""
    lead = risk.lead
    vuln = lead.vulnerability
    asset = lead.asset
    service = lead.service
    assets = risk.assets

    if len(assets) == 1:
        where = f"{assets[0].asset_name} ({assets[0].asset_type.lower()})"
    else:
        where = (
            f"{len(assets)} assets including "
            + _join([a.asset_name for a in assets[:3]])
        )

    clauses: list[str] = []
    if lead.internet_reachable:
        clauses.append("it is reachable from the internet")
    if not vuln.auth_required:
        clauses.append("exploitation needs no credentials")
    if risk.kev_cves:
        confirmed = _join(risk.kev_cves[:3])
        clauses.append(f"CISA confirms {confirmed} {'are' if len(risk.kev_cves) > 1 else 'is'} being exploited in the wild")
    elif vuln.exploit_available:
        clauses.append("a working public exploit exists")

    opening = (
        f"Ranked {risk.rank} because {_join(clauses)}."
        if clauses
        else f"Ranked {risk.rank} on the combination of business exposure and open findings."
    )

    campaign_sentence = ""
    if lead.primary_intel:
        intel = lead.primary_intel
        region = intel.target_region.strip()
        where_region = "worldwide" if region.lower() == "global" else f"in the {region}"
        campaign_sentence = (
            f" {intel.threat_actor} is running the '{intel.campaign_name}' campaign against "
            f"{intel.target_sector.lower()} targets {where_region}, rated "
            f"{intel.exploit_maturity.lower()} with {intel.confidence.lower()} confidence and "
            f"last seen {intel.active_last_seen}."
        )
        if intel.ransomware_association:
            campaign_sentence += " Ransomware has been deployed in this campaign."

    business_sentence = ""
    if service:
        obligations = [f for f in service.compliance_frameworks if f and f.lower() != "none"]
        bits = [f"a {service.revenue_impact.lower()} revenue impact"]
        if service.customer_facing:
            bits.append("direct customer impact")
        if obligations:
            bits.append(f"{', '.join(obligations)} obligations")
        bits.append(f"a {service.rto_hours} hour recovery objective")
        business_sentence = (
            f" A successful attack lands on {service.business_service}, owned by "
            f"{service.business_owner}, which carries {_join(bits)}. "
            f"{service.business_impact.rstrip('.')}."
        )

    gaps: list[str] = []
    if not asset.edr_installed:
        gaps.append("there is no EDR agent to detect what happens next")
    if not vuln.patch_available:
        gaps.append("no vendor patch is available")
    if vuln.days_open > 30:
        gaps.append(f"the finding has been open {vuln.days_open} days")
    if asset.is_unowned:
        gaps.append("no team is assigned to fix it")
    if asset.is_stale:
        gaps.append(f"the asset was last seen {asset.last_seen_days} days ago")
    gap_sentence = f" Compounding this, {_join(gaps)}." if gaps else ""

    return (
        f"{opening} The weakness is {vuln.vulnerability_name} on {where}."
        f"{campaign_sentence}{business_sentence}{gap_sentence}"
    )


def deterministic_remediation(risk: RiskGroup, controls: list[Control]) -> str:
    """Summarise the retrieved controls without a model, quoting the document."""
    if not controls:
        return (
            "No NIST SP 800-53 control could be retrieved for this risk. Treat the "
            "remediation guidance as missing rather than as not required."
        )
    lead = risk.lead
    primary = controls[0]
    lines = [
        f"{primary.citation} is the controlling requirement. It states: "
        f'"{excerpt(primary, 300)}"'
    ]
    if len(controls) > 1:
        supporting = _join([f"{c.identifier} {c.name}" for c in controls[1:3]])
        lines.append(f"Supporting controls retrieved for this risk: {supporting}.")

    actions: list[str] = []
    if lead.kev and lead.kev.required_action:
        actions.append(
            f"CISA's required action for {lead.kev.cve_id} is: {lead.kev.required_action.rstrip('.')}."
        )
    if lead.vulnerability.patch_available:
        actions.append(
            "A vendor patch exists, so the corrective path is to test and install it "
            "inside the remediation window rather than to compensate around it."
        )
    else:
        actions.append(
            "No vendor patch exists, so containment has to come from compensating "
            "controls until one ships."
        )
    if not lead.asset.edr_installed:
        actions.append(
            "Deploying endpoint detection on the affected assets closes the detection "
            "gap this risk depends on."
        )
    lines.extend(actions)
    return " ".join(lines)


def _evidence_payload(risk: RiskGroup, controls: list[Control]) -> str:
    lead = risk.lead
    service = lead.service
    payload = {
        "rank": risk.rank,
        "score_out_of_100": round(risk.score, 1),
        "band": risk.band,
        "vulnerability": {
            "name": lead.vulnerability.vulnerability_name,
            "cves": risk.cves,
            "cvss": lead.vulnerability.cvss,
            "days_open": lead.vulnerability.days_open,
            "patch_available": lead.vulnerability.patch_available,
            "authentication_required": lead.vulnerability.auth_required,
            "affected_component": lead.vulnerability.affected_component,
        },
        "confirmed_exploited_by_cisa_kev": risk.kev_cves,
        "ransomware_associated": risk.ransomware_linked,
        "assets": [
            {
                "name": a.asset_name,
                "type": a.asset_type,
                "environment": a.environment,
                "internet_exposed": a.internet_exposed,
                "edr_installed": a.edr_installed,
                "owner_team": a.owner_team,
                "criticality": a.criticality,
            }
            for a in risk.assets
        ],
        "business_service": (
            {
                "name": service.business_service,
                "owner": service.business_owner,
                "impact_if_lost": service.business_impact,
                "customer_facing": service.customer_facing,
                "compliance_scope": service.compliance_scope,
                "revenue_impact": service.revenue_impact,
                "recovery_time_objective_hours": service.rto_hours,
            }
            if service
            else None
        ),
        "threat_intelligence": [
            {
                "actor": r.threat_actor,
                "campaign": r.campaign_name,
                "sector": r.target_sector,
                "region": r.target_region,
                "exploit_maturity": r.exploit_maturity,
                "ransomware": r.ransomware_association,
                "confidence": r.confidence,
                "last_seen": r.active_last_seen,
                "summary": r.summary,
            }
            for r in risk.intel[:3]
        ],
        "scoring_evidence": [e.as_dict() for e in lead.evidence],
        "retrieved_nist_controls": [
            {
                "identifier": c.identifier,
                "name": c.name,
                "family": c.family_name,
                "text": excerpt(c, 900),
            }
            for c in controls
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def write(
    risk: RiskGroup,
    controls: list[Control],
    *,
    provider_id: str | None = None,
    model: str | None = None,
    use_llm: bool = True,
) -> Narrative:
    """Produce the narrative, preferring the model but never depending on it."""
    fallback = Narrative(
        why=deterministic_why(risk),
        remediation=deterministic_remediation(risk, controls),
        source="deterministic",
    )
    if not use_llm:
        return fallback

    allowed_controls = [c.identifier for c in controls]
    prompt = (
        "Here is one scored risk and the NIST SP 800-53 control text retrieved for it.\n\n"
        f"{_evidence_payload(risk, controls)}\n\n"
        "Return a JSON object with exactly two string keys:\n"
        '  "why": three to four sentences explaining why this risk ranks where it '
        "does and what it would mean for the business if exploited.\n"
        '  "remediation": three to four sentences explaining what the retrieved NIST '
        "control requires and what to do about this risk, quoting the control by its "
        "identifier. Only use controls from retrieved_nist_controls: "
        f"{', '.join(allowed_controls) or 'none were retrieved'}."
    )

    try:
        raw, selection = generate(
            prompt,
            provider_id=provider_id,
            model=model,
            system=SYSTEM,
            temperature=0.15,
            max_tokens=900,
            json_mode=True,
        )
    except LLMError as exc:
        fallback.error = exc.message
        return fallback

    try:
        from ..llm import coerce_json

        parsed = coerce_json(raw)
        why = str(parsed.get("why", "")).strip()
        remediation = str(parsed.get("remediation", "")).strip()
    except Exception as exc:  # noqa: BLE001 - fall back on any parse problem
        fallback.error = f"Model output could not be parsed: {exc}"
        return fallback

    if not why or not remediation:
        fallback.error = "Model returned an incomplete narrative."
        return fallback

    allowed_cves = risk.cves
    why_report = guard.check(why, allowed_controls=allowed_controls, allowed_cves=allowed_cves)
    rem_report = guard.check(
        remediation, allowed_controls=allowed_controls, allowed_cves=allowed_cves
    )

    # If the guard stripped a narrative down to nothing, the model was writing
    # from memory rather than from the evidence. Use the template instead.
    if not why_report.text or not rem_report.text:
        fallback.error = (
            "Model output failed grounding checks and was discarded: "
            + "; ".join(why_report.violations + rem_report.violations)
        )
        fallback.guard_report = {
            "ok": False,
            "violations": why_report.violations + rem_report.violations,
            "removed_sentences": why_report.removed_sentences + rem_report.removed_sentences,
        }
        return fallback

    return Narrative(
        why=why_report.text,
        remediation=rem_report.text,
        source="model",
        provider=selection.provider.id,
        model=selection.model,
        guard_report={
            "ok": why_report.ok and rem_report.ok,
            "violations": why_report.violations + rem_report.violations,
            "removed_sentences": why_report.removed_sentences + rem_report.removed_sentences,
        },
    )
