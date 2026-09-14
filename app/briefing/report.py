"""Render the analysis as Markdown.

The brief asks for output a technical manager can read and act on without
further processing, so this is the canonical deliverable: the dashboard is a
view of it and the JSON endpoint is the machine readable form of it.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .analysis import Analysis, RiskBrief

BAND_MARK = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}

FACTOR_LABELS = {
    "exploitability": "Active exploitation",
    "exposure": "Internet exposure",
    "campaign": "Threat campaign match",
    "business_impact": "Business impact",
    "missing_controls": "Missing controls",
    "cvss": "CVSS severity",
}

FACTOR_CAPS = {
    "exploitability": 30,
    "exposure": 22,
    "campaign": 20,
    "business_impact": 20,
    "missing_controls": 12,
    "cvss": 10,
}


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _risk_section(brief: RiskBrief) -> list[str]:
    risk = brief.risk
    lead = risk.lead
    service = lead.service
    lines: list[str] = []

    lines.append(f"## {risk.rank}. {risk.title}")
    lines.append("")
    lines.append(
        f"**Risk score {risk.score:.1f} / 100 ({BAND_MARK.get(risk.band, risk.band)})**"
    )
    lines.append("")

    # --- the five things the brief requires for every risk ---
    assets = risk.assets
    asset_line = ", ".join(f"{a.asset_name} ({a.asset_type}, {a.environment})" for a in assets)
    lines.append(f"- **Asset:** {asset_line}")
    vuln_bits = []
    for member in risk.members:
        marker = " [in CISA KEV]" if member.kev else ""
        vuln_bits.append(
            f"{member.vulnerability.cve} {member.vulnerability.vulnerability_name} "
            f"(CVSS {member.vulnerability.cvss:.1f}, open {member.vulnerability.days_open} days){marker}"
        )
    lines.append(f"- **Vulnerability:** {'; '.join(dict.fromkeys(vuln_bits))}")

    if risk.intel:
        intel = lead.primary_intel or risk.intel[0]
        lines.append(
            f"- **Matched threat intel:** {intel.threat_actor} running "
            f"'{intel.campaign_name}' against {intel.target_sector} in "
            f"{intel.target_region}. Exploit maturity {intel.exploit_maturity.lower()}, "
            f"confidence {intel.confidence.lower()}, last seen {intel.active_last_seen}. "
            f"Ransomware association: {_yes_no(intel.ransomware_association)}."
        )
    else:
        lines.append(
            "- **Matched threat intel:** none. No campaign in the feed references "
            "these identifiers, so this ranks on exposure and impact alone."
        )

    if service:
        lines.append(
            f"- **Business service at risk:** {service.business_service}, owned by "
            f"{service.business_owner}. {service.business_impact.rstrip('.')}. "
            f"Revenue impact {service.revenue_impact.lower()}, recovery objective "
            f"{service.rto_hours}h, compliance scope {service.compliance_scope}."
        )
    else:
        lines.append(
            f"- **Business service at risk:** {risk.service_name} (no service record found)."
        )

    lines.append("")
    lines.append(f"**Why this ranks here.** {brief.narrative.why}")
    lines.append("")

    # --- score breakdown, so the ranking is auditable ---
    lines.append("**Score breakdown**")
    lines.append("")
    lines.append("| Factor | Points | Cap |")
    lines.append("| --- | ---: | ---: |")
    for key, label in FACTOR_LABELS.items():
        points = lead.factors.get(key, 0.0)
        lines.append(f"| {label} | {points:.1f} | {FACTOR_CAPS[key]} |")
    if risk.amplifier:
        lines.append(
            f"| Blast radius ({len(assets)} assets affected) | +{risk.amplifier:.1f} | 6 |"
        )
    lines.append("")

    # --- retrieved NIST guidance ---
    if brief.controls:
        lines.append("**Remediation guidance, retrieved from NIST SP 800-53 Rev. 5**")
        lines.append("")
        for control in brief.controls:
            facet = brief.control_sources.get(control.identifier, "")
            suffix = f" _(retrieved for: {facet.lower()})_" if facet else ""
            lines.append(f"- **{control.identifier} {control.name}** ({control.family_name}){suffix}")
            excerpt_text = next(
                (c["excerpt"] for c in brief.as_dict()["controls"] if c["identifier"] == control.identifier),
                "",
            )
            if excerpt_text:
                lines.append(f"  > {excerpt_text}")
        lines.append("")
        lines.append(brief.narrative.remediation)
        lines.append("")
    else:
        lines.append(
            "**Remediation guidance:** no NIST control could be retrieved for this risk."
        )
        lines.append("")

    if risk.warnings:
        lines.append("**Caveats on this finding**")
        lines.append("")
        for warning in risk.warnings:
            lines.append(f"- {warning}")
        lines.append("")

    return lines


def render(analysis: Analysis, briefs: list[RiskBrief] | None = None) -> str:
    briefs = briefs if briefs is not None else analysis.briefs
    summary = analysis.summary()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# TawasolPay, prioritised cyber risk brief")
    lines.append("")
    lines.append(f"Generated {generated}.")
    lines.append("")

    narrative_sources = {b.narrative.source for b in briefs}
    if narrative_sources == {"deterministic"}:
        lines.append(
            "> Narratives in this run were composed deterministically from the scored "
            "evidence. No language model was used. Ranking, exploitation status and "
            "control retrieval never use one."
        )
    else:
        used = sorted({f"{b.narrative.provider}/{b.narrative.model}" for b in briefs if b.narrative.source == "model"})
        lines.append(
            "> Narratives were written by " + ", ".join(used) + ", constrained to the "
            "retrieved evidence and checked for fabricated control and CVE citations. "
            "Ranking and control retrieval are deterministic and did not use a model."
        )
    lines.append("")

    lines.append("## Estate at a glance")
    lines.append("")
    lines.append(
        f"- {summary['assets']} assets, {summary['internet_exposed_assets']} internet exposed, "
        f"{summary['assets_without_edr']} without EDR"
    )
    lines.append(
        f"- {summary['vulnerabilities']} open vulnerabilities across "
        f"{summary['business_services']} business services"
    )
    lines.append(
        f"- {summary['kev_confirmed_vulnerabilities']} confirmed by CISA KEV as exploited "
        f"in the wild, of which {summary['ransomware_linked_vulnerabilities']} are linked "
        "to ransomware campaigns"
    )
    lines.append(
        f"- {summary['intel_matched']} of {summary['intel_records']} threat intel records "
        f"match this estate; {summary['intel_unmatched']} do not and were excluded from scoring"
    )
    bands = summary["bands"]
    lines.append(
        f"- Risk bands: {bands['Critical']} critical, {bands['High']} high, "
        f"{bands['Medium']} medium, {bands['Low']} low"
    )
    lines.append("")

    kev_meta = analysis.kev_meta
    lines.append(
        f"KEV snapshot: {kev_meta['entries']} entries, newest dated "
        f"{kev_meta['newest_entry']} ({kev_meta['age_days']} days old). "
        f"Retrieval mode: {analysis.retrieval['mode']} over "
        f"{analysis.retrieval['chunks']} NIST passages."
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append(f"# Top {len(briefs)} risks")
    lines.append("")
    for brief in briefs:
        lines.extend(_risk_section(brief))
        lines.append("---")
        lines.append("")

    # --- the intel that did not apply, reported rather than dropped ---
    if analysis.unmatched_intel:
        lines.append("# Threat intel with no match in this estate")
        lines.append("")
        lines.append(
            f"{len(analysis.unmatched_intel)} of {len(analysis.pack.intel)} intel records "
            "reference vulnerabilities or techniques that do not appear in TawasolPay's "
            "current inventory. They contributed nothing to the scores above. They are "
            "listed because 'we checked and it does not affect us' is a finding."
        )
        lines.append("")
        lines.append("| Actor | Campaign | Reference | Sector | Region | Ransomware |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for record in analysis.unmatched_intel:
            lines.append(
                f"| {record.threat_actor} | {record.campaign_name} | "
                f"{record.matched_cve_or_control} | {record.target_sector} | "
                f"{record.target_region} | {_yes_no(record.ransomware_association)} |"
            )
        lines.append("")

    # --- data quality, because the ranking rests on these records ---
    issues = analysis.issues
    if issues:
        lines.append("# Data quality notes")
        lines.append("")
        lines.append(
            "Problems found in the source data during ingest. Each one is a reason a "
            "finding above could be wrong."
        )
        lines.append("")
        for issue in issues:
            lines.append(f"- **{issue.kind.replace('_', ' ')}** ({issue.subject}): {issue.message}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Sources: CISA Known Exploited Vulnerabilities catalogue; NIST SP 800-53 Rev. 5 "
        "control catalogue; TawasolPay asset, vulnerability, threat intelligence and "
        "business service records; MDR advisory."
    )
    lines.append("")
    return "\n".join(lines)
