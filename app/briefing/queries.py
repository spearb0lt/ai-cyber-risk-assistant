"""Build NIST retrieval queries from structured signals.

The query is assembled from the record fields, not written by an LLM. That
keeps retrieval reproducible and stops a model's paraphrase from quietly
steering which control gets cited.

Several narrow queries beat one long one. A risk usually has two separate
control needs: something about the weakness itself (an unauthenticated RCE on
an edge device) and something about the gap that let it persist (no EDR, open
for 120 days, nobody owns the box). Retrieving each facet separately and
merging surfaces both, where a single blended query tends to return only the
dominant theme.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..scoring.grouping import RiskGroup

# Vocabulary bridges from the estate's words to the catalogue's words. NIST
# does not say "EDR" or "internet facing", so a literal query misses.
_COMPONENT_HINTS = {
    "vpn": "remote access virtual private network gateway boundary protection external connections",
    "ssl-vpn": "remote access virtual private network cryptographic protection boundary",
    "session": "session authenticity session identifiers session termination invalidate tokens",
    "token": "authenticator management session identifiers credential protection",
    "openssh": "remote access secure shell cryptographic protection least functionality",
    "tls": "transmission confidentiality and integrity cryptographic protection",
    "web framework": "information input validation web application least functionality",
    "api": "application programming interface access enforcement input validation",
    "kernel": "least functionality flaw remediation system integrity",
    "container": "least functionality configuration settings component isolation",
    "kubernetes": "configuration management least functionality access enforcement",
    "database": "protection of information at rest access enforcement least privilege",
    "backup": "system backup contingency planning information recovery integrity",
    "active directory": "account management identity management least privilege",
    "jenkins": "developer configuration management least functionality access enforcement",
    "teamcity": "developer configuration management access enforcement authenticator management",
    "confluence": "input validation least functionality access enforcement",
    "jira": "input validation least functionality access enforcement",
    "storage": "protection of information at rest media protection access enforcement",
    "firmware": "flaw remediation system component integrity supply chain",
}


@dataclass(frozen=True)
class Facet:
    label: str
    query: str


def _component_hint(*terms: str) -> str:
    text = " ".join(t.lower() for t in terms if t)
    hints = [hint for key, hint in _COMPONENT_HINTS.items() if key in text]
    return " ".join(dict.fromkeys(" ".join(hints).split()))


def facets_for(risk: RiskGroup) -> list[Facet]:
    """The distinct guidance this risk needs, as separate retrieval queries."""
    lead = risk.lead
    vuln = lead.vulnerability
    asset = lead.asset
    out: list[Facet] = []

    # 1. The weakness itself.
    weakness = [
        vuln.vulnerability_name,
        vuln.affected_component,
        asset.asset_type,
        _component_hint(vuln.affected_component, vuln.vulnerability_name, asset.asset_type,
                        asset.vendor_product),
    ]
    if lead.internet_reachable:
        weakness.append(
            "internet facing external system boundary protection restrict external connections"
        )
    if not vuln.auth_required:
        weakness.append("unauthenticated access identification and authentication access enforcement")
    out.append(Facet("Weakness", " ".join(p for p in weakness if p)))

    # 2. Remediation posture: patching and the age of the finding.
    posture = ["flaw remediation install security relevant software and firmware updates"]
    if vuln.patch_available:
        posture.append(
            f"vendor patch available but the finding has been open {vuln.days_open} days "
            "corrective actions benchmarks time to remediate"
        )
    else:
        posture.append(
            "no vendor patch available compensating controls mitigation unsupported "
            "system components alternative sources of support"
        )
    if vuln.days_open > 90:
        posture.append("remediation timeframes exceeded vulnerability monitoring and scanning")
    out.append(Facet("Remediation", " ".join(posture)))

    # 3. The missing compensating control, if there is one.
    gaps: list[str] = []
    if not asset.edr_installed:
        gaps.append(
            "malicious code protection endpoint detection and response system monitoring "
            "detect unauthorised activity intrusion detection"
        )
    if asset.is_unowned:
        gaps.append(
            "system component inventory accountability assign responsible individual ownership"
        )
    if asset.is_stale:
        gaps.append("system component inventory automated maintenance unsupported components")
    if risk.ransomware_linked:
        gaps.append(
            "incident handling ransomware containment system backup recovery "
            "information integrity contingency plan"
        )
    if gaps:
        out.append(Facet("Control gap", " ".join(gaps)))

    # 4. Compliance obligation, only when the service carries one.
    service = lead.service
    if service and service.compliance_frameworks and service.compliance_frameworks != ["None"]:
        scope = " ".join(service.compliance_frameworks).upper()
        terms = ["risk assessment security categorisation continuous monitoring"]
        if "PCI" in scope:
            terms.append(
                "protection of information at rest cardholder payment data "
                "cryptographic protection access enforcement"
            )
        if "GDPR" in scope or "PDPL" in scope:
            terms.append(
                "personally identifiable information processing privacy personal data "
                "processing purposes"
            )
        out.append(Facet("Compliance", " ".join(terms)))

    return out
