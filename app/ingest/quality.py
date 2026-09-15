"""Data quality checks run at ingest, surfaced in the UI and the report.

A risk ranking is only as good as the records under it. Rather than let a
contradiction quietly change a score, every one found here is reported next to
the finding it affects, so a reader can see what the system was unsure about.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .loaders import DataPack


@dataclass(frozen=True)
class Issue:
    kind: str
    severity: str  # "warning" or "info"
    subject: str  # the record id the issue attaches to
    message: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def inspect(pack: DataPack) -> list[Issue]:
    """Every integrity problem the pack contains, as concrete findings."""
    issues: list[Issue] = []

    for vuln in pack.vulnerabilities:
        asset = pack.asset_for(vuln)
        if asset is None:
            issues.append(
                Issue(
                    "orphan_vulnerability",
                    "warning",
                    vuln.vuln_id,
                    f"References asset {vuln.asset_id}, which is not in the inventory. "
                    "It cannot be scored for business impact.",
                )
            )
            continue

        # The two files each carry an exposure flag and they can disagree.
        # Treating the more severe one as true is the safe default, but the
        # disagreement itself is reported rather than hidden.
        if vuln.internet_facing != asset.internet_exposed:
            issues.append(
                Issue(
                    "exposure_conflict",
                    "warning",
                    vuln.vuln_id,
                    f"{vuln.vuln_id} records exposure '{vuln.asset_exposure}' but asset "
                    f"{asset.asset_id} ({asset.asset_name}) is marked "
                    f"internet_exposed={'Yes' if asset.internet_exposed else 'No'}. "
                    "Scoring used the more exposed of the two.",
                )
            )

        if asset.business_service not in pack.services:
            issues.append(
                Issue(
                    "unknown_service",
                    "warning",
                    asset.asset_id,
                    f"Business service '{asset.business_service}' has no record in "
                    "business_services.csv, so impact was scored at the floor.",
                )
            )

    for asset in pack.assets.values():
        if asset.is_unowned:
            issues.append(
                Issue(
                    "unowned_asset",
                    "warning",
                    asset.asset_id,
                    f"{asset.asset_name} has no owning team, so no one is accountable "
                    "for remediating its findings.",
                )
            )
        if asset.is_stale:
            issues.append(
                Issue(
                    "stale_asset",
                    "info",
                    asset.asset_id,
                    f"{asset.asset_name} was last seen {asset.last_seen_days} days ago. "
                    "Its vulnerability and control state may no longer be accurate.",
                )
            )

    # An asset with no findings at all is the quietest failure in the pack.
    # Nothing in assets.csv records when an asset was last scanned, so "clean"
    # and "never looked at" are the same row to this system, and an asset in
    # neither state appears nowhere in a report that only lists risks.
    with_findings = {v.asset_id for v in pack.vulnerabilities}
    silent = [a for a in pack.assets.values() if a.asset_id not in with_findings]
    for asset in silent:
        notable = asset.internet_exposed or asset.criticality.lower() in {"critical", "high"}
        issues.append(
            Issue(
                "no_findings_recorded",
                "warning" if notable else "info",
                asset.asset_id,
                f"{asset.asset_name} has no vulnerability records at all. The data pack "
                "has no scan date, so this cannot be distinguished from an asset that "
                "was never scanned, and it appears nowhere in the ranking either way."
                + (
                    f" It is {asset.criticality.lower()} criticality"
                    + (" and internet exposed" if asset.internet_exposed else "")
                    + ", so treat its absence as unverified rather than clean."
                    if notable
                    else ""
                ),
            )
        )

    # Synthetic identifiers cannot be confirmed against any public catalogue.
    synthetic = sorted({v.cve for v in pack.vulnerabilities if v.is_synthetic_id})
    if synthetic:
        issues.append(
            Issue(
                "unverifiable_identifier",
                "info",
                "catalogue",
                f"{len(synthetic)} vulnerability identifiers are not real CVE ids "
                "(for example "
                + ", ".join(synthetic[:3])
                + "). They cannot be cross referenced against CISA KEV, so their "
                "exploitation status rests on the pack's own exploit_available flag.",
            )
        )

    return issues


def summarise(issues: list[Issue]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for issue in issues:
        counts[issue.kind] = counts.get(issue.kind, 0) + 1
    return {
        "total": len(issues),
        "warnings": sum(1 for i in issues if i.severity == "warning"),
        "by_kind": counts,
        "issues": [i.as_dict() for i in issues],
    }


def issues_for(issues: list[Issue], *subjects: str) -> list[Issue]:
    """The issues attached to any of these record ids."""
    wanted = {s for s in subjects if s}
    return [i for i in issues if i.subject in wanted]
