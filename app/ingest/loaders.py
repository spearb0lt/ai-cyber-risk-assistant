"""Load the TawasolPay data pack into typed records.

Every CSV here has a stable schema and an exact join key, so it is parsed into
a dataclass and queried with ordinary filters. Nothing in this module is
embedded. The reasoning behind that split is in the README.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .. import settings

YES = {"yes", "y", "true", "1"}


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in YES


def _int(value: str | None, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _float(value: str | None, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _split(value: str | None) -> list[str]:
    """Split a comma separated cell, dropping the several spellings of empty."""
    raw = (value or "").strip()
    if not raw or raw.lower() in {"none", "n/a", "na", "-"}:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _read_csv(path: Path) -> list[dict[str, str]]:
    # utf-8-sig because a BOM on the first header turns asset_id into
    # ﻿asset_id and silently breaks every lookup.
    with io.open(path, encoding="utf-8-sig", newline="") as handle:
        return [
            {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            for row in csv.DictReader(handle)
        ]


@dataclass(frozen=True)
class Asset:
    asset_id: str
    asset_name: str
    asset_type: str
    environment: str
    owner_team: str
    business_service: str
    internet_exposed: bool
    criticality: str
    data_classification: str
    edr_installed: bool
    last_seen_days: int
    location: str
    vendor_product: str

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def is_stale(self) -> bool:
        """Not seen for over a month, so its inventory record is unreliable."""
        return self.last_seen_days > 30

    @property
    def is_unowned(self) -> bool:
        return not self.owner_team or self.owner_team.lower() in {"none", "unassigned", "n/a"}


@dataclass(frozen=True)
class Vulnerability:
    vuln_id: str
    asset_id: str
    vulnerability_name: str
    cve: str
    severity: str
    cvss: float
    exploit_available: bool
    patch_available: bool
    days_open: int
    asset_exposure: str
    auth_required: bool
    status: str
    affected_component: str

    @property
    def internet_facing(self) -> bool:
        return self.asset_exposure.lower() == "internet"

    @property
    def is_synthetic_id(self) -> bool:
        """True for the pack's invented ids, which no public catalogue holds.

        This matters: absence from CISA KEV means "cannot be confirmed" for
        these, not "not exploited". The scoring engine must not treat the two
        the same way.
        """
        return not re.fullmatch(r"CVE-\d{4}-\d{4,7}", self.cve or "")


@dataclass(frozen=True)
class ThreatIntel:
    intel_id: str
    threat_actor: str
    campaign_name: str
    target_sector: str
    target_region: str
    matched_cve_or_control: str
    exploit_maturity: str
    active_last_seen: str
    ransomware_association: bool
    confidence: str
    summary: str


@dataclass(frozen=True)
class BusinessService:
    business_service: str
    business_owner: str
    business_impact: str
    customer_facing: bool
    compliance_scope: str
    revenue_impact: str
    rto_hours: int
    depends_on: list[str] = field(default_factory=list)
    risk_appetite: str = ""

    @property
    def compliance_frameworks(self) -> list[str]:
        return _split(self.compliance_scope)


@dataclass(frozen=True)
class RemediationHint:
    finding_type: str
    recommended_action: str
    priority_hint: str
    validation_evidence: str


@dataclass
class DataPack:
    assets: dict[str, Asset]
    vulnerabilities: list[Vulnerability]
    intel: list[ThreatIntel]
    services: dict[str, BusinessService]
    hints: list[RemediationHint]
    advisory: str

    # services that depend on a given service, i.e. its blast radius
    dependents: dict[str, list[str]] = field(default_factory=dict)

    def asset_for(self, vuln: Vulnerability) -> Asset | None:
        return self.assets.get(vuln.asset_id)

    def service_for(self, asset: Asset) -> BusinessService | None:
        return self.services.get(asset.business_service)


def _load_assets(path: Path) -> dict[str, Asset]:
    out: dict[str, Asset] = {}
    for row in _read_csv(path):
        asset = Asset(
            asset_id=row.get("asset_id", ""),
            asset_name=row.get("asset_name", ""),
            asset_type=row.get("asset_type", ""),
            environment=row.get("environment", ""),
            owner_team=row.get("owner_team", ""),
            business_service=row.get("business_service", ""),
            internet_exposed=_flag(row.get("internet_exposed")),
            criticality=row.get("criticality", ""),
            data_classification=row.get("data_classification", ""),
            edr_installed=_flag(row.get("edr_installed")),
            last_seen_days=_int(row.get("last_seen_days")),
            location=row.get("location", ""),
            vendor_product=row.get("vendor_product", ""),
        )
        if asset.asset_id:
            out[asset.asset_id] = asset
    return out


def _load_vulnerabilities(path: Path) -> list[Vulnerability]:
    return [
        Vulnerability(
            vuln_id=row.get("vuln_id", ""),
            asset_id=row.get("asset_id", ""),
            vulnerability_name=row.get("vulnerability_name", ""),
            cve=row.get("cve", ""),
            severity=row.get("severity", ""),
            cvss=_float(row.get("cvss")),
            exploit_available=_flag(row.get("exploit_available")),
            patch_available=_flag(row.get("patch_available")),
            days_open=_int(row.get("days_open")),
            asset_exposure=row.get("asset_exposure", ""),
            auth_required=_flag(row.get("auth_required")),
            status=row.get("status", ""),
            affected_component=row.get("affected_component", ""),
        )
        for row in _read_csv(path)
        if row.get("vuln_id")
    ]


def _load_intel(path: Path) -> list[ThreatIntel]:
    return [
        ThreatIntel(
            intel_id=row.get("intel_id", ""),
            threat_actor=row.get("threat_actor", ""),
            campaign_name=row.get("campaign_name", ""),
            target_sector=row.get("target_sector", ""),
            target_region=row.get("target_region", ""),
            matched_cve_or_control=row.get("matched_cve_or_control", ""),
            exploit_maturity=row.get("exploit_maturity", ""),
            active_last_seen=row.get("active_last_seen", ""),
            ransomware_association=_flag(row.get("ransomware_association")),
            confidence=row.get("confidence", ""),
            summary=row.get("summary", ""),
        )
        for row in _read_csv(path)
        if row.get("intel_id")
    ]


def _load_services(path: Path) -> dict[str, BusinessService]:
    out: dict[str, BusinessService] = {}
    for row in _read_csv(path):
        service = BusinessService(
            business_service=row.get("business_service", ""),
            business_owner=row.get("business_owner", ""),
            business_impact=row.get("business_impact", ""),
            customer_facing=_flag(row.get("customer_facing")),
            compliance_scope=row.get("compliance_scope", ""),
            revenue_impact=row.get("revenue_impact", ""),
            rto_hours=_int(row.get("rto_hours"), 24),
            depends_on=_split(row.get("depends_on")),
            risk_appetite=row.get("risk_appetite", ""),
        )
        if service.business_service:
            out[service.business_service] = service
    return out


def _load_hints(path: Path) -> list[RemediationHint]:
    return [
        RemediationHint(
            finding_type=row.get("finding_type", ""),
            recommended_action=row.get("recommended_action", ""),
            priority_hint=row.get("priority_hint", ""),
            validation_evidence=row.get("validation_evidence", ""),
        )
        for row in _read_csv(path)
        if row.get("finding_type")
    ]


@lru_cache(maxsize=1)
def load_pack(directory: str | None = None) -> DataPack:
    """Read the whole data pack once and cache it for the process."""
    base = Path(directory) if directory else settings.DATASET_DIR
    services = _load_services(base / "business_services.csv")

    # Invert depends_on: a service that many others depend on carries a wider
    # blast radius than its own record suggests.
    dependents: dict[str, list[str]] = {name: [] for name in services}
    for service in services.values():
        for upstream in service.depends_on:
            dependents.setdefault(upstream, []).append(service.business_service)

    advisory_path = base / "synthetic_threat_report.md"
    advisory = advisory_path.read_text(encoding="utf-8") if advisory_path.exists() else ""

    return DataPack(
        assets=_load_assets(base / "assets.csv"),
        vulnerabilities=_load_vulnerabilities(base / "vulnerabilities.csv"),
        intel=_load_intel(base / "threat_intelligence.csv"),
        services=services,
        hints=_load_hints(base / "remediation_guidance.csv"),
        advisory=advisory,
        dependents=dependents,
    )
