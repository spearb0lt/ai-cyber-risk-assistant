"""Every tunable number in the scoring model, in one place.

The defaults reproduce the model the README describes. Nothing here is magic,
which is the point: the weights are a judgement, and a judgement a reviewer
cannot inspect or change is indistinguishable from an arbitrary one. The API
and the UI both accept an override, so the ranking can be re-derived under a
different set of priorities and compared.

Setting a factor cap to 0 removes that factor entirely. It drops out of the
numerator and out of the denominator, so the remaining factors still span the
full 0 to 100 range rather than the score collapsing toward zero. "Ignore CVSS
completely" is therefore a single slider, and the result is still comparable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any

# Bounds applied to any supplied value. Generous enough to let a reviewer make
# a factor dominant, tight enough that a typo cannot produce nonsense.
MIN_VALUE = 0.0
MAX_VALUE = 100.0


@dataclass(frozen=True)
class Weights:
    # ---------------------------------------------------------------- caps
    # The ceiling each factor contributes. Their sum is the raw total that a
    # score is normalised against.
    cap_exploitability: float = 30.0
    cap_exposure: float = 22.0
    cap_campaign: float = 20.0
    cap_business_impact: float = 20.0
    cap_missing_controls: float = 12.0
    cap_cvss: float = 10.0

    # ------------------------------------------------- exploitability signals
    kev_listed: float = 14.0
    kev_ransomware: float = 8.0
    exploit_available: float = 6.0
    maturity_weaponized: float = 6.0
    maturity_active: float = 6.0
    maturity_commodity: float = 4.0
    maturity_proof_of_concept: float = 2.0
    maturity_social: float = 1.0

    # ------------------------------------------------------- exposure signals
    internet_reachable: float = 14.0
    no_auth_required: float = 5.0
    # Both sources agreeing that it is internet facing is stronger evidence
    # than one source asserting it alone.
    exposure_sources_agree: float = 3.0

    # ------------------------------------------------------- campaign signals
    campaign_matched: float = 8.0
    campaign_targets_our_region: float = 5.0
    campaign_ransomware: float = 5.0
    campaign_confidence_high: float = 2.0
    campaign_confidence_medium: float = 1.0
    # Named in the MDR advisory that arrived this morning. A human analyst
    # judged this one worth reporting to this company, which the generic feed
    # does not tell you.
    advisory_named: float = 6.0
    advisory_ransomware: float = 3.0

    # ------------------------------------------------ business impact signals
    revenue_critical: float = 6.0
    revenue_high: float = 4.0
    revenue_medium: float = 2.0
    customer_facing: float = 4.0
    compliance_pci: float = 4.0
    compliance_privacy: float = 3.0
    compliance_other: float = 2.0
    rto_under_2h: float = 3.0
    rto_under_8h: float = 2.0
    asset_criticality_critical: float = 3.0
    asset_criticality_high: float = 2.0
    # Each other service that depends on this one, capped.
    dependency_each: float = 1.0
    dependency_cap: float = 3.0

    # ----------------------------------------------- missing control signals
    no_edr: float = 5.0
    no_patch_available: float = 4.0
    open_over_90_days: float = 3.0
    open_over_30_days: float = 2.0
    stale_asset: float = 2.0
    unowned_asset: float = 2.0

    # ------------------------------------------------------------- grouping
    # Each additional affected asset widens the blast radius.
    asset_amplifier: float = 2.0
    amplifier_cap: float = 6.0

    # --------------------------------------------------------------- output
    top_n: float = 5.0
    max_risks_per_service: float = 1.0

    # ----------------------------------------------------------------- bands
    band_critical: float = 70.0
    band_high: float = 55.0
    band_medium: float = 40.0

    @property
    def raw_total(self) -> float:
        """The denominator. Zeroed factors leave it, so 100 stays reachable."""
        total = (
            self.cap_exploitability
            + self.cap_exposure
            + self.cap_campaign
            + self.cap_business_impact
            + self.cap_missing_controls
            + self.cap_cvss
        )
        # Every cap at zero would divide by zero. Fall back to 1 so the score
        # is a well defined 0 rather than an exception.
        return total if total > 0 else 1.0

    @property
    def enabled_factors(self) -> list[str]:
        return [
            name
            for name, cap in (
                ("exploitability", self.cap_exploitability),
                ("exposure", self.cap_exposure),
                ("campaign", self.cap_campaign),
                ("business_impact", self.cap_business_impact),
                ("missing_controls", self.cap_missing_controls),
                ("cvss", self.cap_cvss),
            )
            if cap > 0
        ]

    def cap_for(self, factor: str) -> float:
        return float(getattr(self, f"cap_{factor}", 0.0))

    def band_for(self, score: float) -> str:
        if score >= self.band_critical:
            return "Critical"
        if score >= self.band_high:
            return "High"
        if score >= self.band_medium:
            return "Medium"
        return "Low"

    def as_dict(self) -> dict[str, float]:
        return {k: float(v) for k, v in asdict(self).items()}

    def key(self) -> tuple:
        """A hashable identity, used to cache one analysis per weighting."""
        return tuple(sorted(self.as_dict().items()))

    def is_default(self) -> bool:
        return self.as_dict() == DEFAULTS.as_dict()

    def changed_from_default(self) -> dict[str, tuple[float, float]]:
        base = DEFAULTS.as_dict()
        mine = self.as_dict()
        return {k: (base[k], mine[k]) for k in mine if base[k] != mine[k]}

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "Weights":
        """Build from untrusted input, ignoring unknown keys and bad values."""
        if not raw:
            return cls()
        known = {f.name for f in fields(cls)}
        values: dict[str, float] = {}
        for name, value in raw.items():
            if name not in known:
                continue
            try:
                number = float(value)
            except (TypeError, ValueError):
                continue
            if number != number or number in (float("inf"), float("-inf")):
                continue
            values[name] = max(MIN_VALUE, min(MAX_VALUE, number))
        # These two are counts, not weights, and must stay sane.
        if "top_n" in values:
            values["top_n"] = max(1.0, min(25.0, round(values["top_n"])))
        if "max_risks_per_service" in values:
            values["max_risks_per_service"] = max(0.0, min(10.0, round(values["max_risks_per_service"])))
        return cls(**values)


DEFAULTS = Weights()


# Presentation metadata for the tuning panel. Grouped so the UI can render the
# six caps prominently and keep the individual signals behind a disclosure.
FACTOR_LABELS = {
    "exploitability": "Active exploitation",
    "exposure": "Internet exposure",
    "campaign": "Threat campaign match",
    "business_impact": "Business impact",
    "missing_controls": "Missing controls",
    "cvss": "CVSS severity",
}

SIGNAL_GROUPS: list[dict[str, Any]] = [
    {
        "factor": "exploitability",
        "signals": [
            ("kev_listed", "Listed in CISA KEV"),
            ("kev_ransomware", "KEV records ransomware use"),
            ("exploit_available", "Public exploit available"),
            ("maturity_weaponized", "Intel: weaponised"),
            ("maturity_active", "Intel: active exploitation"),
            ("maturity_commodity", "Intel: commodity exploit"),
            ("maturity_proof_of_concept", "Intel: proof of concept"),
            ("maturity_social", "Intel: social engineering"),
        ],
    },
    {
        "factor": "exposure",
        "signals": [
            ("internet_reachable", "Reachable from the internet"),
            ("no_auth_required", "No authentication needed"),
            ("exposure_sources_agree", "Both sources agree on exposure"),
        ],
    },
    {
        "factor": "campaign",
        "signals": [
            ("campaign_matched", "Matched to a named campaign"),
            ("campaign_targets_our_region", "Campaign targets our region"),
            ("campaign_ransomware", "Campaign deploys ransomware"),
            ("campaign_confidence_high", "Intel confidence high"),
            ("campaign_confidence_medium", "Intel confidence medium"),
            ("advisory_named", "Named in this morning's MDR advisory"),
            ("advisory_ransomware", "Advisory marks the chain as ransomware"),
        ],
    },
    {
        "factor": "business_impact",
        "signals": [
            ("revenue_critical", "Revenue impact critical"),
            ("revenue_high", "Revenue impact high"),
            ("revenue_medium", "Revenue impact medium"),
            ("customer_facing", "Customer facing service"),
            ("compliance_pci", "In PCI DSS scope"),
            ("compliance_privacy", "In GDPR or PDPL scope"),
            ("compliance_other", "In SOC 2 or ISO 27001 scope"),
            ("rto_under_2h", "Recovery objective 2h or less"),
            ("rto_under_8h", "Recovery objective 8h or less"),
            ("asset_criticality_critical", "Asset criticality critical"),
            ("asset_criticality_high", "Asset criticality high"),
            ("dependency_each", "Per dependent service"),
            ("dependency_cap", "Dependent service ceiling"),
        ],
    },
    {
        "factor": "missing_controls",
        "signals": [
            ("no_edr", "No EDR on the asset"),
            ("no_patch_available", "No vendor patch available"),
            ("open_over_90_days", "Open more than 90 days"),
            ("open_over_30_days", "Open more than 30 days"),
            ("stale_asset", "Asset not seen in over 30 days"),
            ("unowned_asset", "No owning team assigned"),
        ],
    },
]

GROUPING_SIGNALS = [
    ("asset_amplifier", "Per additional affected asset"),
    ("amplifier_cap", "Blast radius ceiling"),
]

OUTPUT_SIGNALS = [
    ("top_n", "Risks to report"),
    ("max_risks_per_service", "Max risks per business service (0 = no cap)"),
]

BAND_SIGNALS = [
    ("band_critical", "Critical at or above"),
    ("band_high", "High at or above"),
    ("band_medium", "Medium at or above"),
]


def _signals_for(factor: str) -> list[tuple[str, str]]:
    """Sub-signals for a factor. CVSS has none: it is read straight off the
    score rather than assembled from observations, so its cap is its only
    tunable."""
    for group in SIGNAL_GROUPS:
        if group["factor"] == factor:
            return group["signals"]
    return []


def schema() -> dict[str, Any]:
    """Everything the tuning UI needs to render itself."""
    return {
        "defaults": DEFAULTS.as_dict(),
        "factors": [
            {
                "id": factor,
                "label": FACTOR_LABELS[factor],
                "cap_field": f"cap_{factor}",
                "cap_default": DEFAULTS.cap_for(factor),
                "signals": [
                    {"field": field, "label": label}
                    for field, label in _signals_for(factor)
                ],
            }
            for factor in FACTOR_LABELS
        ],
        "grouping": [{"field": f, "label": l} for f, l in GROUPING_SIGNALS],
        "output": [{"field": f, "label": l} for f, l in OUTPUT_SIGNALS],
        "bands": [{"field": f, "label": l} for f, l in BAND_SIGNALS],
        "min": MIN_VALUE,
        "max": MAX_VALUE,
    }
