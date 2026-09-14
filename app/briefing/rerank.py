"""Optional model reranking of retrieved NIST controls.

Why this exists, and what it deliberately does not do.

The brief requires that remediation guidance come from the NIST document and
not from the model's training data. Asking a model "what NIST control applies
to CitrixBleed?" would violate that directly: the answer would be recalled, not
retrieved, and a recalled control id looks identical to a retrieved one while
being unverifiable and sometimes wrong.

Reranking is a different operation. Retrieval still decides which controls are
admissible; the model only reorders a shortlist that similarity search already
produced, and may not add to it. Every returned id is checked against the
candidate set, and anything invented is dropped. The worst case is therefore a
worse ordering of correct controls, never a fabricated one.

It is worth having because similarity and applicability are not the same thing.
Similarity search matches "session token leak" to SC-23 Session Authenticity on
vocabulary. Judging that SC-23 is the *controlling* requirement here, rather
than SI-2 which is merely also true, is a reading task, and a model is better
at it than a cosine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..llm import LLMError, coerce_json, generate
from ..reference.nist import Control, excerpt
from ..scoring.grouping import RiskGroup

SYSTEM = (
    "You are a security control analyst. You are given one risk and a numbered "
    "shortlist of NIST SP 800-53 Rev. 5 controls that a search already "
    "retrieved for it.\n"
    "Your only job is to put that shortlist in the right order, most "
    "applicable first, and say why the top one controls this risk.\n"
    "Hard rules:\n"
    "- Choose only from the numbered shortlist. Never name a control that is "
    "not on it, however relevant you believe it to be.\n"
    "- Judge applicability to this specific risk, not general importance.\n"
    "- Prefer the control that addresses the mechanism of the weakness over "
    "one that addresses process around it."
)


@dataclass
class RerankResult:
    controls: list[Control]
    reason: str = ""
    used_model: bool = False
    provider: str = ""
    model: str = ""
    error: str = ""
    dropped: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "used_model": self.used_model,
            "reason": self.reason,
            "provider": self.provider,
            "model": self.model,
            "error": self.error,
            "dropped": self.dropped,
        }


def _prompt(risk: RiskGroup, controls: list[Control]) -> str:
    lead = risk.lead
    shortlist = "\n".join(
        f"{i}. {c.identifier} {c.name} ({c.family_name})\n   {excerpt(c, 420)}"
        for i, c in enumerate(controls, start=1)
    )
    gaps = []
    if not lead.asset.edr_installed:
        gaps.append("no EDR on the affected asset")
    if not lead.vulnerability.patch_available:
        gaps.append("no vendor patch available")
    if lead.vulnerability.days_open > 30:
        gaps.append(f"open for {lead.vulnerability.days_open} days")
    if lead.asset.is_unowned:
        gaps.append("no owning team assigned")

    return (
        f"RISK\n"
        f"Weakness: {lead.vulnerability.vulnerability_name}\n"
        f"Affected component: {lead.vulnerability.affected_component}\n"
        f"Identifiers: {', '.join(risk.cves)}\n"
        f"Asset type: {lead.asset.asset_type}, "
        f"{'internet facing' if lead.internet_reachable else 'internal only'}\n"
        f"Authentication required to exploit: "
        f"{'yes' if lead.vulnerability.auth_required else 'no'}\n"
        f"Business service: {risk.service_name}\n"
        f"Control gaps: {', '.join(gaps) if gaps else 'none recorded'}\n\n"
        f"SHORTLIST\n{shortlist}\n\n"
        'Return a JSON object with two keys:\n'
        '  "order": an array of the shortlist numbers, most applicable first, '
        "using each number exactly once.\n"
        '  "reason": one sentence, at most 40 words, saying why the first '
        "control is the controlling requirement for this specific risk."
    )


def rerank(
    risk: RiskGroup,
    controls: list[Control],
    *,
    provider_id: str | None = None,
    model: str | None = None,
) -> RerankResult:
    """Reorder retrieved controls by applicability. Never adds or invents one."""
    if len(controls) < 2:
        return RerankResult(controls=list(controls))

    try:
        raw, selection = generate(
            _prompt(risk, controls),
            provider_id=provider_id,
            model=model,
            system=SYSTEM,
            temperature=0.0,
            max_tokens=1200,
            json_mode=True,
        )
    except LLMError as exc:
        return RerankResult(controls=list(controls), error=exc.message)

    try:
        parsed = coerce_json(raw)
        order = parsed.get("order") or []
        reason = str(parsed.get("reason", "")).strip()
    except Exception as exc:  # noqa: BLE001 - any parse problem falls back
        return RerankResult(
            controls=list(controls), error=f"Rerank output could not be parsed: {exc}"
        )

    # Map the model's positions back to controls. Anything out of range or
    # repeated is discarded rather than trusted.
    chosen: list[Control] = []
    seen: set[int] = set()
    dropped: list[str] = []
    for item in order:
        try:
            position = int(item)
        except (TypeError, ValueError):
            dropped.append(str(item))
            continue
        index = position - 1
        if 0 <= index < len(controls) and index not in seen:
            seen.add(index)
            chosen.append(controls[index])
        else:
            dropped.append(str(item))

    # Anything the model left out keeps its retrieval order at the back, so a
    # partial answer still returns the complete candidate set.
    for index, control in enumerate(controls):
        if index not in seen:
            chosen.append(control)

    if not chosen:
        return RerankResult(controls=list(controls), error="Rerank returned no usable order.")

    return RerankResult(
        controls=chosen,
        reason=reason,
        used_model=True,
        provider=selection.provider.id,
        model=selection.model,
        dropped=dropped,
    )
