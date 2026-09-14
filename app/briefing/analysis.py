"""The end to end pipeline: ingest, score, group, retrieve, explain.

Deliberately split in two. `analyse` does everything that needs no API key and
is cached for the process, so the deployed URL answers immediately and
identically for every visitor. `enrich` adds model written prose on top and is
per request, because it depends on whose key is bound.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..ingest import quality
from ..ingest.advisory import Advisory, parse as parse_advisory
from ..ingest.loaders import DataPack, ThreatIntel, load_pack
from ..reference import kev
from ..reference.nist import Control, excerpt
from ..retrieval.hybrid import get_retriever
from ..scoring.engine import ScoredRisk, score_all
from ..scoring.grouping import RiskGroup, group, top_risks
from ..scoring.weights import DEFAULTS, Weights
from . import hints as hints_module
from . import narrative as narrative_module
from . import rerank as rerank_module
from .queries import Facet, facets_for


@dataclass
class RiskBrief:
    risk: RiskGroup
    controls: list[Control]
    control_sources: dict[str, str]  # control id -> which facet retrieved it
    retrieval_mode: str
    narrative: narrative_module.Narrative
    hint: Any = None  # hints.HintMatch, the pack's own one line starting point
    rerank: Any = None  # rerank.RerankResult when model reranking was used

    def as_dict(self) -> dict[str, Any]:
        payload = self.risk.as_dict()
        payload["narrative"] = self.narrative.as_dict()
        payload["retrieval_mode"] = self.retrieval_mode
        payload["hint"] = self.hint.as_dict() if self.hint else None
        payload["control_selection"] = (
            self.rerank.as_dict() if self.rerank else {"used_model": False}
        )
        payload["controls"] = [
            {
                "identifier": c.identifier,
                "name": c.name,
                "family": c.family,
                "family_name": c.family_name,
                "citation": c.citation,
                "excerpt": excerpt(c, 520),
                "full_text": c.control_text,
                "discussion": c.discussion,
                "retrieved_for": self.control_sources.get(c.identifier, ""),
                "is_enhancement": c.is_enhancement,
            }
            for c in self.controls
        ]
        return payload


@dataclass
class Analysis:
    briefs: list[RiskBrief]
    all_scored: list[ScoredRisk]
    unmatched_intel: list[ThreatIntel]
    pack: DataPack
    issues: list[quality.Issue]
    retrieval: dict[str, Any]
    kev_meta: dict[str, Any]
    built_in_ms: int
    advisory: Advisory = field(default_factory=Advisory)
    weights: Weights = DEFAULTS
    generated_at: float = field(default_factory=time.time)

    def summary(self) -> dict[str, Any]:
        counted = len(self.all_scored)
        return {
            "assets": len(self.pack.assets),
            "vulnerabilities": counted,
            "intel_records": len(self.pack.intel),
            "intel_matched": len(self.pack.intel) - len(self.unmatched_intel),
            "intel_unmatched": len(self.unmatched_intel),
            "business_services": len(self.pack.services),
            "internet_exposed_assets": sum(
                1 for a in self.pack.assets.values() if a.internet_exposed
            ),
            "assets_without_edr": sum(
                1 for a in self.pack.assets.values() if not a.edr_installed
            ),
            "kev_confirmed_vulnerabilities": sum(1 for r in self.all_scored if r.kev),
            "advisory_campaigns": len(self.advisory.campaigns),
            "advisory_named_vulnerabilities": sum(1 for r in self.all_scored if r.advisory),
            "ransomware_linked_vulnerabilities": sum(
                1 for r in self.all_scored if r.kev and r.kev.known_ransomware
            ),
            "bands": {
                band: sum(1 for r in self.all_scored if r.band == band)
                for band in ("Critical", "High", "Medium", "Low")
            },
            "data_quality": quality.summarise(self.issues),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "built_in_ms": self.built_in_ms,
            "summary": self.summary(),
            "retrieval": self.retrieval,
            "kev": self.kev_meta,
            "advisory": self.advisory.as_dict(),
            "weights": self.weights.as_dict(),
            "weights_are_default": self.weights.is_default(),
            "weights_changed": {
                k: {"default": a, "current": b}
                for k, (a, b) in self.weights.changed_from_default().items()
            },
            "risks": [b.as_dict() for b in self.briefs],
            "unmatched_intel": [
                {
                    "intel_id": r.intel_id,
                    "threat_actor": r.threat_actor,
                    "campaign_name": r.campaign_name,
                    "target_sector": r.target_sector,
                    "target_region": r.target_region,
                    "matched_cve": r.matched_cve_or_control,
                    "ransomware_association": r.ransomware_association,
                    "confidence": r.confidence,
                    "summary": r.summary,
                }
                for r in self.unmatched_intel
            ],
            "ranked": [
                {
                    "rank": position,
                    "vuln_id": r.vulnerability.vuln_id,
                    "cve": r.vulnerability.cve,
                    "name": r.vulnerability.vulnerability_name,
                    "asset_name": r.asset.asset_name,
                    "business_service": r.service_name,
                    "cvss": r.vulnerability.cvss,
                    "score": round(r.score, 1),
                    "band": r.band,
                    "internet_exposed": r.internet_reachable,
                    "in_kev": bool(r.kev),
                    "in_advisory": r.advisory is not None,
                }
                for position, r in enumerate(self.all_scored, start=1)
            ],
        }


def _retrieve_controls(
    risk: RiskGroup,
    retriever,
    hint_match=None,
    per_facet: int = 2,
    total: int = 4,
):
    """Retrieve NIST controls across the risk's facets and merge them.

    Order matters in the output: the first control is presented as controlling,
    so facets are walked in priority order and the first hit of each is taken
    before any second hit.
    """
    facets = facets_for(risk)
    # The pack's own remediation hint is folded in as an extra facet. It is a
    # one liner written by the security team, so it names the control family in
    # operational language that the vulnerability title often does not.
    hint_query = hints_module.query_text(hint_match)
    if hint_query:
        facets.append(Facet("Team hint", hint_query))

    facet_hits: list[tuple[str, list[Control]]] = []
    modes: set[str] = set()
    for facet in facets:
        controls, result = retriever.best_controls(facet.query, limit=per_facet)
        modes.add(result.mode)
        facet_hits.append((facet.label, controls))

    merged: list[Control] = []
    sources: dict[str, str] = {}
    for depth in range(per_facet):
        for label, controls in facet_hits:
            if depth < len(controls):
                control = controls[depth]
                if control.identifier not in sources:
                    sources[control.identifier] = label
                    merged.append(control)
    mode = "lexical" if "lexical" in modes else ("hybrid" if modes else "none")
    return merged[:total], sources, mode


# One cached analysis per distinct weighting, so the default view is instant
# and a tuned view is only recomputed when its weights actually change.
_cache: dict[tuple, Analysis] = {}
_CACHE_CAP = 12


def analyse(force: bool = False, weights: Weights | None = None) -> Analysis:
    """Everything that needs no API key. Cached per weighting."""
    w = weights or DEFAULTS
    key = w.key()
    if not force and key in _cache:
        return _cache[key]

    started = time.perf_counter()
    pack = load_pack()
    catalogue = kev.load()
    advisory = parse_advisory(pack.advisory)
    scored, unmatched = score_all(pack, catalogue, advisory, w)
    groups = group(scored, w)
    chosen = top_risks(groups, weights=w)
    retriever = get_retriever()

    briefs: list[RiskBrief] = []
    for risk in chosen:
        hint_match = hints_module.match(risk.lead, pack)
        controls, sources, mode = _retrieve_controls(risk, retriever, hint_match)
        briefs.append(
            RiskBrief(
                risk=risk,
                controls=controls,
                control_sources=sources,
                retrieval_mode=mode,
                narrative=narrative_module.write(risk, controls, hint=hint_match, use_llm=False),
                hint=hint_match,
            )
        )

    elapsed = int((time.perf_counter() - started) * 1000)
    analysis = Analysis(
        briefs=briefs,
        all_scored=scored,
        unmatched_intel=unmatched,
        pack=pack,
        issues=quality.inspect(pack),
        retrieval=retriever.describe(),
        kev_meta={
            "entries": len(catalogue),
            "loaded": catalogue.loaded,
            "source": catalogue.source_path,
            "newest_entry": str(catalogue.newest_entry_date() or ""),
            "age_days": catalogue.age_days(),
        },
        built_in_ms=elapsed,
        advisory=advisory,
        weights=w,
    )

    if len(_cache) >= _CACHE_CAP:
        # Keep the default, drop the oldest tuned entry.
        for stale in list(_cache):
            if stale != DEFAULTS.key():
                _cache.pop(stale, None)
                break
    _cache[key] = analysis
    return analysis


def reset() -> None:
    _cache.clear()


def enrich(
    analysis: Analysis,
    *,
    provider_id: str | None = None,
    model: str | None = None,
    rerank_controls: bool = False,
) -> list[RiskBrief]:
    """Rewrite each narrative with a model, using this request's credentials.

    Returns fresh RiskBrief objects rather than mutating the cached analysis,
    because the cache is shared and one visitor's key must not change what
    another visitor sees.

    Raises LLMError when no provider is usable at all. A single risk falling
    back to its composed narrative is a degradation worth absorbing quietly;
    every risk falling back because there is no key is a configuration problem
    the caller asked about explicitly, and should be said out loud.
    """
    from ..llm import resolve

    resolve(provider_id, model)

    out: list[RiskBrief] = []
    for brief in analysis.briefs:
        controls = brief.controls
        sources = brief.control_sources
        reranked = None

        if rerank_controls:
            # Reordering only. The model picks among controls retrieval already
            # admitted and cannot introduce one of its own.
            reranked = rerank_module.rerank(
                brief.risk, controls, provider_id=provider_id, model=model
            )
            controls = reranked.controls

        written = narrative_module.write(
            brief.risk,
            controls,
            hint=brief.hint,
            provider_id=provider_id,
            model=model,
            use_llm=True,
        )
        out.append(
            RiskBrief(
                risk=brief.risk,
                controls=controls,
                control_sources=sources,
                retrieval_mode=brief.retrieval_mode,
                narrative=written,
                hint=brief.hint,
                rerank=reranked,
            )
        )
    return out
