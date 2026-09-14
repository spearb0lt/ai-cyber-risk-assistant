"""HTTP API.

Every endpoint runs under `bind_client_keys`, so provider availability and any
generated prose reflect the calling browser's own keys.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .. import llm, settings
from ..briefing import analysis as analysis_module
from ..briefing import report as report_module
from ..ingest import quality
from ..llm import LLMError
from ..retrieval.hybrid import get_retriever
from .byok import bind_client_keys

router = APIRouter(dependencies=[Depends(bind_client_keys)])


def _fail(exc: LLMError) -> HTTPException:
    return HTTPException(status_code=502, detail={"error": exc.to_dict()})


class VerifyRequest(BaseModel):
    provider: str = Field(..., description="Provider slug, for example 'groq'.")


class BriefRequest(BaseModel):
    provider: str | None = None
    model: str | None = None


@router.get("/health")
def health() -> dict[str, Any]:
    """Cheap liveness check. Used as the platform health probe."""
    current = analysis_module.analyse()
    return {
        "status": "ok",
        "providers_configured": llm.server_providers(),
        "any_provider": llm.any_available(),
        "risks": len(current.briefs),
        "retrieval_mode": current.retrieval["mode"],
        "kev_entries": current.kev_meta["entries"],
    }


@router.get("/config")
def config() -> dict[str, Any]:
    """Everything the front end needs to render itself."""
    provider_id, model_id = llm.default_selection()
    server_keys = llm.server_providers()
    current = analysis_module.analyse()
    return {
        "app_name": settings.APP_NAME,
        "tagline": settings.APP_TAGLINE,
        "providers": llm.all_status(),
        "default_provider": provider_id,
        "default_model": model_id,
        "any_provider": llm.any_available(),
        # Tells the front end this deployment ships no keys of its own, so a
        # visitor who wants model written prose must paste one.
        "allow_client_keys": settings.ALLOW_CLIENT_KEYS,
        "byok_only": settings.ALLOW_CLIENT_KEYS and not server_keys,
        "server_providers": server_keys,
        "client_providers": llm.client_providers(),
        "retrieval": current.retrieval,
        "kev": current.kev_meta,
        "top_n": settings.TOP_N,
    }


@router.post("/providers/verify")
def providers_verify(payload: VerifyRequest) -> dict[str, Any]:
    """Check one provider's key against the provider itself."""
    provider = llm.provider_map().get(payload.provider.strip().lower())
    if provider is None:
        raise HTTPException(
            status_code=404,
            detail={"error": {"message": f"Unknown provider '{payload.provider}'."}},
        )
    try:
        models = provider.verify()
    except LLMError as exc:
        raise _fail(exc) from exc
    status = provider.status().as_dict()
    return {
        "ok": True,
        "provider": provider.id,
        "label": provider.label,
        "key_source": provider.key_source,
        "callable_models": len(models),
        "models": status["models"],
        "default_model": status["default_model"],
    }


@router.get("/analysis")
def get_analysis() -> dict[str, Any]:
    """The full deterministic analysis. Needs no API key."""
    return analysis_module.analyse().as_dict()


@router.post("/analysis/brief")
def post_brief(payload: BriefRequest) -> dict[str, Any]:
    """Rewrite the narratives with a language model, using this caller's key."""
    current = analysis_module.analyse()
    try:
        briefs = analysis_module.enrich(
            current, provider_id=payload.provider, model=payload.model
        )
    except LLMError as exc:
        raise _fail(exc) from exc

    result = current.as_dict()
    result["risks"] = [b.as_dict() for b in briefs]
    # If every narrative fell back, the caller should know why rather than
    # wondering why the prose did not change.
    errors = [b.narrative.error for b in briefs if b.narrative.error]
    result["narrative_errors"] = errors
    result["narrative_source"] = (
        "model" if any(b.narrative.source == "model" for b in briefs) else "deterministic"
    )
    return result


@router.get("/report.md", response_class=PlainTextResponse)
def get_report() -> str:
    """The brief as Markdown, readable without any further processing."""
    return report_module.render(analysis_module.analyse())


@router.post("/report.md", response_class=PlainTextResponse)
def post_report(payload: BriefRequest) -> str:
    """The Markdown brief with model written narratives."""
    current = analysis_module.analyse()
    try:
        briefs = analysis_module.enrich(
            current, provider_id=payload.provider, model=payload.model
        )
    except LLMError as exc:
        raise _fail(exc) from exc
    return report_module.render(current, briefs)


@router.get("/risks")
def list_risks(limit: int = Query(default=0, ge=0, le=500)) -> dict[str, Any]:
    """The full ranked list behind the top 5, for anyone who wants to audit it."""
    current = analysis_module.analyse()
    ranked = current.as_dict()["ranked"]
    return {"total": len(ranked), "ranked": ranked[:limit] if limit else ranked}


@router.get("/intel/unmatched")
def unmatched_intel() -> dict[str, Any]:
    """Threat intel that does not apply to this estate, reported not dropped."""
    current = analysis_module.analyse()
    payload = current.as_dict()
    return {
        "total_intel": len(current.pack.intel),
        "unmatched": payload["unmatched_intel"],
        "note": (
            "These records reference vulnerabilities or techniques with no match in "
            "the current inventory. They contributed nothing to any risk score."
        ),
    }


@router.get("/data-quality")
def data_quality() -> dict[str, Any]:
    current = analysis_module.analyse()
    return quality.summarise(current.issues)


@router.get("/nist/search")
def nist_search(
    q: str = Query(..., min_length=3, description="Free text query."),
    limit: int = Query(default=6, ge=1, le=25),
) -> dict[str, Any]:
    """Search the NIST catalogue directly, to show the retrieval is real."""
    retriever = get_retriever()
    controls, result = retriever.best_controls(q, limit=limit)
    from ..reference.nist import excerpt

    return {
        "query": q,
        "mode": result.mode,
        "note": result.note,
        "controls": [
            {
                "identifier": c.identifier,
                "name": c.name,
                "family_name": c.family_name,
                "citation": c.citation,
                "excerpt": excerpt(c, 500),
                "is_enhancement": c.is_enhancement,
            }
            for c in controls
        ],
        "passages": [h.as_dict() for h in result.hits[:limit]],
    }
