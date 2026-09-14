"""FastAPI application."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import settings
from .api.routes import router
from .llm import LLMError

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("cyber-risk-assistant")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Build the analysis during startup rather than on the first request. On a
    # free instance that sleeps, this moves the several seconds of ingest,
    # scoring and retrieval into the cold start the platform is already
    # waiting on, so the first visitor gets an immediate answer.
    from .briefing.analysis import analyse

    try:
        current = analyse()
        logger.info(
            "analysis ready: %d risks, retrieval=%s, kev=%d entries, %d ms",
            len(current.briefs),
            current.retrieval["mode"],
            current.kev_meta["entries"],
            current.built_in_ms,
        )
    except Exception:  # noqa: BLE001 - never block startup on it
        logger.exception("analysis could not be prebuilt; it will be retried per request")
    yield


app = FastAPI(
    title=f"{settings.APP_NAME} API",
    description="Prioritised, explainable cyber risk from structured data and retrieved NIST guidance.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

origins = [o.strip() for o in (settings.CORS_ORIGINS or "").split(",") if o.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["*"],
        # Wildcard so the browser preflight permits the custom X-LLM-* headers.
        allow_headers=["*"],
    )


@app.middleware("http")
async def timing(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed = (time.perf_counter() - started) * 1000
    response.headers["X-Response-Time"] = f"{elapsed:.0f}ms"
    if request.url.path.startswith("/api/"):
        # An API response can depend on the caller's own API key, so it must
        # never be held in a shared cache along the way.
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(LLMError)
async def llm_error_handler(_request: Request, exc: LLMError):
    return JSONResponse(status_code=502, content={"error": exc.to_dict()})


@app.exception_handler(Exception)
async def unhandled_handler(_request: Request, exc: Exception):
    logger.exception("unhandled error")
    payload = {"error": {"message": "Something went wrong on the server."}}
    if settings.DEBUG:
        payload["error"]["detail"] = str(exc)
    return JSONResponse(status_code=500, content=payload)


app.include_router(router, prefix="/api")

# Static front end. index.html, app.js and styles.css are served with
# no-cache so a redeploy is picked up without a hard refresh.
REVALIDATE = {"Cache-Control": "no-cache"}

if settings.WEB_DIR.exists():
    assets = settings.WEB_DIR / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(settings.WEB_DIR / "index.html", headers=REVALIDATE)

    @app.get("/app.js", include_in_schema=False)
    async def app_js() -> FileResponse:
        return FileResponse(settings.WEB_DIR / "app.js", headers=REVALIDATE)

    @app.get("/styles.css", include_in_schema=False)
    async def styles() -> FileResponse:
        return FileResponse(settings.WEB_DIR / "styles.css", headers=REVALIDATE)

    @app.get("/{path:path}", include_in_schema=False)
    async def spa_fallback(path: str):
        if path.startswith("api/"):
            return JSONResponse(status_code=404, content={"error": {"message": "Not found."}})
        return FileResponse(settings.WEB_DIR / "index.html", headers=REVALIDATE)
