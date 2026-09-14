"""Pick the embedding backend for this process."""
from __future__ import annotations

from .. import settings
from .providers import BaseEmbedder, GeminiEmbedder, LocalEmbedder

_EMBEDDERS: dict[str, type[BaseEmbedder]] = {
    "local": LocalEmbedder,
    "gemini": GeminiEmbedder,
}

_cache: dict[str, BaseEmbedder] = {}


def get(embedder_id: str | None = None) -> BaseEmbedder:
    key = (embedder_id or settings.EMBEDDER or "local").lower()
    if key not in _EMBEDDERS:
        raise ValueError(
            f"Unknown embedder '{key}'. Choose one of: {', '.join(sorted(_EMBEDDERS))}."
        )
    if key not in _cache:
        _cache[key] = _EMBEDDERS[key]()
    return _cache[key]


def reset() -> None:
    _cache.clear()


def known() -> list[str]:
    return sorted(_EMBEDDERS)
