"""Embedding backends.

Two are supported and they are not interchangeable at query time: an index
built with one model cannot be searched with another, because the vectors live
in different spaces. Each embedder therefore carries an `id` and a `dim`, and
the index records which one produced it. Mismatches are refused loudly rather
than returning quiet nonsense.
"""
from __future__ import annotations

from typing import Sequence

import numpy as np

from .. import settings
from ..llm.base import LLMError


class BaseEmbedder:
    id: str = ""
    label: str = ""
    dim: int = 0

    def available(self) -> tuple[bool, str]:
        """Whether this backend can run here, and why not if it cannot."""
        raise NotImplementedError

    def embed(self, texts: Sequence[str], *, is_query: bool = False) -> np.ndarray:
        """Return L2 normalised vectors, shape (len(texts), dim)."""
        raise NotImplementedError


def _normalise(matrix: np.ndarray) -> np.ndarray:
    """L2 normalise so a dot product is a cosine similarity."""
    matrix = np.asarray(matrix, dtype=np.float32)
    if matrix.ndim == 1:
        matrix = matrix.reshape(1, -1)
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (matrix / norms).astype(np.float32)


class LocalEmbedder(BaseEmbedder):
    """BAAI/bge-small-en-v1.5 through ONNX runtime.

    Chosen over sentence-transformers because it needs no torch: about 21 MB of
    wheels and a 130 MB model against roughly 900 MB, which is the difference
    between fitting a free 512 MB instance and not.
    """

    id = "local"
    label = "bge-small-en-v1.5 (local ONNX)"
    dim = 384

    def __init__(self, model_name: str | None = None) -> None:
        self.model_name = model_name or settings.LOCAL_EMBED_MODEL
        self.cache_dir = settings.EMBED_CACHE_DIR
        self._model = None

    def available(self) -> tuple[bool, str]:
        try:
            import fastembed  # noqa: F401
        except ImportError:
            return False, "The fastembed package is not installed on this server."
        return True, ""

    def _load(self):
        if self._model is None:
            try:
                from fastembed import TextEmbedding
            except ImportError as exc:  # pragma: no cover - dependency guard
                raise LLMError(
                    "The fastembed package is not installed, so local embeddings "
                    "are unavailable. Retrieval falls back to lexical search."
                ) from exc
            # Downloads once on first use, then cached on disk. The cache
            # directory is passed explicitly because fastembed ignores HF_HOME
            # and would otherwise land in the system temp directory.
            kwargs = {"model_name": self.model_name}
            if self.cache_dir:
                kwargs["cache_dir"] = self.cache_dir
            self._model = TextEmbedding(**kwargs)
        return self._model

    def embed(self, texts: Sequence[str], *, is_query: bool = False) -> np.ndarray:
        items = list(texts)
        if not items:
            return np.zeros((0, self.dim), dtype=np.float32)
        model = self._load()
        # bge models are trained with an instruction prefix on the query side
        # only. Omitting it measurably degrades retrieval.
        if is_query:
            items = [f"Represent this sentence for searching relevant passages: {t}" for t in items]
        vectors = list(model.embed(items))
        return _normalise(np.vstack(vectors))


class GeminiEmbedder(BaseEmbedder):
    """Gemini embedding API. Needs a key, so it is not the default."""

    id = "gemini"
    label = "gemini-embedding-001"
    dim = 768

    def __init__(self) -> None:
        self.model_name = settings.GEMINI_EMBED_MODEL

    def available(self) -> tuple[bool, str]:
        try:
            import google.genai  # noqa: F401
        except ImportError:
            return False, "The google-genai package is not installed on this server."
        from ..llm import keyring

        if not (keyring.key_for("gemini") or settings.GEMINI_API_KEY):
            return False, "Gemini embeddings need GEMINI_API_KEY, or a key pasted in Settings."
        return True, ""

    def embed(self, texts: Sequence[str], *, is_query: bool = False) -> np.ndarray:
        items = list(texts)
        if not items:
            return np.zeros((0, self.dim), dtype=np.float32)

        from google import genai
        from google.genai import types

        from ..llm import keyring

        api_key = keyring.key_for("gemini") or settings.GEMINI_API_KEY
        if not api_key:
            raise LLMError("No Gemini key is available for embedding.")
        client = genai.Client(api_key=api_key)

        vectors: list[list[float]] = []
        # The API caps how many inputs one call accepts.
        for start in range(0, len(items), 100):
            batch = items[start : start + 100]
            response = client.models.embed_content(
                model=self.model_name,
                contents=batch,
                config=types.EmbedContentConfig(
                    task_type="RETRIEVAL_QUERY" if is_query else "RETRIEVAL_DOCUMENT",
                    output_dimensionality=self.dim,
                ),
            )
            vectors.extend([e.values for e in response.embeddings])
        return _normalise(np.array(vectors, dtype=np.float32))
