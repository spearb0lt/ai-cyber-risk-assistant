"""Hybrid retrieval over NIST SP 800-53.

Dense cosine similarity and BM25 are fused with reciprocal rank fusion. RRF is
used rather than a weighted sum of scores because the two scales are not
comparable: a cosine sits in [-1, 1] while a BM25 score is unbounded and varies
with query length. Fusing ranks instead of scores sidesteps the normalisation
problem entirely and is robust when one retriever is unavailable.

If the embedder cannot load, this degrades to lexical only and says so in
`RetrievalResult.mode`, which the UI and the report both display. Silently
returning worse answers would be the wrong failure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .. import settings
from ..embeddings import registry as embedder_registry
from ..reference import nist
from ..reference.nist import Chunk, Control
from . import bm25, store

# RRF damping. 60 is the value from the original paper and is not sensitive.
RRF_K = 60


@dataclass
class Hit:
    chunk: Chunk
    score: float
    dense_rank: int | None = None
    lexical_rank: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk.chunk_id,
            "control_id": self.chunk.control_id,
            "control_name": self.chunk.control_name,
            "family": self.chunk.family,
            "is_enhancement": self.chunk.is_enhancement,
            "score": round(self.score, 5),
            "dense_rank": self.dense_rank,
            "lexical_rank": self.lexical_rank,
            "text": self.chunk.text,
        }


@dataclass
class RetrievalResult:
    hits: list[Hit]
    mode: str  # "hybrid", "lexical", or "dense"
    note: str = ""
    query: str = ""
    # Fused score per control, populated by best_controls. Kept as a field on
    # the result rather than a third return value so existing callers are
    # untouched. Used to show a reader how close the call between the top two
    # controls actually was.
    control_scores: dict[str, float] = field(default_factory=dict)

    def control_ids(self) -> list[str]:
        seen: list[str] = []
        for hit in self.hits:
            if hit.chunk.control_id not in seen:
                seen.append(hit.chunk.control_id)
        return seen


@dataclass
class Retriever:
    index: store.VectorIndex | None
    chunks: list[Chunk]
    lexical: bm25.Bm25Index
    controls: dict[str, Control]
    embedder_id: str
    mode: str
    note: str = ""
    _dense_failed: bool = field(default=False, repr=False)

    def describe(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "note": self.note,
            "chunks": len(self.chunks),
            "controls": len(self.controls),
            "embedder": self.embedder_id if self.index else "",
            "embedding_model": self.index.model_name if self.index else "",
            "dimensions": self.index.dim if self.index else 0,
        }

    def _dense(self, query: str, limit: int) -> list[tuple[int, float]]:
        if self.index is None or self._dense_failed:
            return []
        try:
            embedder = embedder_registry.get(self.embedder_id)
            vector = embedder.embed([query], is_query=True)[0]
            return self.index.search(vector, limit=limit)
        except Exception as exc:  # noqa: BLE001 - degrade rather than fail
            # One failure is enough to stop trying for this process: the
            # cause is a missing model or a bad key, neither of which is
            # going to resolve between two queries a millisecond apart.
            self._dense_failed = True
            self.mode = "lexical"
            self.note = f"Dense retrieval unavailable, using lexical search only. {exc}"
            return []

    def search(self, query: str, limit: int = 8, pool: int = 25) -> RetrievalResult:
        dense = self._dense(query, pool)
        lexical = self.lexical.search(query, limit=pool)

        fused: dict[int, float] = {}
        dense_ranks: dict[int, int] = {}
        lexical_ranks: dict[int, int] = {}

        for rank, (index, _score) in enumerate(dense, start=1):
            dense_ranks[index] = rank
            fused[index] = fused.get(index, 0.0) + 1.0 / (RRF_K + rank)
        for rank, (index, _score) in enumerate(lexical, start=1):
            lexical_ranks[index] = rank
            fused[index] = fused.get(index, 0.0) + 1.0 / (RRF_K + rank)

        ordered = sorted(fused.items(), key=lambda pair: (-pair[1], pair[0]))[:limit]
        hits = [
            Hit(
                chunk=self.chunks[index],
                score=score,
                dense_rank=dense_ranks.get(index),
                lexical_rank=lexical_ranks.get(index),
            )
            for index, score in ordered
        ]
        mode = self.mode if (dense or self.index is None) else "lexical"
        return RetrievalResult(hits=hits, mode=mode, note=self.note, query=query)

    def best_controls(self, query: str, limit: int = 3, pool: int = 12) -> tuple[list[Control], RetrievalResult]:
        """The most applicable controls for a query, base controls preferred.

        Retrieval returns passages, but a brief needs controls. Passages are
        collapsed to their control, and a base control is promoted above its
        own enhancements: SI-2 Flaw Remediation is the actionable answer, while
        SI-2(3) is detail that only makes sense once SI-2 is being done.
        """
        result = self.search(query, limit=pool, pool=max(pool * 3, 30))

        ranked: dict[str, float] = {}
        for position, hit in enumerate(result.hits):
            weight = 1.0 / (1 + position)
            control_id = hit.chunk.control_id
            ranked[control_id] = ranked.get(control_id, 0.0) + weight
            # Credit the base control for its enhancement's match, so a run of
            # enhancement hits surfaces the base control they belong to.
            if hit.chunk.is_enhancement:
                base = self.controls.get(control_id)
                base_id = base.base_identifier if base else control_id
                if base_id in self.controls and base_id != control_id:
                    ranked[base_id] = ranked.get(base_id, 0.0) + weight * 0.8

        def sort_key(item: tuple[str, float]) -> tuple[float, int]:
            control_id, score = item
            control = self.controls.get(control_id)
            # Enhancements are demoted, not excluded.
            penalty = 1 if (control and control.is_enhancement) else 0
            return (-score, penalty)

        best_ids = [cid for cid, _ in sorted(ranked.items(), key=sort_key)]
        controls = [self.controls[cid] for cid in best_ids if cid in self.controls][:limit]
        result.control_scores = dict(ranked)
        return controls, result


_retriever: Retriever | None = None


def get_retriever(force: bool = False) -> Retriever:
    """Build the retriever once per process."""
    global _retriever
    if _retriever is not None and not force:
        return _retriever

    embedder_id = settings.EMBEDDER
    controls = nist.load_controls()
    index = store.load(embedder_id)

    if index is not None:
        chunks = index.chunks
        mode = "hybrid"
        note = ""
    else:
        # No index for this embedder. The chunk text is still on disk, so
        # lexical search works; if even that is missing, rebuild from the
        # catalogue so the system is never left with nothing.
        chunks = store.load_chunks_only() or nist.build_chunks(controls)
        mode = "lexical"
        note = (
            f"No vector index found for embedder '{embedder_id}'. Retrieval is "
            "lexical only. Run scripts/build_index.py to enable semantic search."
        )

    _retriever = Retriever(
        index=index,
        chunks=chunks,
        lexical=bm25.build([c.text for c in chunks]),
        controls=controls,
        embedder_id=embedder_id,
        mode=mode,
        note=note,
    )
    return _retriever


def reset() -> None:
    global _retriever
    _retriever = None
