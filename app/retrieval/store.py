"""On disk vector index for the NIST chunks.

Deliberately not ChromaDB, FAISS or Qdrant. The corpus is 1,602 chunks of 384
floats, which is 2.3 MB: a full cosine pass over it is a single numpy matrix
multiply taking well under a millisecond. An approximate nearest neighbour
index would add a dependency and an approximation in order to make an already
instant, already exact search slower and less accurate. At a hundred times this
size the trade would flip, and the interface here would not have to change.

The index records which embedder produced it. Searching a 384 dimension index
with a 768 dimension query is a silent correctness bug, so it is refused.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .. import settings
from ..reference.nist import Chunk

INDEX_NAME = "nist_sp800_53"


def paths(embedder_id: str, directory: Path | None = None) -> tuple[Path, Path]:
    base = directory or settings.INDEX_DIR
    return (
        base / f"{INDEX_NAME}_{embedder_id}.npz",
        base / f"{INDEX_NAME}_chunks.jsonl",
    )


@dataclass
class VectorIndex:
    vectors: np.ndarray  # (n, dim), L2 normalised
    chunks: list[Chunk]
    embedder_id: str
    dim: int
    model_name: str

    def __len__(self) -> int:
        return len(self.chunks)

    def search(self, query_vector: np.ndarray, limit: int = 10) -> list[tuple[int, float]]:
        """Exact cosine similarity. Vectors on both sides are unit length, so
        the dot product is the cosine."""
        if self.vectors.size == 0:
            return []
        vector = np.asarray(query_vector, dtype=np.float32).reshape(-1)
        if vector.shape[0] != self.dim:
            raise ValueError(
                f"Query vector has {vector.shape[0]} dimensions but the index was "
                f"built with {self.dim} by '{self.embedder_id}'. Rebuild the index "
                f"with scripts/build_index.py --embedder {self.embedder_id}."
            )
        scores = self.vectors @ vector
        top = np.argsort(-scores)[:limit]
        return [(int(i), float(scores[i])) for i in top]


def save(
    vectors: np.ndarray,
    chunks: list[Chunk],
    *,
    embedder_id: str,
    dim: int,
    model_name: str,
    directory: Path | None = None,
) -> tuple[Path, Path]:
    vector_path, chunk_path = paths(embedder_id, directory)
    vector_path.parent.mkdir(parents=True, exist_ok=True)

    np.savez_compressed(
        vector_path,
        vectors=np.asarray(vectors, dtype=np.float32),
        meta=np.array(
            json.dumps(
                {
                    "embedder_id": embedder_id,
                    "dim": dim,
                    "model_name": model_name,
                    "count": len(chunks),
                }
            )
        ),
    )
    with open(chunk_path, "w", encoding="utf-8") as handle:
        for chunk in chunks:
            handle.write(json.dumps(chunk.as_dict(), ensure_ascii=False) + "\n")
    return vector_path, chunk_path


def load(embedder_id: str, directory: Path | None = None) -> VectorIndex | None:
    """Load the index for this embedder, or None if it has not been built."""
    vector_path, chunk_path = paths(embedder_id, directory)
    if not vector_path.exists() or not chunk_path.exists():
        return None

    payload = np.load(vector_path, allow_pickle=False)
    meta = json.loads(str(payload["meta"]))
    vectors = payload["vectors"].astype(np.float32)

    chunks: list[Chunk] = []
    with open(chunk_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                chunks.append(Chunk.from_dict(json.loads(line)))

    if len(chunks) != vectors.shape[0]:
        raise ValueError(
            f"Index is inconsistent: {vectors.shape[0]} vectors against "
            f"{len(chunks)} chunks. Rebuild it with scripts/build_index.py."
        )

    return VectorIndex(
        vectors=vectors,
        chunks=chunks,
        embedder_id=meta.get("embedder_id", embedder_id),
        dim=int(meta.get("dim", vectors.shape[1] if vectors.size else 0)),
        model_name=meta.get("model_name", ""),
    )


def load_chunks_only(directory: Path | None = None) -> list[Chunk]:
    """The chunk text without any vectors, which is all BM25 needs.

    This is what makes lexical-only operation possible when no index has been
    built for the active embedder.
    """
    _, chunk_path = paths("local", directory)
    if not chunk_path.exists():
        return []
    chunks: list[Chunk] = []
    with open(chunk_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                chunks.append(Chunk.from_dict(json.loads(line)))
    return chunks
