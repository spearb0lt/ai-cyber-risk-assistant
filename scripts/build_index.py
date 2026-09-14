"""Chunk NIST SP 800-53 and embed it into a searchable index.

    python scripts/build_index.py                     # local ONNX, the default
    python scripts/build_index.py --embedder gemini   # Gemini embedding API

The resulting index is committed to the repository so a deployment does not
have to embed 1,600 passages on a cold start.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np  # noqa: E402

from app import settings  # noqa: E402
from app.embeddings import registry as embedder_registry  # noqa: E402
from app.reference import nist  # noqa: E402
from app.retrieval import store  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--embedder",
        default=settings.EMBEDDER,
        choices=embedder_registry.known(),
        help="Which embedding backend to build with (default: %(default)s).",
    )
    parser.add_argument(
        "--batch-size", type=int, default=128, help="Passages per embedding call."
    )
    args = parser.parse_args()

    controls = nist.load_controls()
    if not controls:
        print(
            f"No NIST catalogue at {settings.NIST_CSV}.\n"
            "Run: python scripts/fetch_reference_data.py",
            file=sys.stderr,
        )
        return 1

    chunks = nist.build_chunks(controls)
    print(f"Catalogue : {len(controls)} controls from {settings.NIST_CSV.name}")
    print(f"Chunks    : {len(chunks)} passages, longest {max(len(c.text) for c in chunks)} chars")

    embedder = embedder_registry.get(args.embedder)
    ok, reason = embedder.available()
    if not ok:
        print(f"\nEmbedder '{args.embedder}' is unavailable: {reason}", file=sys.stderr)
        return 1
    print(f"Embedder  : {embedder.label} ({embedder.dim} dimensions)")

    started = time.time()
    vectors: list[np.ndarray] = []
    total = len(chunks)
    for start in range(0, total, args.batch_size):
        batch = chunks[start : start + args.batch_size]
        vectors.append(embedder.embed([c.text for c in batch]))
        done = min(start + args.batch_size, total)
        print(f"  embedded {done}/{total}", end="\r", flush=True)
    matrix = np.vstack(vectors) if vectors else np.zeros((0, embedder.dim), dtype=np.float32)
    elapsed = time.time() - started
    print(f"  embedded {total}/{total} in {elapsed:.1f}s      ")

    if matrix.shape[1] != embedder.dim:
        print(
            f"\nEmbedder reported {embedder.dim} dimensions but returned "
            f"{matrix.shape[1]}. Refusing to write a mislabelled index.",
            file=sys.stderr,
        )
        return 1

    vector_path, chunk_path = store.save(
        matrix,
        chunks,
        embedder_id=embedder.id,
        dim=embedder.dim,
        model_name=getattr(embedder, "model_name", embedder.label),
    )
    size_mb = vector_path.stat().st_size / 1e6
    print(f"\nWrote {vector_path.name} ({size_mb:.2f} MB) and {chunk_path.name}")

    # Prove the index answers before declaring success.
    index = store.load(embedder.id)
    if index is None:
        print("Index did not load back. Something is wrong.", file=sys.stderr)
        return 1
    probe = "session token leak allows authentication bypass on a load balancer"
    hits = index.search(embedder.embed([probe], is_query=True)[0], limit=3)
    print(f"\nSanity probe: {probe!r}")
    for position, (row, score) in enumerate(hits, start=1):
        chunk = index.chunks[row]
        print(f"  {position}. {chunk.control_id:<10} {chunk.control_name[:52]:<52} {score:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
