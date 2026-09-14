"""BM25 lexical search over the NIST chunks.

Pure Python and dependency free, which is the point: it is the fallback that
keeps retrieval working if the ONNX model cannot load on a small host, and it
is fused with the dense scores the rest of the time.

Lexical search earns its place here beyond redundancy. Control identifiers and
fixed phrases ("flaw remediation", "boundary protection", "session
authenticity") are exactly the sort of rare, precise tokens a dense model
smooths over and BM25 weights heavily.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Sequence

# Terms with no discriminating power in a corpus of security controls. Kept
# deliberately short: over-pruning removes signal from phrases such as
# "least functionality".
_STOPWORDS = frozenset(
    """
    the a an of to and or in for with that this is are be as on by at from it its
    such which if any other all not shall must may can will would should when
    these those their there them then than into upon while also more most each
    """.split()
)

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\-]*")

K1 = 1.5
B = 0.75


def tokenise(text: str) -> list[str]:
    return [
        token
        for token in _TOKEN_RE.findall((text or "").lower())
        if token not in _STOPWORDS and len(token) > 2
    ]


@dataclass
class Bm25Index:
    documents: list[list[str]]
    frequencies: list[Counter]
    lengths: list[int]
    average_length: float
    idf: dict[str, float]

    def search(self, query: str, limit: int = 10) -> list[tuple[int, float]]:
        terms = tokenise(query)
        if not terms:
            return []
        scored: list[tuple[int, float]] = []
        for index, frequency in enumerate(self.frequencies):
            length = self.lengths[index]
            total = 0.0
            for term in terms:
                count = frequency.get(term)
                if not count:
                    continue
                weight = self.idf.get(term)
                if weight is None:
                    continue
                denominator = count + K1 * (1 - B + B * length / self.average_length)
                total += weight * (count * (K1 + 1)) / denominator
            if total > 0:
                scored.append((index, total))
        scored.sort(key=lambda pair: (-pair[1], pair[0]))
        return scored[:limit]


def build(texts: Sequence[str]) -> Bm25Index:
    documents = [tokenise(text) for text in texts]
    frequencies = [Counter(document) for document in documents]
    lengths = [len(document) for document in documents]
    count = len(documents) or 1
    average_length = (sum(lengths) / count) or 1.0

    document_frequency: Counter = Counter()
    for document in documents:
        document_frequency.update(set(document))

    idf = {
        term: math.log(1 + (count - freq + 0.5) / (freq + 0.5))
        for term, freq in document_frequency.items()
    }
    return Bm25Index(
        documents=documents,
        frequencies=frequencies,
        lengths=lengths,
        average_length=average_length,
        idf=idf,
    )
