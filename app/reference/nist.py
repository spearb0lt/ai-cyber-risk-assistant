"""NIST SP 800-53 Rev. 5 control catalogue, and its chunking for retrieval.

This is the one document in the system that is genuinely retrieved rather than
queried. There is no key that joins "an internet facing payment gateway with
no EDR" to a control id, so the mapping has to be semantic.

Source: the official control catalogue CSV from csrc.nist.gov, 1,189 controls
(322 base controls plus 867 enhancements). The snapshot in data/reference is
committed; scripts/fetch_reference_data.py refreshes it.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .. import settings

# "AC-2" is a base control; "AC-2(3)" is an enhancement of it.
_ENHANCEMENT_RE = re.compile(r"^([A-Z]{2})-(\d+)\((\d+)\)$")
_BASE_RE = re.compile(r"^([A-Z]{2})-(\d+)$")

FAMILY_NAMES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "Personally Identifiable Information Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


@dataclass(frozen=True)
class Control:
    identifier: str
    name: str
    control_text: str
    discussion: str
    related: str

    @property
    def family(self) -> str:
        return self.identifier[:2].upper()

    @property
    def family_name(self) -> str:
        return FAMILY_NAMES.get(self.family, self.family)

    @property
    def is_enhancement(self) -> bool:
        return bool(_ENHANCEMENT_RE.match(self.identifier))

    @property
    def base_identifier(self) -> str:
        """The base control this belongs to. A base control returns itself."""
        match = _ENHANCEMENT_RE.match(self.identifier)
        return f"{match.group(1)}-{match.group(2)}" if match else self.identifier

    @property
    def citation(self) -> str:
        return f"NIST SP 800-53 Rev. 5 {self.identifier} {self.name}"


@dataclass(frozen=True)
class Chunk:
    """One retrievable passage. Long controls are split so that a match points
    at the specific paragraph rather than at 18,000 characters of prose."""

    chunk_id: str
    control_id: str
    control_name: str
    family: str
    is_enhancement: bool
    part: int
    text: str

    def as_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "family": self.family,
            "is_enhancement": self.is_enhancement,
            "part": self.part,
            "text": self.text,
        }

    @staticmethod
    def from_dict(raw: dict) -> "Chunk":
        return Chunk(
            chunk_id=raw["chunk_id"],
            control_id=raw["control_id"],
            control_name=raw["control_name"],
            family=raw["family"],
            is_enhancement=bool(raw["is_enhancement"]),
            part=int(raw["part"]),
            text=raw["text"],
        )


def _clean(value: str | None) -> str:
    """Collapse the catalogue's heavy internal whitespace without losing structure."""
    text = (value or "").replace("\r\n", "\n").strip()
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


@lru_cache(maxsize=1)
def load_controls(path: str | None = None) -> dict[str, Control]:
    target = Path(path) if path else settings.NIST_CSV
    if not target.exists():
        return {}
    out: dict[str, Control] = {}
    with io.open(target, encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            identifier = (row.get("identifier") or "").strip().upper()
            if not identifier:
                continue
            out[identifier] = Control(
                identifier=identifier,
                name=_clean(row.get("name")),
                control_text=_clean(row.get("control_text")),
                discussion=_clean(row.get("discussion")),
                related=_clean(row.get("related")),
            )
    return out


# Target size for one chunk, in characters. Chosen so a typical control is a
# single chunk (the median control is ~620 characters) while the handful of
# very long ones are split at paragraph boundaries.
CHUNK_CHARS = 1100
CHUNK_OVERLAP_PARAGRAPHS = 1
# A hard ceiling on one piece. bge-small-en-v1.5 truncates at 512 tokens, and
# a chunk carries its header on top of the piece, so 1,500 characters keeps the
# largest chunk near 480 tokens and nothing is silently cut. SA-12 Supply Chain
# Protection is one unbroken 18,000 character paragraph, which is what makes a
# hard cap necessary rather than merely tidy.
CHUNK_HARD_CAP = 1500

_SENTENCE_RE = re.compile(r"(?<=[.;:])\s+")


def _split_long(paragraph: str, cap: int) -> list[str]:
    """Break an oversized paragraph at sentence boundaries."""
    if len(paragraph) <= cap:
        return [paragraph]
    pieces: list[str] = []
    current = ""
    for sentence in _SENTENCE_RE.split(paragraph):
        if current and len(current) + len(sentence) + 1 > cap:
            pieces.append(current.strip())
            current = ""
        # A single sentence longer than the cap is cut on whitespace; this is
        # rare enough that a word boundary is a good enough seam.
        while len(sentence) > cap:
            head = sentence[:cap].rsplit(" ", 1)[0] or sentence[:cap]
            pieces.append(head.strip())
            sentence = sentence[len(head) :].lstrip()
        current = f"{current} {sentence}".strip()
    if current:
        pieces.append(current.strip())
    return [p for p in pieces if p]


def _split_paragraphs(text: str, limit: int) -> list[str]:
    """Group paragraphs into pieces no larger than the limit, where possible."""
    paragraphs: list[str] = []
    for raw in text.split("\n\n"):
        stripped = raw.strip()
        if stripped:
            paragraphs.extend(_split_long(stripped, CHUNK_HARD_CAP))
    if not paragraphs:
        return []

    pieces: list[str] = []
    current: list[str] = []
    size = 0
    for paragraph in paragraphs:
        if size and size + len(paragraph) > limit:
            pieces.append("\n\n".join(current))
            # Carry the previous paragraph forward for context, but only when
            # it is small. Carrying a large one forward is how an overlap
            # window pushes a chunk back over the hard cap.
            tail = current[-CHUNK_OVERLAP_PARAGRAPHS:] if CHUNK_OVERLAP_PARAGRAPHS else []
            current = [p for p in tail if len(p) <= limit // 3]
            size = sum(len(p) for p in current)
        current.append(paragraph)
        size += len(paragraph)
    if current:
        pieces.append("\n\n".join(current))
    return pieces


def build_chunks(controls: dict[str, Control] | None = None) -> list[Chunk]:
    """Turn the catalogue into retrievable passages.

    Each chunk is prefixed with its control id and name. That prefix is part of
    the embedded text on purpose: it carries the family vocabulary ("Flaw
    Remediation", "Boundary Protection") that a query is most likely to match.
    """
    catalogue = controls if controls is not None else load_controls()
    chunks: list[Chunk] = []
    for identifier, control in sorted(catalogue.items()):
        body = control.control_text
        if control.discussion:
            body = f"{body}\n\nDiscussion. {control.discussion}" if body else control.discussion
        if not body:
            body = control.name

        header = f"{control.identifier} {control.name} ({control.family_name})"
        pieces = _split_paragraphs(body, CHUNK_CHARS) or [body]
        for index, piece in enumerate(pieces):
            chunks.append(
                Chunk(
                    chunk_id=f"{identifier}#{index}",
                    control_id=identifier,
                    control_name=control.name,
                    family=control.family,
                    is_enhancement=control.is_enhancement,
                    part=index,
                    text=f"{header}\n{piece}",
                )
            )
    return chunks


def excerpt(control: Control, limit: int = 420) -> str:
    """A short, verbatim quotation from the control, for citation in the brief.

    Verbatim matters: the brief requires guidance to come from the document,
    so what is shown is the document's own words, cut at a sentence boundary.
    """
    text = control.control_text or control.discussion or control.name
    # Some controls state their requirement in a single line. SC-23 is the
    # whole of "Protect the authenticity of communications sessions." Quoting
    # only that is accurate but useless to act on, so the catalogue's own
    # discussion is appended to fill the remaining budget.
    if control.control_text and control.discussion and len(control.control_text) < limit // 2:
        text = f"{control.control_text} {control.discussion}"
    text = re.sub(r"\s*\n\s*", " ", text).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    boundary = max(cut.rfind(". "), cut.rfind("; "))
    if boundary > limit * 0.5:
        return cut[: boundary + 1].strip()
    return cut.rsplit(" ", 1)[0].strip() + "..."
