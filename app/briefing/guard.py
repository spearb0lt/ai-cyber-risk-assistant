"""Grounding checks applied to anything a model wrote.

The brief requires that remediation guidance come from the NIST document
rather than the model's memory. Retrieval supplies the document; this module
is what stops the model quietly adding to it.

Three checks, cheap and mechanical:

1. Every NIST control id the text cites must be one that was retrieved for
   this risk. A model asked about patching will happily cite SI-2 from memory
   with slightly wrong wording, and that is exactly the failure the brief is
   asking about.
2. Every CVE id must be one attached to this risk.
3. Asset names must be ones this risk actually covers.

A violation does not silently rewrite the text. It is recorded, the sentence
carrying it is dropped, and the drop is reported, so a reader can see the
system caught something rather than trusting that it did.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# "SI-2", "SI-2(3)", "AC-17 (2)". Word boundaries keep it from matching
# "CVE-2024-21762" or an ordinary hyphenated word.
_CONTROL_RE = re.compile(r"\b([A-Z]{2})-(\d{1,2})(?:\s?\((\d{1,3})\))?\b")
_CVE_RE = re.compile(r"\bCVE-[0-9A-Z]{3,4}-[0-9]{3,7}\b", re.IGNORECASE)

# Two letter prefixes that are real NIST 800-53 families. Without this, "IT-1"
# or "US-2" in ordinary prose would be treated as a fabricated control.
_FAMILIES = frozenset(
    "AC AT AU CA CM CP IA IR MA MP PE PL PM PS PT RA SA SC SI SR".split()
)


@dataclass
class GuardReport:
    text: str
    ok: bool
    removed_sentences: list[str] = field(default_factory=list)
    invented_controls: list[str] = field(default_factory=list)
    invented_cves: list[str] = field(default_factory=list)

    @property
    def violations(self) -> list[str]:
        out = []
        if self.invented_controls:
            out.append(
                "cited NIST controls that were not retrieved: "
                + ", ".join(sorted(set(self.invented_controls)))
            )
        if self.invented_cves:
            out.append(
                "cited CVE ids not present in this risk: "
                + ", ".join(sorted(set(self.invented_cves)))
            )
        return out

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "violations": self.violations,
            "removed_sentences": self.removed_sentences,
        }


def control_ids_in(text: str) -> list[str]:
    """NIST control identifiers mentioned in a piece of text."""
    found: list[str] = []
    for family, number, enhancement in _CONTROL_RE.findall(text or ""):
        if family not in _FAMILIES:
            continue
        identifier = f"{family}-{int(number)}"
        if enhancement:
            identifier += f"({int(enhancement)})"
        if identifier not in found:
            found.append(identifier)
    return found


def cves_in(text: str) -> list[str]:
    out: list[str] = []
    for match in _CVE_RE.findall(text or ""):
        upper = match.upper()
        if upper not in out:
            out.append(upper)
    return out


def _split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    return [p for p in parts if p.strip()]


def check(
    text: str,
    *,
    allowed_controls: Iterable[str],
    allowed_cves: Iterable[str] = (),
) -> GuardReport:
    """Drop any sentence that cites something outside the supplied evidence."""
    allowed_control_set = {c.upper() for c in allowed_controls}
    # An enhancement is acceptable when its base control was retrieved: SI-2(3)
    # is a subsection of SI-2, not a different claim.
    allowed_bases = {re.sub(r"\(\d+\)$", "", c) for c in allowed_control_set}
    allowed_cve_set = {c.upper() for c in allowed_cves}

    kept: list[str] = []
    removed: list[str] = []
    bad_controls: list[str] = []
    bad_cves: list[str] = []

    for sentence in _split_sentences(text):
        offending_controls = [
            identifier
            for identifier in control_ids_in(sentence)
            if identifier.upper() not in allowed_control_set
            and re.sub(r"\(\d+\)$", "", identifier.upper()) not in allowed_bases
        ]
        offending_cves = [
            cve
            for cve in cves_in(sentence)
            if allowed_cve_set and cve not in allowed_cve_set
        ]
        if offending_controls or offending_cves:
            removed.append(sentence)
            bad_controls.extend(offending_controls)
            bad_cves.extend(offending_cves)
            continue
        kept.append(sentence)

    return GuardReport(
        text=" ".join(kept).strip(),
        ok=not removed,
        removed_sentences=removed,
        invented_controls=bad_controls,
        invented_cves=bad_cves,
    )
