"""Parse the MDR advisory that arrived this morning.

The brief says to ingest the threat report, not merely to hold it. It carries
signal the CSV feed does not: it is dated, it is addressed to this company, and
it names the exploit chains a human analyst judged worth waking the CISO for.
A CVE named here is more urgent than the same CVE sitting in a feed of forty
records, because someone decided it applied to TawasolPay specifically.

So it is parsed into campaign sections, each with the CVEs in its exploit
chain, and a risk whose CVE appears in one gets a scoring contribution plus a
verbatim quotation of the paragraph that named it.

The parse is defensive. If the advisory changes shape, this yields nothing and
scoring carries on without it rather than raising.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..llm.base import sanitise_output

# "### 4. IronVeil - "CitrixBleed Exploitation""
_SECTION_RE = re.compile(r"^###\s+\d+\.\s*(.+?)\s*$", re.MULTILINE)
# Identifiers in this pack take three shapes: a real CVE, the pack's synthetic
# CVE-SYN-YYYY-NNNN form, and bare synthetic tags such as CICD-SYN-001.
#
# Order matters. Alternation is first-match, so the four part synthetic form
# has to be tried before the three part real one, or CVE-SYN-2026-0004 matches
# as CVE-SYN-2026 and silently loses its last component.
_ID_RE = re.compile(
    r"\b(?:"
    r"CVE-SYN-[0-9]{4}-[0-9]{3,7}"
    r"|CVE-[0-9]{4}-[0-9]{3,7}"
    r"|[A-Z0-9]{2,10}-SYN-[0-9]{3,4}"
    r")\b"
)
_FIELD_RE = re.compile(r"^\*\*(.+?):\*\*\s*(.+?)\s*$", re.MULTILINE)

# Whatever dash the document used between actor and campaign name. Built from
# code points so no source file in this project contains one of these
# characters itself, matching how app/llm/base.py handles the same problem.
_SEPARATORS = "".join(chr(c) for c in (0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015))
_TRAILING_SEPARATOR_RE = re.compile(rf"[\s{_SEPARATORS}-]+$")


def _split_actor_campaign(heading: str) -> tuple[str, str]:
    """Turn 'IronVeil - "CitrixBleed Exploitation"' into its two parts."""
    quoted = re.search(r'"([^"]+)"', heading)
    campaign = quoted.group(1).strip() if quoted else ""
    actor = heading
    if quoted:
        actor = heading[: quoted.start()]
    # Strip whatever dash character the document used as the separator.
    actor = _TRAILING_SEPARATOR_RE.sub("", actor).strip()
    return actor, campaign


@dataclass(frozen=True)
class AdvisoryCampaign:
    actor: str
    campaign: str
    target_profile: str
    exploit_chain: str
    ransomware: str
    confidence: str
    body: str
    identifiers: tuple[str, ...] = ()

    @property
    def is_ransomware(self) -> bool:
        return self.ransomware.strip().lower().startswith("yes")

    def as_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "campaign": self.campaign,
            "target_profile": self.target_profile,
            "exploit_chain": self.exploit_chain,
            "ransomware": self.ransomware,
            "is_ransomware": self.is_ransomware,
            "confidence": self.confidence,
            "identifiers": list(self.identifiers),
            "body": self.body,
        }


@dataclass
class Advisory:
    campaigns: list[AdvisoryCampaign] = field(default_factory=list)
    title: str = ""
    raw: str = ""
    by_identifier: dict[str, AdvisoryCampaign] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.campaigns)

    def campaign_for(self, identifier: str) -> AdvisoryCampaign | None:
        return self.by_identifier.get((identifier or "").strip().upper())

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "campaigns": [c.as_dict() for c in self.campaigns],
            "identifiers_named": sorted(self.by_identifier),
        }


def _excerpt(body: str, limit: int = 420) -> str:
    """The first substantive paragraph of a section, for quotation."""
    for paragraph in body.split("\n\n"):
        cleaned = " ".join(paragraph.split())
        # Skip the bold key/value header lines and the IOC list.
        if not cleaned or cleaned.startswith("**"):
            continue
        if len(cleaned) > limit:
            cut = cleaned[:limit]
            boundary = cut.rfind(". ")
            return cut[: boundary + 1] if boundary > limit * 0.5 else cut.rsplit(" ", 1)[0] + "..."
        return cleaned
    return ""


def parse(markdown: str) -> Advisory:
    if not markdown or not markdown.strip():
        return Advisory()

    title_match = re.search(r"^#\s+(.+?)\s*$", markdown, re.MULTILINE)
    advisory = Advisory(
        title=sanitise_output(title_match.group(1).strip()) if title_match else "",
        raw=markdown,
    )

    matches = list(_SECTION_RE.finditer(markdown))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        body = markdown[start:end].strip()
        # Sections are separated by horizontal rules; drop the trailing one.
        body = re.sub(r"\n-{3,}\s*$", "", body).strip()

        fields = {k.strip().lower(): v.strip() for k, v in _FIELD_RE.findall(body)}
        actor, campaign = _split_actor_campaign(match.group(1))
        chain = fields.get("exploit chain", "")
        # Identifiers are taken from the exploit chain line only. The prose can
        # mention a CVE in passing, and a passing mention is not a chain.
        identifiers = tuple(dict.fromkeys(_ID_RE.findall(chain.upper())))

        # The source document uses typographic dashes throughout. Everything
        # here is re-presented in the brief and the dashboard rather than
        # quoted for the record, so it goes through the same ASCII
        # normalisation as model output does.
        record = AdvisoryCampaign(
            actor=sanitise_output(actor),
            campaign=sanitise_output(campaign),
            target_profile=sanitise_output(fields.get("target profile", "")),
            exploit_chain=sanitise_output(chain),
            ransomware=sanitise_output(fields.get("ransomware", "")),
            confidence=sanitise_output(fields.get("confidence", "")),
            body=sanitise_output(_excerpt(body)),
            identifiers=identifiers,
        )
        advisory.campaigns.append(record)
        for identifier in identifiers:
            advisory.by_identifier.setdefault(identifier, record)

    return advisory
