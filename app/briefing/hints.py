"""Match a risk to the pack's one line remediation hints.

The brief is explicit that `remediation_guidance.csv` is "a hint, not the
answer", and that detailed guidance must come from NIST. Both halves of that
matter. Using the CSV as the answer would fail the exercise; ignoring it
entirely wastes a field the security team actually maintains, and which carries
two things NIST cannot: a P0 to P2 triage priority, and the evidence someone
has to produce to close the ticket.

So it is matched and shown, clearly labelled as the operational starting point
beside the retrieved control, never in place of it. The match is also folded
into the retrieval query, because a hint saying "rotate all VPN admin
credentials" is a strong signal about which control family applies.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from ..ingest.loaders import DataPack, RemediationHint
from ..scoring.engine import ScoredRisk

_WORD_RE = re.compile(r"[a-z0-9]+")
# Grammatical filler only. Security words such as "remote" stay, because they
# genuinely discriminate; how common a term is gets handled by weighting below
# rather than by a hand written stop list.
_NOISE = frozenset("the a an of to and or in for with on at via".split())

# Vulnerability titles use acronyms where the remediation hints spell the same
# thing out. Without expansion, "Fortinet SSL-VPN Heap Buffer Overflow RCE"
# shares only the token "vpn" with "VPN Appliance Remote Code Execution".
_ACRONYMS = {
    "rce": "remote code execution",
    "ssrf": "server side request forgery",
    "ssti": "server side template injection",
    "xss": "cross site scripting",
    "idor": "insecure direct object reference",
    "sqli": "sql injection",
    "lfi": "local file inclusion",
    "rfi": "remote file inclusion",
    "dos": "denial of service",
    "mfa": "multi factor authentication",
    "edr": "endpoint detection response",
    "ad": "active directory",
}


def _tokens(text: str) -> set[str]:
    out: set[str] = set()
    for word in _WORD_RE.findall((text or "").lower()):
        if word in _NOISE or len(word) < 3:
            continue
        out.add(word)
        expansion = _ACRONYMS.get(word)
        if expansion:
            out.update(expansion.split())
    return out


@dataclass(frozen=True)
class HintMatch:
    hint: RemediationHint
    score: float
    matched_on: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.hint.finding_type,
            "recommended_action": self.hint.recommended_action,
            "priority_hint": self.hint.priority_hint,
            "validation_evidence": self.hint.validation_evidence,
            "match_score": round(self.score, 2),
            "matched_on": self.matched_on,
        }


def _weights(pack: DataPack) -> dict[str, float]:
    """How distinctive each token is across the hint corpus.

    "authentication" and "bypass" appear in several finding types, so matching
    on them says almost nothing. "netscaler" and "teamcity" appear once, so
    matching on one is close to conclusive. Weighting by inverse frequency is
    what stops "JetBrains TeamCity Authentication Bypass" from confidently
    matching "VPN Authentication Bypass", which shares both of its generic
    tokens and none of its meaning.
    """
    counts: dict[str, int] = {}
    for hint in pack.hints:
        for token in _tokens(hint.finding_type):
            counts[token] = counts.get(token, 0) + 1
    total = len(pack.hints) or 1
    return {token: math.log(1 + total / count) for token, count in counts.items()}


# A token appearing in this many distinct asset_type values is a category word
# ("server" spans API Server, Build Server, Mail Server and more), not the name
# of a technology, so it must not be allowed to veto a match.
_GENERIC_TYPE_SPREAD = 2


def _product_vocabulary(pack: DataPack) -> set[str]:
    """Tokens that name a technology rather than an attack or a category.

    Derived from the estate's own `vendor_product` and `asset_type` fields
    rather than hand written, so it stays correct if the inventory changes.
    In this pack it separates the three kinds of word cleanly: citrix,
    netscaler, teamcity, jenkins and vpn survive as products; authentication,
    bypass, injection and execution never enter because no asset is named
    after them; and server, web and application are filtered out for spanning
    too many asset types to identify anything.
    """
    type_spread: dict[str, set[str]] = {}
    vendor_tokens: set[str] = set()
    for asset in pack.assets.values():
        vendor_tokens |= _tokens(asset.vendor_product)
        for token in _tokens(asset.asset_type):
            type_spread.setdefault(token, set()).add(asset.asset_type)

    generic = {t for t, kinds in type_spread.items() if len(kinds) >= _GENERIC_TYPE_SPREAD}
    return (vendor_tokens | set(type_spread)) - generic


def match(risk: ScoredRisk, pack: DataPack, threshold: float = 0.55) -> HintMatch | None:
    """Best hint for this risk, or None when nothing is close enough.

    Two conditions, both necessary.

    First, the risk must cover enough of what makes the hint distinctive,
    measured by inverse frequency across the hint corpus.

    Second, if the hint names a product, the risk must involve that product.
    Without this, "JetBrains TeamCity Authentication Bypass" matches "VPN
    Authentication Bypass" at 0.67, because two of the hint's three tokens are
    generic attack vocabulary and only the product word distinguishes them.
    Showing a VPN credential rotation procedure against a build server is
    exactly the kind of confident wrong answer worth engineering against.
    """
    if not pack.hints:
        return None

    # The vulnerability's own words are the primary evidence. The asset counts
    # as supporting context, because a hint written as "Build Server Arbitrary
    # File Read" is about a build server and that fact lives in asset_type
    # rather than in the CVE's name.
    direct = _tokens(risk.vulnerability.vulnerability_name) | _tokens(
        risk.vulnerability.affected_component
    )
    contextual = _tokens(risk.asset.asset_type) | _tokens(risk.asset.vendor_product)
    target = direct | contextual
    if not target:
        return None

    weights = _weights(pack)
    products = _product_vocabulary(pack)
    best: HintMatch | None = None
    best_rank: tuple[float, float] = (0.0, 0.0)

    for hint in pack.hints:
        candidate = _tokens(hint.finding_type)
        if not candidate:
            continue
        overlap = target & candidate
        if not overlap:
            continue

        # A product the hint names but the risk does not have is a veto, not a
        # deduction. There is no amount of shared attack vocabulary that makes
        # a VPN procedure right for a build server.
        hint_products = candidate & products
        if hint_products and not (hint_products <= target):
            continue

        available = sum(weights.get(t, 1.0) for t in candidate)
        matched = sum(weights.get(t, 1.0) for t in overlap)
        score = matched / available if available else 0.0
        # Two hints can both cover a finding completely. "Citrix NetScaler
        # Session Token Leak" and "Load Balancer Session Token Leak" both fit
        # CitrixBleed on a load balancer, and the first is the better answer
        # because it names what the finding itself names. Ties therefore break
        # toward the hint grounded in the vulnerability rather than the asset.
        specificity = sum(weights.get(t, 1.0) for t in (overlap & direct))
        rank = (score, specificity)
        if best is None or rank > best_rank:
            best = HintMatch(hint=hint, score=score, matched_on=", ".join(sorted(overlap)))
            best_rank = rank

    if best and best.score >= threshold:
        return best
    return None


def query_text(hint_match: HintMatch | None) -> str:
    """The hint's own words, for folding into the NIST retrieval query."""
    if not hint_match:
        return ""
    return f"{hint_match.hint.finding_type} {hint_match.hint.recommended_action}"
