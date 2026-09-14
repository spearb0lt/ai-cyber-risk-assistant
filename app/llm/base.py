"""Provider-neutral contracts for the LLM layer."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Sequence

from . import keyring

# One global style rule appended to every system prompt, so generated prose
# reads the same regardless of which provider answered.
STYLE_RULES = (
    "Formatting rules that override any other style preference:\n"
    "1. Write plain, factual British English for a technical manager.\n"
    "2. Never use em dashes or en dashes. Use a comma, a colon, a full stop, "
    "or the word 'to' for ranges.\n"
    "3. Do not open with filler such as 'Certainly' or 'Of course'.\n"
    "4. Never invent a CVE id, a control id, an asset name or a number. Use "
    "only what the supplied evidence contains."
)


class LLMError(RuntimeError):
    """Raised when a provider call cannot be completed."""

    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        model: str = "",
        status: int | None = None,
        retryable: bool = False,
        hint: str = "",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.model = model
        self.status = status
        self.retryable = retryable
        self.hint = hint

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "provider": self.provider,
            "model": self.model,
            "status": self.status,
            "retryable": self.retryable,
            "hint": self.hint,
        }


@dataclass(frozen=True)
class ModelSpec:
    id: str
    label: str
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label, "note": self.note}


@dataclass
class ProviderStatus:
    id: str
    label: str
    available: bool
    reason: str = ""
    models: Sequence[ModelSpec] = field(default_factory=tuple)
    default_model: str = ""
    docs_url: str = ""
    key_names: Sequence[str] = field(default_factory=tuple)
    # "client" when this request supplied the key, "server" when the key comes
    # from the deployment's environment, "" when there is no key at all.
    key_source: str = ""
    # True for adapters that accept a custom OpenAI compatible base URL.
    accepts_base_url: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "available": self.available,
            "reason": self.reason,
            "models": [m.as_dict() for m in self.models],
            "default_model": self.default_model,
            "docs_url": self.docs_url,
            "key_names": list(self.key_names),
            "key_source": self.key_source,
            "accepts_base_url": self.accepts_base_url,
        }


_FENCE_RE = re.compile(r"^```(?:json|JSON)?\s*|\s*```$")

# Models ignore style instructions often enough that the dash rule is also
# enforced here, on every response. Built from code points so that no source
# file in this project contains one of these characters itself.
_DASH = "".join(chr(code) for code in (0x2013, 0x2014, 0x2012, 0x2015))
_RANGE_DASH_RE = re.compile(rf"(?<=\d)\s*[{_DASH}]\s*(?=\d)")
_LEADING_DASH_RE = re.compile(rf"(?m)^([ \t]*)[{_DASH}][ \t]+")
_SPACED_DASH_RE = re.compile(rf"[ \t]+[{_DASH}][ \t]+")
_ANY_DASH_RE = re.compile(rf"[{_DASH}]")


def sanitise_output(text: str) -> str:
    """Replace typographic dashes with plain ASCII punctuation."""
    if not text:
        return text
    cleaned = _RANGE_DASH_RE.sub(" to ", text)
    cleaned = _LEADING_DASH_RE.sub(lambda m: m.group(1) + "- ", cleaned)
    cleaned = _SPACED_DASH_RE.sub(", ", cleaned)
    cleaned = _ANY_DASH_RE.sub("-", cleaned)
    return cleaned


def coerce_json(raw: str) -> Any:
    """Parse model output that is meant to be JSON but may carry noise."""
    if raw is None:
        raise ValueError("Model returned no content.")
    text = raw.strip()
    if not text:
        raise ValueError("Model returned an empty response.")

    text = _FENCE_RE.sub("", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Locate the outermost JSON object or array in the response.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue

    raise ValueError(f"Model did not return valid JSON. First 300 characters: {text[:300]!r}")


class BaseProvider:
    """Interface every provider adapter implements.

    An adapter is a process wide singleton, so the credential cannot live on
    the instance. `api_key` prefers the key the current request brought and
    falls back to the one the deployment holds in its environment, which lets
    the same object serve a bring your own key visitor and a server key
    deployment without either knowing about the other.
    """

    id: str = ""
    label: str = ""
    docs_url: str = ""
    key_names: tuple[str, ...] = ()
    models: tuple[ModelSpec, ...] = ()
    accepts_base_url: bool = False

    # Credential read from the environment at construction. May be None.
    env_key: str | None = None

    @property
    def api_key(self) -> str | None:
        return keyring.key_for(self.id) or self.env_key

    @property
    def key_source(self) -> str:
        if keyring.key_for(self.id):
            return "client"
        return "server" if self.env_key else ""

    def has_server_key(self) -> bool:
        return bool(self.env_key)

    def is_available(self) -> bool:  # pragma: no cover - trivial
        raise NotImplementedError

    def unavailable_reason(self) -> str:
        return (
            f"Paste a {self.label} API key in Settings, or set "
            f"{' or '.join(self.key_names)} on the server."
        )

    def default_model(self) -> str:
        models = self.models
        return models[0].id if models else ""

    def status(self) -> ProviderStatus:
        available = self.is_available()
        return ProviderStatus(
            id=self.id,
            label=self.label,
            available=available,
            reason="" if available else self.unavailable_reason(),
            models=self.models if available else (),
            default_model=self.default_model() if available else "",
            docs_url=self.docs_url,
            key_names=self.key_names,
            key_source=self.key_source,
            accepts_base_url=self.accepts_base_url,
        )

    def verify(self) -> list[str]:
        """Check the credential against the provider and list callable models."""
        raise NotImplementedError

    def generate(
        self,
        prompt: str,
        *,
        model: str,
        system: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:  # pragma: no cover - interface
        raise NotImplementedError
