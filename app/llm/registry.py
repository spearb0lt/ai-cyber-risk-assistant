"""Provider registry and the single entry point every caller uses.

Routing is strict: the provider and model chosen in the UI are the source of
truth. There is no silent cross provider fallback, so a quota error from the
selected provider surfaces with an actionable hint rather than quietly
producing text from somewhere else.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import keyring
from .base import BaseProvider, LLMError
from .providers import (
    CloudflareProvider,
    GeminiProvider,
    GroqProvider,
    HuggingFaceProvider,
    OmniRouterProvider,
    OpenAIProvider,
    OpenRouterProvider,
)

# Display order in the picker, and therefore the order in which a default is
# chosen: the first provider with a usable key wins. Ordered by measured
# latency on this workload, not alphabetically. Cloudflare writes all five
# narratives in about 45 seconds where the OpenRouter free models take about
# 105, so it leads when both keys are present.
_ORDER: tuple[type[BaseProvider], ...] = (
    GeminiProvider,
    GroqProvider,
    CloudflareProvider,
    OpenRouterProvider,
    OmniRouterProvider,
    OpenAIProvider,
    HuggingFaceProvider,
)

_registry: dict[str, BaseProvider] | None = None


def provider_map() -> dict[str, BaseProvider]:
    global _registry
    if _registry is None:
        _registry = {}
        for cls in _ORDER:
            instance = cls()
            _registry[instance.id] = instance
    return _registry


def reset_registry() -> None:
    """Rebuild adapters, used after the environment changes in tests."""
    global _registry
    _registry = None


def all_status() -> list[dict[str, Any]]:
    return [provider.status().as_dict() for provider in provider_map().values()]


def server_providers() -> list[str]:
    """Providers the deployment itself holds a key for, ignoring the request."""
    return [p.id for p in provider_map().values() if p.has_server_key()]


def client_providers() -> list[str]:
    """Providers the current request brought its own key for."""
    supplied = keyring.supplied()
    return [p.id for p in provider_map().values() if p.id in supplied]


def available_providers() -> list[BaseProvider]:
    return [p for p in provider_map().values() if p.is_available()]


def any_available() -> bool:
    return bool(available_providers())


def default_selection() -> tuple[str, str]:
    """First usable provider and model, used when the client sends nothing."""
    for provider in available_providers():
        model = provider.default_model()
        if model:
            return provider.id, model
    return "", ""


@dataclass
class Selection:
    provider: BaseProvider
    model: str

    @property
    def label(self) -> str:
        return f"{self.provider.label} / {self.model}"


def resolve(provider_id: str | None = None, model: str | None = None) -> Selection:
    """Turn a client supplied provider and model into a usable Selection."""
    providers = provider_map()
    usable = available_providers()

    if not usable:
        raise LLMError(
            "No AI provider key is available for this request.",
            hint=(
                "Open Settings and paste your own API key for Google Gemini, Groq, "
                "OpenRouter, OmniRouter, Cloudflare Workers AI, Hugging Face or any "
                "OpenAI compatible gateway. The key stays in your browser and is sent "
                "only with your own requests."
            ),
        )

    provider_id = (provider_id or "").strip().lower()
    model = (model or "").strip()

    if provider_id:
        provider = providers.get(provider_id)
        if provider is None:
            raise LLMError(f"Unknown provider '{provider_id}'.")
        if not provider.is_available():
            raise LLMError(provider.unavailable_reason(), provider=provider.id)
    else:
        provider = usable[0]

    if not model:
        model = provider.default_model()
    if not model:
        raise LLMError(
            f"{provider.label} has no model available for this key.",
            provider=provider.id,
            hint="Pick another provider, or name a model id explicitly.",
        )
    return Selection(provider=provider, model=model)


def generate(
    prompt: str,
    *,
    provider_id: str | None = None,
    model: str | None = None,
    system: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 2048,
    json_mode: bool = False,
) -> tuple[str, Selection]:
    """Run one completion and report which provider and model answered."""
    selection = resolve(provider_id, model)
    text = selection.provider.generate(
        prompt,
        model=selection.model,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
        json_mode=json_mode,
    )
    return text, selection
