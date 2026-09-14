"""Concrete provider adapters.

Every gateway here except Gemini speaks the OpenAI chat completions protocol,
so one base class covers Groq, OpenRouter, OmniRouter, OpenAI itself, and any
self hosted gateway a visitor points the adapter at.
"""
from __future__ import annotations

import re
import time
from typing import Any, Iterable

from .. import settings
from . import keyring
from .base import STYLE_RULES, BaseProvider, LLMError, ModelSpec, sanitise_output

# ---------------------------------------------------------------------------
# Model discovery cache
#
# Keyed by credential fingerprint so one visitor's model list is never served
# to another visitor.
# ---------------------------------------------------------------------------

_DISCOVERY_TTL = 900.0
_CACHE_CAP = 64
_discovered: dict[str, tuple[float, list[str]]] = {}


def _cache_key(provider_id: str, api_key: str | None) -> str:
    return f"{provider_id}:{keyring.fingerprint(api_key)}"


def _cache_get(provider_id: str, api_key: str | None) -> list[str] | None:
    entry = _discovered.get(_cache_key(provider_id, api_key))
    if not entry:
        return None
    stamped, models = entry
    if time.time() - stamped > _DISCOVERY_TTL:
        return None
    return models


def _cache_put(provider_id: str, models: list[str], api_key: str | None) -> None:
    if len(_discovered) >= _CACHE_CAP:
        for stale in sorted(_discovered, key=lambda k: _discovered[k][0])[: _CACHE_CAP // 2]:
            _discovered.pop(stale, None)
    _discovered[_cache_key(provider_id, api_key)] = (time.time(), list(models))


def reset_caches() -> None:
    _discovered.clear()


# ---------------------------------------------------------------------------
# Error classification
#
# Matching is done on the exception message rather than on typed SDK
# exceptions, deliberately: an arbitrary OpenAI compatible gateway raises
# whatever its own stack raises, and the text is the only reliable signal.
# ---------------------------------------------------------------------------

_TRANSIENT_MARKERS = (
    "429",
    "resource_exhausted",
    "rate limit",
    "rate_limit",
    "503",
    "unavailable",
    "overloaded",
    "timeout",
    "timed out",
    "502",
    "504",
)


def _is_transient(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _TRANSIENT_MARKERS)


_RETRY_AFTER_RE = re.compile(r"try again in\s*(\d+(?:\.\d+)?)\s*(ms|s|m)\b", re.IGNORECASE)
_RETRY_DELAY_RE = re.compile(r"retry[^0-9]{0,20}(\d+(?:\.\d+)?)\s*s", re.IGNORECASE)


def _retry_delay(message: str, attempt: int) -> float:
    """How long to wait before retrying, honouring the provider's own advice."""
    match = _RETRY_AFTER_RE.search(message)
    if match:
        value = float(match.group(1))
        unit = match.group(2).lower()
        seconds = value / 1000 if unit == "ms" else value * 60 if unit == "m" else value
        return min(seconds + 1.0, 45.0)
    match = _RETRY_DELAY_RE.search(message)
    if match:
        return min(float(match.group(1)) + 1.0, 45.0)
    return min(2.0 * (attempt + 1), 15.0)


def _hint_for(message: str, label: str) -> str:
    lowered = message.lower()
    if any(m in lowered for m in ("401", "unauthor", "invalid api key", "authentication")):
        return f"{label} rejected that key. Check it was copied whole and has not been revoked."
    if any(m in lowered for m in ("429", "quota", "rate limit")):
        return f"{label} is rate limiting this key. Wait a moment, or pick another provider."
    if any(m in lowered for m in ("402", "credit", "billing")):
        return f"{label} reports no credit left on this key."
    if any(m in lowered for m in ("404", "does not exist", "decommission")):
        return "That model id is not available to this key. Pick another model."
    if "context" in lowered and "length" in lowered:
        return "The request was too long for this model's context window."
    return f"Try another model or provider. {label} said: {message[:160]}"


# Models that spend output tokens on hidden reasoning before answering.
_REASONING_MODEL = re.compile(
    r"gpt-oss|qwen3|deepseek-r1|magistral|o1-|o3-|o4-|nemotron|inkling|ling-3|laguna|nex-n",
    re.IGNORECASE,
)


def _compose_system(system: str | None) -> str:
    return f"{system}\n\n{STYLE_RULES}" if system else STYLE_RULES


def _content_text(content: Any) -> str:
    """Flatten the several shapes a gateway may use for message content."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and item.get("text"):
                parts.append(str(item["text"]))
            elif getattr(item, "text", None):
                parts.append(str(item.text))
        return "".join(parts)
    return str(content)


def _extra(provider_id: str) -> Iterable[ModelSpec]:
    """Extra model ids an operator added via <PROVIDER>_EXTRA_MODELS."""
    raw = settings.env(f"{provider_id.upper()}_EXTRA_MODELS") or ""
    for item in raw.split(","):
        model_id = item.strip()
        if model_id:
            yield ModelSpec(model_id, model_id, note="From the server environment")


def _merge(curated: list[ModelSpec], live: list[str], cap: int) -> tuple[ModelSpec, ...]:
    """Curated models this key can actually call, then anything else it offers."""
    live_set = set(live)
    merged: list[ModelSpec] = []
    seen: set[str] = set()
    for spec in curated:
        # An empty live list means discovery failed, not that nothing works.
        if (not live_set or spec.id in live_set) and spec.id not in seen:
            merged.append(spec)
            seen.add(spec.id)
    for model_id in live:
        if model_id not in seen and len(merged) < cap:
            merged.append(ModelSpec(model_id, model_id))
            seen.add(model_id)
    return tuple(merged[:cap])


def _promote(models: tuple[ModelSpec, ...], preferred: str | None) -> tuple[ModelSpec, ...]:
    if not preferred:
        return models
    chosen = [m for m in models if m.id == preferred]
    if not chosen:
        chosen = [ModelSpec(preferred, preferred, note="Set on the server")]
    return tuple(chosen + [m for m in models if m.id != preferred])


# ---------------------------------------------------------------------------
# OpenAI compatible adapters
# ---------------------------------------------------------------------------


class OpenAICompatibleProvider(BaseProvider):
    """Shared adapter for any OpenAI compatible chat completions endpoint."""

    env_base_url: str = ""
    max_attempts: int = 3
    model_cap: int = 20
    curated: list[ModelSpec] = []
    preferred: str | None = None
    accepts_base_url: bool = True
    extra_headers: dict[str, str] = {}

    @property
    def base_url(self) -> str:
        """A visitor may point the adapter at their own compatible gateway."""
        return keyring.base_url_for(self.id) or self.env_base_url

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _client(self):
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise LLMError(
                "The openai package is not installed on the server.", provider=self.id
            ) from exc
        if not self.api_key:
            raise LLMError(self.unavailable_reason(), provider=self.id, hint="Missing API key.")
        return OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=float(settings.REQUEST_TIMEOUT),
            max_retries=0,
            default_headers=self.extra_headers or None,
        )

    def _discover(self) -> list[str]:
        """Ask the gateway which models this key can actually call."""
        if not self.api_key:
            return []
        try:
            client = self._client()
            return [item.id for item in client.models.list().data if getattr(item, "id", None)]
        except Exception:  # noqa: BLE001 - discovery is best effort
            return []

    @property
    def models(self) -> tuple[ModelSpec, ...]:
        api_key = self.api_key
        live = _cache_get(self.id, api_key)
        if live is None:
            live = self._discover()
            _cache_put(self.id, live, api_key)
        return _promote(_merge(list(self.curated), live, self.model_cap), self.preferred)

    def verify(self) -> list[str]:
        """Prove the credential works, and report what it can call."""
        if not self.api_key:
            raise LLMError(self.unavailable_reason(), provider=self.id)
        client = self._client()
        try:
            ids = [item.id for item in client.models.list().data if getattr(item, "id", None)]
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            message = str(exc)
            raise LLMError(
                f"{self.label} did not accept that key.",
                provider=self.id,
                hint=_hint_for(message, self.label),
            ) from exc
        _cache_put(self.id, ids, self.api_key)
        return ids

    def _call(self, messages, *, model, temperature, max_tokens, json_mode) -> str:
        client = self._client()
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if _REASONING_MODEL.search(model):
            kwargs["reasoning_effort"] = "low"
            kwargs["max_tokens"] = max(max_tokens, 8192)

        last_error: Exception | None = None
        for attempt in range(self.max_attempts):
            try:
                response = client.chat.completions.create(**kwargs)
                choice = response.choices[0] if response.choices else None
                message_obj = choice.message if choice else None
                content = _content_text(
                    getattr(message_obj, "content", None) if message_obj else None
                )
                if content.strip():
                    return sanitise_output(content.strip())
                finish = (getattr(choice, "finish_reason", "") or "") if choice else ""
                if finish == "length":
                    raise RuntimeError("The model ran out of output tokens before answering.")
                if finish in ("content_filter", "safety"):
                    raise RuntimeError("The provider's safety filter blocked this response.")
                raise RuntimeError(
                    f"The model returned an empty response (finish reason: {finish or 'none'})."
                )
            except Exception as exc:  # noqa: BLE001 - normalised below
                message = str(exc)
                last_error = exc
                lowered = message.lower()
                # Gateways disagree about request shape. Degrade and retry
                # rather than fail on a parameter the model did not need.
                if json_mode and ("response_format" in lowered or "json_object" in lowered):
                    kwargs.pop("response_format", None)
                    json_mode = False
                    continue
                if "max_completion_tokens" in lowered and "max_tokens" in kwargs:
                    kwargs["max_completion_tokens"] = kwargs.pop("max_tokens")
                    continue
                if "temperature" in lowered and "unsupported" in lowered:
                    kwargs.pop("temperature", None)
                    continue
                if "reasoning_effort" in lowered and "reasoning_effort" in kwargs:
                    kwargs.pop("reasoning_effort", None)
                    continue
                if _is_transient(message) and attempt < self.max_attempts - 1:
                    time.sleep(_retry_delay(message, attempt))
                    continue
                break

        message = str(last_error) if last_error else "Unknown provider error."
        raise LLMError(
            f"{self.label} call failed: {message[:400]}",
            provider=self.id,
            model=model,
            retryable=_is_transient(message),
            hint=_hint_for(message, self.label),
        )

    def generate(
        self,
        prompt: str,
        *,
        model: str,
        system: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:
        messages = [
            {"role": "system", "content": _compose_system(system)},
            {"role": "user", "content": prompt},
        ]
        if json_mode:
            messages[0]["content"] += (
                "\n\nReturn only a single valid JSON value. No prose, no markdown fences."
            )
        return self._call(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )


class GroqProvider(OpenAICompatibleProvider):
    id = "groq"
    label = "Groq"
    docs_url = "https://console.groq.com/keys"
    key_names = ("GROQ_API_KEY",)
    env_base_url = "https://api.groq.com/openai/v1"
    model_cap = 20

    def __init__(self) -> None:
        self.env_key = settings.GROQ_API_KEY
        self.preferred = settings.GROQ_MODEL
        self.curated = [
            ModelSpec("llama-3.3-70b-versatile", "Llama 3.3 70B", note="Strong default, free tier"),
            ModelSpec("openai/gpt-oss-120b", "GPT OSS 120B", note="Best reasoning here"),
            ModelSpec("llama-3.1-8b-instant", "Llama 3.1 8B", note="Fastest, lowest quality"),
        ] + list(_extra(self.id))


class OpenRouterProvider(OpenAICompatibleProvider):
    id = "openrouter"
    label = "OpenRouter"
    docs_url = "https://openrouter.ai/keys"
    key_names = ("OPENROUTER_API_KEY",)
    model_cap = 30
    # OpenRouter attributes traffic by these headers. Neither is a secret.
    extra_headers = {
        "HTTP-Referer": "https://github.com/spearb0lt/ai-cyber-risk-assistant",
        "X-Title": "AI Cyber Risk Assistant",
    }

    def __init__(self) -> None:
        self.env_key = settings.OPENROUTER_API_KEY
        self.env_base_url = settings.OPENROUTER_BASE_URL or "https://openrouter.ai/api/v1"
        self.preferred = settings.OPENROUTER_MODEL
        # Verified against the live catalogue. OpenRouter retires free models
        # without notice, so these are a preference and not a guarantee: any id
        # that has gone is dropped by _merge and discovery fills the gap.
        # Ordered by what actually works, not by size. Most OpenRouter free
        # models either rate limit immediately, refuse structured output, or
        # emit their reasoning instead of the JSON they were asked for. These
        # two were verified to return well formed JSON against this key.
        self.curated = [
            ModelSpec(
                "nex-agi/nex-n2.5-mini:free",
                "Nex N2.5 Mini (free)",
                note="262k context, reliable structured output and quick",
            ),
            ModelSpec(
                "nex-agi/nex-n2.5-pro:free",
                "Nex N2.5 Pro (free)",
                note="262k context, higher quality but can take minutes",
            ),
            ModelSpec(
                "nvidia/nemotron-3-ultra-550b-a55b:free",
                "Nemotron 3 Ultra 550B (free)",
                note="1M context, reasoning model, slower",
            ),
            ModelSpec(
                "nvidia/nemotron-3.5-lightning:free",
                "Nemotron 3.5 Lightning (free)",
                note="1M context, reasoning model",
            ),
            ModelSpec("google/gemma-4-31b-it:free", "Gemma 4 31B (free)", note="262k context"),
        ] + list(_extra(self.id))

    def _discover(self) -> list[str]:
        """List callable models, free ones first.

        OpenRouter serves roughly 450 models, the large majority of them paid.
        A free tier key calling a paid id fails with a 402 that reads like a
        broken deployment, so the free ids are ordered to the front and become
        what the picker defaults to.
        """
        ids = super()._discover()
        free = [i for i in ids if i.endswith(":free")]
        paid = [i for i in ids if not i.endswith(":free")]
        return free + paid


class OmniRouterProvider(OpenAICompatibleProvider):
    """OmniRouter, an OpenAI compatible gateway fronting many providers.

    Its catalogue changes constantly, so there is no useful curated list: the
    picker is filled entirely from whatever the key can actually call.
    """

    id = "omnirouter"
    label = "OmniRouter"
    docs_url = "https://omnirouter.li"
    key_names = ("OMNIROUTER_API_KEY",)
    model_cap = 40

    def __init__(self) -> None:
        self.env_key = settings.OMNIROUTER_API_KEY
        self.env_base_url = settings.OMNIROUTER_BASE_URL or "https://omnirouter.li/v1"
        self.preferred = settings.OMNIROUTER_MODEL
        self.curated = list(_extra(self.id))

    def unavailable_reason(self) -> str:
        return (
            "Paste an OmniRouter API key in Settings, or set OMNIROUTER_API_KEY on "
            "the server. Set OMNIROUTER_BASE_URL if your endpoint differs."
        )


class OpenAIProvider(OpenAICompatibleProvider):
    """OpenAI, and by way of the base URL override any compatible gateway."""

    id = "openai"
    label = "OpenAI compatible"
    docs_url = "https://platform.openai.com/api-keys"
    key_names = ("OPENAI_API_KEY",)
    model_cap = 22

    def __init__(self) -> None:
        self.env_key = settings.OPENAI_API_KEY
        self.env_base_url = settings.OPENAI_BASE_URL or "https://api.openai.com/v1"
        self.preferred = settings.OPENAI_MODEL
        self.curated = [
            ModelSpec("gpt-4o-mini", "GPT-4o mini", note="Cheap and capable"),
            ModelSpec("gpt-4.1-mini", "GPT-4.1 mini"),
        ] + list(_extra(self.id))

    def unavailable_reason(self) -> str:
        return (
            "Paste an OpenAI API key in Settings, or set OPENAI_API_KEY on the server. "
            "Any OpenAI compatible gateway also works if you give its base URL, which "
            "is how to point this at Ollama, LM Studio or vLLM."
        )


# ---------------------------------------------------------------------------
# Gemini, which does not speak the OpenAI protocol
# ---------------------------------------------------------------------------


class GeminiProvider(BaseProvider):
    id = "gemini"
    label = "Google Gemini"
    docs_url = "https://aistudio.google.com/apikey"
    key_names = ("GEMINI_API_KEY", "GOOGLE_API_KEY")
    accepts_base_url = False

    def __init__(self) -> None:
        self.env_key = settings.GEMINI_API_KEY
        self.preferred = settings.GEMINI_MODEL
        self.curated = [
            ModelSpec("gemini-2.5-flash", "Gemini 2.5 Flash", note="Generous free tier"),
            ModelSpec("gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite", note="Fastest"),
            ModelSpec("gemini-2.5-pro", "Gemini 2.5 Pro", note="Highest quality"),
        ] + list(_extra(self.id))

    def is_available(self) -> bool:
        return bool(self.api_key)

    def _client(self):
        try:
            from google import genai
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise LLMError(
                "The google-genai package is not installed on the server.", provider=self.id
            ) from exc
        if not self.api_key:
            raise LLMError(self.unavailable_reason(), provider=self.id, hint="Missing API key.")
        return genai.Client(api_key=self.api_key)

    def _discover(self) -> list[str]:
        try:
            client = self._client()
            out = []
            for model in client.models.list():
                name = (getattr(model, "name", "") or "").replace("models/", "")
                actions = getattr(model, "supported_actions", None) or []
                if name and (not actions or "generateContent" in actions):
                    out.append(name)
            return out
        except Exception:  # noqa: BLE001 - discovery is best effort
            return []

    @property
    def models(self) -> tuple[ModelSpec, ...]:
        api_key = self.api_key
        live = _cache_get(self.id, api_key)
        if live is None:
            live = self._discover()
            _cache_put(self.id, live, api_key)
        # Gemini lists legacy and embedding models too; keep the curated set
        # first and only add live ids that look like current chat models.
        usable = [m for m in live if m.startswith("gemini-") and "embedding" not in m]
        return _promote(_merge(list(self.curated), usable, 18), self.preferred)

    def verify(self) -> list[str]:
        if not self.api_key:
            raise LLMError(self.unavailable_reason(), provider=self.id)
        try:
            ids = self._discover()
            if not ids:
                raise RuntimeError("Gemini returned no models for this key.")
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            message = str(exc)
            raise LLMError(
                "Google Gemini did not accept that key.",
                provider=self.id,
                hint=_hint_for(message, self.label),
            ) from exc
        _cache_put(self.id, ids, self.api_key)
        return ids

    @staticmethod
    def _normalise(model: str) -> str:
        return model.replace("models/", "").strip()

    def generate(
        self,
        prompt: str,
        *,
        model: str,
        system: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:
        from google.genai import types

        client = self._client()
        config = types.GenerateContentConfig(
            system_instruction=_compose_system(system),
            temperature=temperature,
            max_output_tokens=max_tokens,
            response_mime_type="application/json" if json_mode else "text/plain",
        )
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = client.models.generate_content(
                    model=self._normalise(model), contents=prompt, config=config
                )
                text = (getattr(response, "text", "") or "").strip()
                if text:
                    return sanitise_output(text)
                raise RuntimeError("Gemini returned an empty response.")
            except Exception as exc:  # noqa: BLE001 - normalised below
                last_error = exc
                if _is_transient(str(exc)) and attempt < 2:
                    time.sleep(_retry_delay(str(exc), attempt))
                    continue
                break

        message = str(last_error) if last_error else "Unknown provider error."
        raise LLMError(
            f"Gemini call failed: {message[:400]}",
            provider=self.id,
            model=model,
            retryable=_is_transient(message),
            hint=_hint_for(message, self.label),
        )


class HuggingFaceProvider(OpenAICompatibleProvider):
    """Hugging Face's inference router, which speaks the OpenAI protocol."""

    id = "huggingface"
    label = "Hugging Face"
    docs_url = "https://huggingface.co/settings/tokens"
    key_names = ("HUGGINGFACE_API_KEY", "HF_TOKEN")
    model_cap = 30

    def __init__(self) -> None:
        self.env_key = settings.HUGGINGFACE_API_KEY
        self.env_base_url = settings.HUGGINGFACE_BASE_URL or "https://router.huggingface.co/v1"
        self.preferred = settings.HUGGINGFACE_MODEL
        self.curated = [
            ModelSpec("meta-llama/Llama-3.3-70B-Instruct", "Llama 3.3 70B Instruct"),
            ModelSpec("Qwen/Qwen2.5-72B-Instruct", "Qwen2.5 72B Instruct"),
            ModelSpec("deepseek-ai/DeepSeek-V3-0324", "DeepSeek V3", note="Long context"),
        ] + list(_extra(self.id))

    def unavailable_reason(self) -> str:
        return (
            "Paste a Hugging Face access token in Settings, or set HUGGINGFACE_API_KEY "
            "on the server. The token needs inference permission."
        )


_CF_API_ROOT = "https://api.cloudflare.com/client/v4"


class CloudflareProvider(OpenAICompatibleProvider):
    """Cloudflare Workers AI.

    The odd one out: the account id is part of the request URL, so a token
    alone cannot address anything. That second value travels in its own header
    and is validated as strictly alphanumeric, because it is interpolated into
    a path and must not be able to escape its segment.
    """

    id = "cloudflare"
    label = "Cloudflare Workers AI"
    docs_url = "https://dash.cloudflare.com/profile/api-tokens"
    key_names = ("CLOUDFLARE_API_TOKEN",)
    model_cap = 24
    needs_account = True
    accepts_base_url = False

    def __init__(self) -> None:
        self.env_key = settings.CLOUDFLARE_API_TOKEN
        self.env_account = settings.CLOUDFLARE_ACCOUNT_ID
        self.preferred = settings.CLOUDFLARE_MODEL
        # Only ids verified against Cloudflare's own model pages are listed.
        # Anything else the account can call arrives through discovery.
        self.curated = [
            ModelSpec(
                "@cf/openai/gpt-oss-120b",
                "GPT OSS 120B",
                note="128k context, strongest reasoning here",
            ),
            ModelSpec(
                "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
                "Llama 3.3 70B Instruct FP8 Fast",
                note="24k context, quick and capable default",
            ),
            ModelSpec(
                "@cf/meta/llama-4-scout-17b-16e-instruct",
                "Llama 4 Scout 17B",
                note="131k context, natively multimodal",
            ),
            ModelSpec("@cf/qwen/qwen3-30b-a3b-fp8", "Qwen3 30B A3B FP8", note="32k context"),
        ] + list(_extra(self.id))

    @property
    def account_id(self) -> str:
        return keyring.account_for(self.id) or self.env_account or ""

    @property
    def base_url(self) -> str:
        account = self.account_id
        if not account:
            return ""
        return f"{_CF_API_ROOT}/accounts/{account}/ai/v1"

    def is_available(self) -> bool:
        return bool(self.api_key and self.account_id)

    def unavailable_reason(self) -> str:
        if self.api_key and not self.account_id:
            return (
                "Cloudflare also needs your account id, which is part of the request "
                "URL. Add it in Settings, or set CLOUDFLARE_ACCOUNT_ID on the server."
            )
        return (
            "Paste a Cloudflare API token and account id in Settings, or set "
            "CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID on the server. The token "
            "needs the Workers AI permission."
        )

    def _discover(self) -> list[str]:
        """Cloudflare's OpenAI layer has no /models, so its own search API is used."""
        if not (self.api_key and self.account_id):
            return []
        try:
            import requests

            response = requests.get(
                f"{_CF_API_ROOT}/accounts/{self.account_id}/ai/models/search",
                headers={"Authorization": f"Bearer {self.api_key}"},
                params={"per_page": 200, "task": "Text Generation"},
                timeout=15,
            )
            response.raise_for_status()
            payload = response.json()
            return [
                item["name"]
                for item in payload.get("result", [])
                if isinstance(item, dict) and item.get("name")
            ]
        except Exception:  # noqa: BLE001 - discovery is best effort
            return []

    def verify(self) -> list[str]:
        if not self.api_key:
            raise LLMError(self.unavailable_reason(), provider=self.id)
        if not self.account_id:
            raise LLMError(
                "Cloudflare needs an account id as well as a token.",
                provider=self.id,
                hint="Find it on the right of your Cloudflare dashboard overview page.",
            )
        ids = self._discover()
        if not ids:
            raise LLMError(
                "Cloudflare did not accept that token and account id pair.",
                provider=self.id,
                hint="Check the token has the Workers AI permission and the account id is correct.",
            )
        _cache_put(self.id, ids, self.api_key)
        return ids
