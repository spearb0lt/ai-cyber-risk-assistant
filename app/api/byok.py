"""Bind a request's own provider credentials, if it brought any.

Attached as a router wide dependency so every endpoint runs with the caller's
keys in scope and no endpoint has to remember to ask for them.
"""
from __future__ import annotations

from fastapi import Request

from .. import settings
from ..llm import keyring

# Only these slugs are accepted. An unrecognised header is ignored rather than
# forwarded, so a crafted header cannot reach an upstream Authorization value.
ALLOWED_SLUGS = frozenset(
    {"gemini", "groq", "openrouter", "omnirouter", "openai", "huggingface", "cloudflare"}
)
# Providers whose endpoint a visitor may redirect. Gemini is excluded: it is
# not an OpenAI compatible endpoint and has no meaningful base URL override.
ALLOWED_BASE_URL_SLUGS = frozenset(
    {"openai", "openrouter", "omnirouter", "groq", "huggingface"}
)
# Only Cloudflare needs a second credential.
ALLOWED_ACCOUNT_SLUGS = frozenset({"cloudflare"})


async def bind_client_keys(request: Request) -> None:
    if not settings.ALLOW_CLIENT_KEYS:
        keyring.reset()
        return

    keys: dict[str, str] = {}
    base_urls: dict[str, str] = {}
    accounts: dict[str, str] = {}

    for raw_name, raw_value in request.headers.items():
        name = raw_name.lower()
        if name.startswith(keyring.KEY_PREFIX):
            slug = name[len(keyring.KEY_PREFIX) :]
            if slug in ALLOWED_SLUGS:
                cleaned = keyring.clean_key(raw_value)
                if cleaned:
                    keys[slug] = cleaned
        elif name.startswith(keyring.ACCOUNT_PREFIX):
            slug = name[len(keyring.ACCOUNT_PREFIX) :]
            if slug in ALLOWED_ACCOUNT_SLUGS:
                cleaned = keyring.clean_account(raw_value)
                if cleaned:
                    accounts[slug] = cleaned
        elif name.startswith(keyring.BASE_URL_PREFIX):
            slug = name[len(keyring.BASE_URL_PREFIX) :]
            if slug in ALLOWED_BASE_URL_SLUGS:
                cleaned = keyring.clean_base_url(raw_value)
                if cleaned:
                    base_urls[slug] = cleaned

    # Always bind, including the empty case: that is what clears a previous
    # request's credentials from this worker's context.
    keyring.bind(keys, base_urls, accounts)
