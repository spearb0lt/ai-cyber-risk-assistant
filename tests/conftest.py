"""Test environment.

The suite must assert the same things on a laptop with a populated .env and on
a CI runner with none, so provider credentials are stripped before the app is
imported. Anything that depends on a real key belongs in a manual check, not
here.
"""
from __future__ import annotations

import os

# Read before app.settings imports dotenv, which happens on first app import.
os.environ["CRA_IGNORE_DOTENV"] = "1"
for name in (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "OMNIROUTER_API_KEY",
    "OPENAI_API_KEY",
    "HUGGINGFACE_API_KEY",
    "HF_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
):
    os.environ.pop(name, None)
