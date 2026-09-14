"""Central configuration. Every secret is read from the environment.

Nothing here raises at import time. A missing key simply means the matching
provider reports itself unavailable, so the app boots and runs with whatever
subset of keys is present, including none at all.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
DATA_DIR = BASE_DIR / "data"
DATASET_DIR = DATA_DIR / "dataset"
REFERENCE_DIR = DATA_DIR / "reference"
INDEX_DIR = DATA_DIR / "index"

# Only this project's own .env is read, and only to fill in variables the real
# environment has not already set. A hosted deployment has no .env at all, so
# the platform's environment is the single source of truth there.
if os.environ.get("CRA_IGNORE_DOTENV", "").strip().lower() not in {"1", "true", "yes"}:
    _env_file = BASE_DIR / ".env"
    if _env_file.exists():
        load_dotenv(_env_file, override=False)


def env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return default


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


APP_NAME = env("APP_NAME", default="Cyber Risk Assistant")
APP_TAGLINE = env(
    "APP_TAGLINE",
    default="Prioritised, explainable cyber risk for TawasolPay",
)
ENVIRONMENT = env("ENVIRONMENT", default="production")
DEBUG = env_bool("DEBUG", False)

# Provider credentials. Every one of these may be absent.
GEMINI_API_KEY = env("GEMINI_API_KEY", "GOOGLE_API_KEY")
GROQ_API_KEY = env("GROQ_API_KEY")
OPENROUTER_API_KEY = env("OPENROUTER_API_KEY")
OMNIROUTER_API_KEY = env("OMNIROUTER_API_KEY")
OPENAI_API_KEY = env("OPENAI_API_KEY")

# Optional model preferences, promoted to the top of each picker.
GEMINI_MODEL = env("GEMINI_MODEL")
GROQ_MODEL = env("GROQ_MODEL")
OPENROUTER_MODEL = env("OPENROUTER_MODEL")
OMNIROUTER_MODEL = env("OMNIROUTER_MODEL")
OPENAI_MODEL = env("OPENAI_MODEL")

# Optional gateway overrides.
OPENAI_BASE_URL = env("OPENAI_BASE_URL")
OPENROUTER_BASE_URL = env("OPENROUTER_BASE_URL")
OMNIROUTER_BASE_URL = env("OMNIROUTER_BASE_URL")

# Embeddings. "local" needs no key; "gemini" reuses GEMINI_API_KEY.
EMBEDDER = (env("EMBEDDER", default="local") or "local").lower()
LOCAL_EMBED_MODEL = env("LOCAL_EMBED_MODEL", default="BAAI/bge-small-en-v1.5")
GEMINI_EMBED_MODEL = env("GEMINI_EMBED_MODEL", default="gemini-embedding-001")

ALLOW_CLIENT_KEYS = env_bool("ALLOW_CLIENT_KEYS", True)
REQUEST_TIMEOUT = env_int("REQUEST_TIMEOUT", 120)
CORS_ORIGINS = env("CORS_ORIGINS", default="")

# Analysis tuning.
TOP_N = env_int("TOP_N", 5)
# A diversity cap. Without it the five highest scores can all be the same
# campaign against the same service, which is true but useless to brief.
MAX_RISKS_PER_SERVICE = env_int("MAX_RISKS_PER_SERVICE", 1)

# Reference document locations, refreshed by scripts/fetch_reference_data.py.
KEV_CSV = REFERENCE_DIR / "cisa_kev.csv"
NIST_CSV = REFERENCE_DIR / "nist_sp800_53_r5.csv"
KEV_URL = env(
    "KEV_URL",
    default="https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.csv",
)
NIST_URL = env(
    "NIST_URL",
    default=(
        "https://csrc.nist.gov/CSRC/media/Projects/risk-management/"
        "800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_catalog_load.csv"
    ),
)
