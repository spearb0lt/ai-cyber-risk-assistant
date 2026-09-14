"""Pluggable embedding backends."""
from .providers import BaseEmbedder, GeminiEmbedder, LocalEmbedder
from .registry import get, known, reset

__all__ = ["BaseEmbedder", "GeminiEmbedder", "LocalEmbedder", "get", "known", "reset"]
