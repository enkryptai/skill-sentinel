"""Provider facts that must be known before the heavy CrewAI import.

Kept dependency-free so the CLI can decide whether an API key is required
without paying for (or prematurely triggering) the CrewAI import, which reads
model configuration from the environment at import time.
"""

from __future__ import annotations

# Providers that serve an OpenAI-compatible API from a local (or otherwise
# self-hosted) endpoint. They need no API key, and CrewAI routes them to its
# native OpenAI-compatible client rather than through litellm.
LOCAL_PROVIDER_PREFIXES: tuple[str, ...] = (
    "hosted_vllm/",
    "ollama/",
    "ollama_chat/",
)


def is_local_model(model: str) -> bool:
    """Whether ``model`` names a locally served, keyless provider."""
    return bool(model) and model.startswith(LOCAL_PROVIDER_PREFIXES)
