"""Abstract LLM client interface, JSON parsing utilities, and profile factory."""

from __future__ import annotations

import abc
import json
import os
import re
from typing import Any

from aiops_auditor.models import ModelProfile

THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)


def extract_json_object(raw_text: str) -> dict[str, Any]:
    """Robustly extract a JSON object from LLM output (handles DeepSeek <think> blocks and fences)."""
    cleaned = THINK_BLOCK_RE.sub("", raw_text or "").strip()
    if not cleaned:
        raise ValueError("Empty LLM response")

    # 1. Direct JSON parse
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # 2. Markdown code fence
    fence_match = JSON_FENCE_RE.search(cleaned)
    if fence_match:
        parsed = json.loads(fence_match.group(1))
        if isinstance(parsed, dict):
            return parsed

    # 3. Balanced outermost braces fallback
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        parsed = json.loads(cleaned[start : end + 1])
        if isinstance(parsed, dict):
            return parsed

    raise ValueError(f"Could not extract valid JSON object from LLM output: {cleaned[:200]!r}")


class BaseLLMClient(abc.ABC):
    """Base interface implemented by all model runtime adapters."""

    def __init__(self, profile: ModelProfile) -> None:
        self.profile = profile

    @property
    @abc.abstractmethod
    def backend_name(self) -> str:
        """Identifier of the concrete backend."""

    @abc.abstractmethod
    def health_check(self) -> bool:
        """Return True if the backend is reachable and ready."""

    @abc.abstractmethod
    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """Run a defensive audit inference call and return parsed JSON."""


def create_llm_client(profile: ModelProfile) -> BaseLLMClient:
    """Instantiate the appropriate LLM adapter for the requested model profile."""
    from aiops_auditor.llm.heuristic_fallback import HeuristicLLMClient
    from aiops_auditor.llm.ollama_client import OllamaLLMClient
    from aiops_auditor.llm.openai_compat import OpenAICompatLLMClient

    if profile.backend == "heuristic":
        return HeuristicLLMClient(profile)
    if profile.backend == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        return OllamaLLMClient(profile, base_url=base_url)
    if profile.backend == "openai_compat":
        base_url = os.getenv("VLLM_BASE_URL", "http://127.0.0.1:8000/v1")
        api_key = os.getenv("VLLM_API_KEY", "")
        return OpenAICompatLLMClient(profile, base_url=base_url, api_key=api_key)

    raise ValueError(f"Unsupported LLM backend '{profile.backend}' in profile '{profile.name}'")

