"""LLM adapter package for Ollama, vLLM/OpenAI-compatible APIs, and heuristic fallback."""

from aiops_auditor.llm.base import BaseLLMClient, create_llm_client, extract_json_object

__all__ = ["BaseLLMClient", "create_llm_client", "extract_json_object"]

