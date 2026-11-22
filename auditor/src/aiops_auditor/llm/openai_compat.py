"""OpenAI-compatible client for vLLM / llama.cpp servers (<=16GB VRAM prod serving)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from aiops_auditor.llm.base import BaseLLMClient, extract_json_object
from aiops_auditor.models import ModelProfile


class OpenAICompatLLMClient(BaseLLMClient):
    def __init__(
        self,
        profile: ModelProfile,
        base_url: str = "http://127.0.0.1:8000/v1",
        api_key: str = "",
    ) -> None:
        super().__init__(profile)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    @property
    def backend_name(self) -> str:
        return "openai_compat"

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def health_check(self) -> bool:
        req = urllib.request.Request(
            f"{self.base_url}/models", headers=self._headers(), method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.profile.model,
            "temperature": self.profile.temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers=self._headers(),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.profile.timeout_sec) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        choices = raw.get("choices", [])
        if not choices:
            raise ValueError("No choices returned by OpenAI-compatible backend")
        content = choices[0].get("message", {}).get("content", "")
        return extract_json_object(content)

