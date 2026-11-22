"""Native Ollama HTTP client (supports local CPU small models and <=16GB VRAM GPU models)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from aiops_auditor.llm.base import BaseLLMClient, extract_json_object
from aiops_auditor.models import ModelProfile


class OllamaLLMClient(BaseLLMClient):
    def __init__(self, profile: ModelProfile, base_url: str = "http://127.0.0.1:11434") -> None:
        super().__init__(profile)
        self.base_url = base_url.rstrip("/")

    @property
    def backend_name(self) -> str:
        return "ollama"

    def health_check(self) -> bool:
        req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.profile.model,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.profile.temperature,
                "num_ctx": self.profile.context_window,
            },
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.profile.timeout_sec) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        content = raw.get("message", {}).get("content", "")
        return extract_json_object(content)

