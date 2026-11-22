"""Configuration loader with zero-dependency YAML fallback and env overrides."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aiops_auditor.models import AuditPolicy, ModelProfile, Severity

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"


def _parse_scalar(raw: str) -> Any:
    val = raw.strip()
    if not val:
        return ""
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    lower = val.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower in ("null", "none", "~"):
        return None
    try:
        if "." in val:
            return float(val)
        return int(val)
    except ValueError:
        return val


def _simple_yaml_load(text: str) -> dict[str, Any]:
    """Minimal indentation-based YAML parser for structured config files.

    Used automatically when PyYAML is not installed so the auditor works
    in bare Python environments with zero third-party dependencies.
    """
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(text)
        return loaded if isinstance(loaded, dict) else {}
    except ImportError:
        pass

    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    lines = text.splitlines()
    for idx, raw_line in enumerate(lines):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        container = stack[-1][1]

        if stripped.startswith("- "):
            item_val = _parse_scalar(stripped[2:])
            if isinstance(container, list):
                container.append(item_val)
            continue

        if ":" in stripped:
            key, rest = stripped.split(":", 1)
            key = key.strip()
            rest = rest.strip()
            if rest and not rest.startswith("#"):
                # Strip trailing inline comment if preceded by space+#
                if " #" in rest:
                    rest = rest.split(" #", 1)[0].strip()
                container[key] = _parse_scalar(rest)
            else:
                # Look ahead to determine if next non-empty line is a list or dict
                next_is_list = False
                for look_ahead in lines[idx + 1 :]:
                    la_stripped = look_ahead.strip()
                    if not la_stripped or la_stripped.startswith("#"):
                        continue
                    next_is_list = la_stripped.startswith("- ")
                    break
                new_container: Any = [] if next_is_list else {}
                container[key] = new_container
                stack.append((indent, new_container))

    return root


def load_model_profiles(config_path: Path | None = None) -> tuple[str, dict[str, ModelProfile]]:
    path = config_path or (CONFIG_DIR / "models.yaml")
    data = _simple_yaml_load(path.read_text(encoding="utf-8"))
    default_profile = str(data.get("default_profile", "local-dev"))
    raw_profiles = data.get("profiles", {})

    profiles: dict[str, ModelProfile] = {}
    for name, cfg in raw_profiles.items():
        if not isinstance(cfg, dict):
            continue
        profiles[name] = ModelProfile(
            name=name,
            tier=str(cfg.get("tier", "local_test")),
            backend=str(cfg.get("backend", "ollama")),
            model=str(cfg.get("model", "")),
            license=str(cfg.get("license", "Unknown")),
            vram_gb_required=float(cfg.get("vram_gb_required", 0.0)),
            ram_gb_required=float(cfg.get("ram_gb_required", 4.0)),
            context_window=int(cfg.get("context_window", 8192)),
            temperature=float(cfg.get("temperature", 0.1)),
            timeout_sec=int(cfg.get("timeout_sec", 90)),
            description=str(cfg.get("description", "")),
        )
    return default_profile, profiles


def load_policy(config_path: Path | None = None) -> AuditPolicy:
    path = config_path or (CONFIG_DIR / "policy.yaml")
    if not path.exists():
        return AuditPolicy()

    data = _simple_yaml_load(path.read_text(encoding="utf-8"))
    fail_sev = os.getenv("AIOPS_FAIL_ON_SEVERITY", str(data.get("fail_on_severity", "HIGH")))
    max_llm = int(os.getenv("AIOPS_MAX_LLM_FINDINGS", str(data.get("max_llm_findings", 25))))
    enable_osv_raw = os.getenv(
        "AIOPS_ENABLE_OSV_LOOKUP", str(data.get("enable_osv_lookup", False))
    ).lower()
    auto_sync_raw = os.getenv(
        "AIOPS_AUTO_SYNC_CVE", str(data.get("auto_sync_cve", False))
    ).lower()
    auto_agent_raw = os.getenv(
        "AIOPS_ENABLE_AUTONOMOUS_AGENT", str(data.get("enable_autonomous_agent", True))
    ).lower()

    excluded = data.get("excluded_dirs")
    if not isinstance(excluded, list):
        excluded = AuditPolicy().excluded_dirs

    return AuditPolicy(
        fail_on_severity=Severity.from_str(fail_sev),
        max_llm_findings=max_llm,
        context_lines_before=int(data.get("context_lines_before", 18)),
        context_lines_after=int(data.get("context_lines_after", 18)),
        enable_osv_lookup=enable_osv_raw in ("true", "1", "yes"),
        auto_sync_cve=auto_sync_raw in ("true", "1", "yes"),
        cve_kb_ttl_hours=int(data.get("cve_kb_ttl_hours", 6)),
        enable_autonomous_agent=auto_agent_raw in ("true", "1", "yes"),
        max_agent_steps=int(os.getenv("AIOPS_MAX_AGENT_STEPS", str(data.get("max_agent_steps", 6)))),
        excluded_dirs=[str(d) for d in excluded],
        allowed_false_positive_suppression=bool(
            data.get("allowed_false_positive_suppression", True)
        ),
    )

