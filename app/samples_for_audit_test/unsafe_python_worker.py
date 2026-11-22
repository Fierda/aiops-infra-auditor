"""STATIC AUDIT TEST FIXTURE — Demonstrates Python deserialization & command sinks."""

import pickle
import subprocess
import yaml


def load_untrusted_config(raw_yaml: str):
    # Unsafe YAML deserialization (CWE-502)
    return yaml.load(raw_yaml)


def restore_cached_blob(raw_bytes: bytes):
    # Untrusted pickle deserialization (CWE-502)
    return pickle.loads(raw_bytes)


def run_user_report(filename: str):
    # Shell injection via shell=True (CWE-78)
    return subprocess.run(f"cat /var/reports/{filename}", shell=True, check=False)

