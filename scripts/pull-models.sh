#!/usr/bin/env bash
set -euo pipefail

PROFILE="${1:-local-dev}"
OLLAMA_CONTAINER="${OLLAMA_CONTAINER:-aiops-ollama-local}"

case "$PROFILE" in
  local-tiny)
    MODEL="qwen2.5-coder:1.5b"
    REQ_VRAM="1.5"
    ;;
  local-dev)
    MODEL="qwen2.5-coder:3b"
    REQ_VRAM="2.5"
    ;;
  local-8gb)
    MODEL="qwen2.5-coder:7b"
    REQ_VRAM="5.8"
    ;;
  prod-16gb-coder)
    MODEL="qwen2.5-coder:14b-instruct-q4_K_M"
    REQ_VRAM="12.5"
    OLLAMA_CONTAINER="${OLLAMA_CONTAINER_PROD:-aiops-ollama-prod}"
    ;;
  prod-16gb-reasoning)
    MODEL="deepseek-r1:14b"
    REQ_VRAM="12.8"
    OLLAMA_CONTAINER="${OLLAMA_CONTAINER_PROD:-aiops-ollama-prod}"
    ;;
  *)
    echo "Unknown profile: $PROFILE"
    echo "Supported: local-tiny | local-dev | local-8gb | prod-16gb-coder | prod-16gb-reasoning"
    exit 1
    ;;
esac

echo "[INFO] Profile: $PROFILE -> Open-Source Model: $MODEL (Est. VRAM: ${REQ_VRAM} GB)"

if command -v ollama >/dev/null 2>&1; then
  ollama pull "$MODEL"
elif command -v docker >/dev/null 2>&1; then
  docker exec -it "$OLLAMA_CONTAINER" ollama pull "$MODEL"
else
  echo "[ERROR] Neither local 'ollama' CLI nor 'docker' is installed."
  exit 1
fi

