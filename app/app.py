"""Hardened reference microservice deployed by the IaC + Ansible pipeline."""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
LOGGER = logging.getLogger("aiops.sample_app")

APP_ENV = os.getenv("APP_ENV", "production")
APP_VERSION = "1.0.0"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class HardenedRequestHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler with strict security headers and JSON responses."""

    server_version = "AppService"
    sys_version = ""

    def _send_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return

        if self.path == "/readyz":
            self._send_json(200, {"ready": True, "env": APP_ENV})
            return

        if self.path == "/api/v1/status":
            self._send_json(
                200,
                {
                    "service": "aiops-sample-app",
                    "version": APP_VERSION,
                    "env": APP_ENV,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
            return

        self._send_json(404, {"error": "not_found"})

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        LOGGER.info("http_request %s", format % args)


def run_server() -> None:
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), HardenedRequestHandler)

    def _shutdown(_signum: int, _frame: Any) -> None:
        LOGGER.info("shutdown_signal_received")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    LOGGER.info("app_started host=%s port=%s env=%s", host, port, APP_ENV)
    server.serve_forever()


if __name__ == "__main__":
    run_server()

