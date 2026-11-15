"""
Requirement 3: Hardened HTTPS TLS 1.2/1.3 Server + HTTP->HTTPS HSTS Redirect Listener
- Auto-provisions Two-Tier X.509 PKI and seeds SQLite RBAC demo accounts on first boot
- Validates all 6 X.509 certificate chain invariants before binding network sockets
- Binds both IPv4 (`0.0.0.0`) and IPv6 loopback (`::1`) so `127.0.0.1` and `localhost` respond instantly
"""
from __future__ import annotations

import contextlib
import http.server
import re
import socket
import ssl
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from werkzeug.serving import BaseWSGIServer, ThreadedWSGIServer, WSGIRequestHandler

from carevault import create_app
from carevault.config import settings
from carevault.database import query_one
from carevault.security.pki_generator import generate_pki
from carevault.security.tls_validator import build_ssl_context
from carevault.seed import seed_database


class CareVaultWSGIRequestHandler(WSGIRequestHandler):
    """Ensures `werkzeug.socket` exposes the live `ssl.SSLSocket` for TLS cipher inspection."""

    server_version = "CareVault"
    sys_version = ""

    def make_environ(self) -> dict[str, Any]:
        environ = super().make_environ()
        environ["werkzeug.socket"] = self.connection
        if hasattr(self.connection, "cipher"):
            environ["wsgi.url_scheme"] = "https"
        return environ

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        if getattr(self.server, "server_port", None) == settings.https_port:
            super().log_request(code, size)


class CareVaultThreadedTLSServer(ThreadedWSGIServer):
    """Performs TLS 1.2/1.3 handshakes inside per-connection worker threads with a 10s timeout.

    Prevents Chromium speculative TCP preconnect sockets or Slowloris incomplete-TLS connections
    from blocking the main `accept()` loop.
    """

    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        host: str,
        port: int,
        app: Any,
        tls_context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            host,
            port,
            app,
            handler=CareVaultWSGIRequestHandler,
            passthrough_errors=False,
            ssl_context=None,
        )
        self.ssl_context = tls_context
        self._tls_context = tls_context

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            request.settimeout(10.0)
            tls_sock = self._tls_context.wrap_socket(
                request,
                server_side=True,
                do_handshake_on_connect=True,
            )
        except (ssl.SSLError, TimeoutError, ConnectionError, OSError):
            self.shutdown_request(request)
            return
        super().process_request_thread(tls_sock, client_address)


class _SafeThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False


class _IPv6ThreadingHTTPServer(_SafeThreadingHTTPServer):
    address_family = socket.AF_INET6


def _make_http_redirect_handler(target_https_port: int) -> type[http.server.BaseHTTPRequestHandler]:
    class HstsRedirectHandler(http.server.BaseHTTPRequestHandler):
        server_version = "CareVault"
        sys_version = ""
        timeout = 5

        def _redirect(self) -> None:
            raw_host = self.headers.get("Host", "127.0.0.1")
            if raw_host.startswith("["):
                hostname = raw_host.split("]")[0] + "]"
            else:
                hostname = raw_host.split(":")[0].strip() or "127.0.0.1"
            if hostname not in {"localhost", "127.0.0.1", "[::1]", "carevault.local"}:
                hostname = "127.0.0.1"
            port_suffix = "" if target_https_port == 443 else f":{target_https_port}"
            cleaned_path = re.sub(r"[\x00-\x1f\x7f]", "", self.path or "/")
            safe_path = "/" + cleaned_path.lstrip("/\\")
            location = f"https://{hostname}{port_suffix}{safe_path}"

            self.send_response(301, "Moved Permanently")
            self.send_header("Location", location)
            self.send_header(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            self._redirect()

        def do_HEAD(self) -> None:
            self._redirect()

        def do_POST(self) -> None:
            self._redirect()

        def log_message(self, format: str, *args: Any) -> None:
            return

    return HstsRedirectHandler


@dataclass
class RunningServers:
    https_server: BaseWSGIServer
    http_server: http.server.ThreadingHTTPServer
    https_thread: threading.Thread
    http_thread: threading.Thread
    pki_summary: dict[str, Any]
    extra_servers: list[Any] = field(default_factory=list)

    def stop(self) -> None:
        for srv in self.extra_servers:
            with contextlib.suppress(OSError):
                srv.shutdown()
                srv.server_close()
        self.http_server.shutdown()
        self.http_server.server_close()
        self.https_server.shutdown()
        self.https_server.server_close()
        self.http_thread.join(timeout=3.0)
        self.https_thread.join(timeout=3.0)


def ensure_bootstrap() -> None:
    if not (
        settings.tls_ca_cert_path.exists()
        and settings.tls_server_cert_path.exists()
        and settings.tls_server_key_path.exists()
    ):
        generate_pki()

    row = query_one("SELECT COUNT(*) AS cnt FROM users")
    if not row or row["cnt"] == 0:
        seed_database()


def _is_carevault_already_running(port: int) -> bool:
    try:
        ctx = ssl.create_default_context(cafile=str(settings.tls_ca_cert_path))
        with urllib.request.urlopen(
            f"https://127.0.0.1:{port}/api/health", context=ctx, timeout=1.5
        ) as resp:
            return bool(resp.status == 200)
    except (OSError, ssl.SSLError, urllib.error.URLError, ValueError):
        return False


def start_servers(
    host: str = "0.0.0.0",
    https_port: int | None = None,
    http_port: int | None = None,
    background: bool = False,
) -> RunningServers | None:
    ensure_bootstrap()
    eff_https_port = https_port or settings.https_port
    eff_http_port = http_port or settings.http_redirect_port

    if not background and _is_carevault_already_running(eff_https_port):
        print("=" * 72)
        print("  CareVault Python Server is ALREADY RUNNING & HEALTHY!")
        print(f"  Open in Browser (Recommended) : https://127.0.0.1:{eff_https_port}")
        print(f"  Alternate Localhost URL       : https://localhost:{eff_https_port}")
        print("=" * 72)
        return None

    ssl_ctx, pki_summary = build_ssl_context()
    app = create_app()

    https_srv = CareVaultThreadedTLSServer(
        host,
        eff_https_port,
        app,
        tls_context=ssl_ctx,
    )

    redirect_cls = _make_http_redirect_handler(eff_https_port)
    http_srv = _SafeThreadingHTTPServer((host, eff_http_port), redirect_cls)

    extra_servers: list[Any] = []
    if host == "0.0.0.0":
        # Bind IPv6 loopback `[::1]` as well so `localhost` on Windows connects with zero delay
        try:
            https_v6 = CareVaultThreadedTLSServer(
                "::1",
                eff_https_port,
                app,
                tls_context=ssl_ctx,
            )
            threading.Thread(target=https_v6.serve_forever, name="https-v6", daemon=True).start()
            extra_servers.append(https_v6)
        except OSError:
            pass
        try:
            http_v6 = _IPv6ThreadingHTTPServer(("::1", eff_http_port), redirect_cls)
            threading.Thread(target=http_v6.serve_forever, name="http-v6", daemon=True).start()
            extra_servers.append(http_v6)
        except OSError:
            pass

    print("=" * 72)
    print("  CareVault Secure Clinical Portal (100% Pure Python / Flask / PKI)")
    print(f"  HTTPS Portal (Recommended) : https://127.0.0.1:{eff_https_port}")
    print(f"  HTTPS Portal (Localhost)   : https://localhost:{eff_https_port}")
    print(f"  HTTP Redirect              : http://127.0.0.1:{eff_http_port} -> 301 HTTPS + HSTS")
    print(
        f"  PKI Chain                  : VALID ({len(pki_summary['checks'])}/6 checks passed, "
        f"{pki_summary['serverCert']['daysRemaining']} days remaining)"
    )
    print("=" * 72)

    http_thread = threading.Thread(target=http_srv.serve_forever, name="http-redirect", daemon=True)
    http_thread.start()

    if background:
        https_thread = threading.Thread(
            target=https_srv.serve_forever, name="https-wsgi", daemon=True
        )
        https_thread.start()
        return RunningServers(
            https_server=https_srv,
            http_server=http_srv,
            https_thread=https_thread,
            http_thread=http_thread,
            pki_summary=pki_summary,
            extra_servers=extra_servers,
        )

    try:
        https_srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down CareVault servers cleanly...")
    finally:
        for srv in extra_servers:
            with contextlib.suppress(OSError):
                srv.shutdown()
                srv.server_close()
        http_srv.shutdown()
        http_srv.server_close()
        https_srv.server_close()
    return None


if __name__ == "__main__":
    start_servers()
