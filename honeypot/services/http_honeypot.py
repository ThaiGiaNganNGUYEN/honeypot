"""Low-interaction HTTP decoy.

Pages are static training content. Posted passwords are recorded and are not
written back into the HTML.
"""

from __future__ import annotations

import html
from dataclasses import dataclass

from honeypot.config import HTTPSettings
from honeypot.events import BODY_DISCARDED
from honeypot.httpparse import HttpRequest

_STYLE = """
body { margin: 0; font-family: "Segoe UI", sans-serif; background: #e8eef6; color: #142033; }
.wrap { max-width: 440px; margin: 8vh auto; background: #fff; padding: 28px;
        border-radius: 12px; box-shadow: 0 8px 30px rgba(20, 32, 51, 0.08); }
.wide { max-width: 760px; }
h1 { margin: 0 0 6px; font-size: 24px; }
p.sub { margin: 0; color: #5c6b80; }
label { display: block; margin-top: 14px; font-size: 14px; }
input { width: 100%; box-sizing: border-box; margin-top: 6px; padding: 10px;
        border: 1px solid #c5d0de; border-radius: 8px; }
button { margin-top: 18px; width: 100%; padding: 10px; border: 0; border-radius: 8px;
         background: #1f6feb; color: white; font-weight: 600; }
footer, .note { margin-top: 18px; color: #5c6b80; font-size: 13px; }
table { width: 100%; border-collapse: collapse; }
td { border-bottom: 1px solid #e5ecf4; padding: 8px 0; }
a { color: #1f6feb; }
nav a { margin-right: 14px; }
""".strip()

_ENV = (
    "# training decoy values — not real secrets\n"
    "APP_ENV=lab\n"
    "DB_HOST=db.internal.lab\n"
    "DB_PASSWORD=training-decoy-not-real\n"
)
_PHP = (
    "<?php\n"
    "// training decoy. this file is not executed.\n"
    "$db_host = 'db.internal.lab';\n"
    "$db_password = 'training-decoy-not-real';\n"
)
_GIT = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.invalid/lab/gateway.git\n"
_KEY = "training decoy\nno key material is stored here\n"
_ROBOTS = "User-agent: *\nDisallow: /\n"


@dataclass
class HTTPOutcome:
    response: bytes
    event_type: str
    username: str | None
    password: str | None
    command: str | None
    path: str | None
    status: str | None
    summary: str
    message: str
    user_agent: str | None
    indicator: str | None = None


def encode_http(
    status: str,
    body: bytes,
    content_type: str,
    server: str,
    extra: list[str] | None = None,
) -> bytes:
    headers = [
        f"HTTP/1.1 {status}",
        f"Server: {server}",
        "X-Lab-Decoy: yes",
        "X-Content-Type-Options: nosniff",
        "Referrer-Policy: no-referrer",
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        "Cache-Control: no-store",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    if extra:
        headers.extend(extra)
    head = "\r\n".join(headers).encode("ascii")
    return head + b"\r\n\r\n" + body


def _page(title: str, body: str, site_name: str, wide: bool = False) -> bytes:
    width = "wrap wide" if wide else "wrap"
    document = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><style>{_STYLE}</style></head>
<body><main class="{width}"><h1>{html.escape(site_name)}</h1>{body}
<p class="note">Training system. Do not enter a real password.</p></main></body></html>"""
    return document.encode("utf-8")


def _login_page(site_name: str) -> bytes:
    body = """
<p class="sub">Sign in to the training gateway</p>
<form method="post" action="/login" autocomplete="off">
<label>Username <input name="username" autocomplete="off"></label>
<label>Password <input name="password" type="password" autocomplete="off"></label>
<button type="submit">Sign in</button>
</form>"""
    return _page(site_name, body, site_name)


def _overview(site_name: str) -> bytes:
    body = """
<p class="sub">Training portal</p>
<nav><a href="/overview">Overview</a><a href="/network">Network</a><a href="/backup">Backup</a><a href="/logs">Logs</a></nav>
<table>
<tr><td>WAN</td><td>link up (simulated)</td></tr>
<tr><td>LAN</td><td>10.8.0.0/24</td></tr>
<tr><td>Hostname</td><td>prod-gateway</td></tr>
<tr><td>Firmware</td><td>lab image</td></tr>
</table>"""
    return _page("Overview", body, site_name, wide=True)


def _network(site_name: str) -> bytes:
    body = """
<p class="sub">Simulated interfaces</p>
<nav><a href="/overview">Overview</a><a href="/network">Network</a></nav>
<table>
<tr><td>eth0</td><td>10.8.0.15/24</td></tr>
<tr><td>wan0</td><td>dhcp, simulated</td></tr>
</table>"""
    return _page("Network", body, site_name, wide=True)


def _backup(site_name: str) -> bytes:
    body = """
<p class="sub">No backup file is stored on this decoy.</p>
<nav><a href="/overview">Overview</a></nav>
<p>The last snapshot is a label only. There is nothing to download.</p>"""
    return _page("Backup", body, site_name, wide=True)


def _logs(site_name: str) -> bytes:
    body = """
<p class="sub">Simulated device log</p>
<nav><a href="/overview">Overview</a></nav>
<pre>Nov 22 08:01:02 prod-gateway dhcpd: lease table loaded
Nov 22 08:04:11 prod-gateway kernel: eth0 link up</pre>"""
    return _page("Logs", body, site_name, wide=True)


def _not_found(path: str, site_name: str) -> bytes:
    shown = html.escape(path[:120])
    body = f"<p>Nothing is hosted at {shown}.</p>"
    return _page("Not found", body, site_name)


def build_outcome(request: HttpRequest, settings: HTTPSettings) -> HTTPOutcome:
    user_agent = request.user_agent
    summary = f"{request.method or 'GET'} {request.target or '/'}"
    message = ""
    if request.too_large:
        message = BODY_DISCARDED
    if request.malformed:
        body = _not_found("/", settings.site_name)
        return HTTPOutcome(
            response=encode_http("400 Bad Request", body, "text/html; charset=utf-8", settings.server_header),
            event_type="http_request",
            username=request.username,
            password=request.password,
            command=request.method,
            path=request.path,
            status="400",
            summary="malformed request",
            message=message or "The request line was not valid HTTP.",
            user_agent=user_agent,
        )

    path = request.path or "/"
    method = request.method or "GET"
    is_login = method == "POST" and (request.password or path in {"/login", "/wp-login.php", "/phpmyadmin"})
    if is_login:
        page = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<meta http-equiv='refresh' content='0; url=/overview'></head>"
            "<body>Redirecting to the training portal.</body></html>"
        ).encode("utf-8")
        response = encode_http(
            "302 Found",
            page,
            "text/html; charset=utf-8",
            settings.server_header,
            ["Location: /overview", "Set-Cookie: lab_session=decoy; HttpOnly; Path=/"],
        )
        return HTTPOutcome(
            response=response,
            event_type="auth_attempt",
            username=request.username,
            password=request.password,
            command=f"POST {path}",
            path=path,
            status="accepted",
            summary=f"POST {path}",
            message="Credentials were recorded and a fake page was returned. No real account was opened.",
            user_agent=user_agent,
        )

    text_pages = {
        "/.env": _ENV,
        "/config.php": _PHP,
        "/.git/config": _GIT,
        "/.ssh/id_rsa": _KEY,
        "/robots.txt": _ROBOTS,
    }
    if path in text_pages:
        body = text_pages[path].encode("utf-8")
        response = encode_http("200 OK", body, "text/plain; charset=utf-8", settings.server_header)
        return HTTPOutcome(
            response=response,
            event_type="http_request",
            username=None,
            password=None,
            command=f"{method} {path}",
            path=path,
            status="200",
            summary=f"{method} {path}",
            message=message,
            user_agent=user_agent,
        )

    html_pages = {
        "/": _login_page,
        "/login": _login_page,
        "/admin": _login_page,
        "/wp-login.php": _login_page,
        "/phpmyadmin": _login_page,
        "/overview": _overview,
        "/network": _network,
        "/backup": _backup,
        "/logs": _logs,
    }
    if path in html_pages:
        body = html_pages[path](settings.site_name)
        status = "200"
    else:
        body = _not_found(path, settings.site_name)
        status = "404"
    return HTTPOutcome(
        response=encode_http(f"{status} {'OK' if status == '200' else 'Not Found'}", body, "text/html; charset=utf-8", settings.server_header),
        event_type="http_request",
        username=request.username,
        password=request.password,
        command=f"{method} {path}",
        path=path,
        status=status,
        summary=summary if len(summary) < 300 else f"{method} {path}",
        message=message,
        user_agent=user_agent,
    )
