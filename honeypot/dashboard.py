"""Local analyst page. It reads the log and does not emulate a service."""

from __future__ import annotations

import argparse
import asyncio
import json

from honeypot.analyze import build_payload
from honeypot.config import ConfigError, Settings, load_settings
from honeypot.eventlog import EventLog, parse_peer
from honeypot.events import configure_stdio
from honeypot.httpparse import read_http_request

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot lab</title>
<style>
:root { color-scheme: dark; --bg: #10161d; --panel: #1a2430; --text: #e8eef6;
        --muted: #b7c3d4; --line: #2d3b4d; --accent: #7fd1c3; --warn: #e6c07b; }
* { box-sizing: border-box; }
body { margin: 0; font-family: "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
header, main { width: min(1100px, calc(100% - 32px)); margin: 0 auto; }
header { padding: 28px 0 8px; }
h1 { margin: 0 0 6px; font-size: 28px; }
h2 { margin: 0 0 10px; font-size: 16px; color: var(--accent); }
p { color: var(--muted); }
.banner { background: #243044; border: 1px solid var(--line); padding: 12px 14px; border-radius: 10px; }
.cards, .grid { display: grid; gap: 12px; }
.cards { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); margin: 16px 0; }
.grid { grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
.card, section { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px; }
.card p { margin: 0; font-size: 13px; }
.card strong { display: block; margin-top: 6px; font-size: 26px; }
section { margin: 12px 0 18px; }
ul { margin: 0; padding-left: 18px; }
li { margin: 6px 0; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); font-size: 14px; vertical-align: top; }
.table-wrap { overflow-x: auto; }
button { background: #245c73; color: white; border: 0; border-radius: 8px; padding: 8px 12px; }
code { color: var(--warn); }
</style>
</head>
<body>
<header>
  <h1>Honeypot lab</h1>
  <p>Local analyst view. Passwords here were typed into the decoy. Keep this page on localhost.</p>
</header>
<main>
  <p class="banner" id="status">Waiting for the log…</p>
  <div class="cards" id="cards"></div>
  <section><h2>Insights</h2><ul id="insights"></ul></section>
  <div class="grid">
    <section><h2>Usernames</h2><div class="table-wrap"><table id="users"></table></div></section>
    <section><h2>Commands</h2><div class="table-wrap"><table id="commands"></table></div></section>
    <section><h2>Paths</h2><div class="table-wrap"><table id="paths"></table></div></section>
    <section><h2>Indicators</h2><ul id="indicators"></ul></section>
  </div>
  <section>
    <h2>Recent events</h2>
    <button id="refresh" type="button">Refresh</button>
    <div class="table-wrap"><table id="events"></table></div>
  </section>
</main>
<script>
function esc(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
function rows(items) {
  if (!items || !items.length) return "<tr><td>(none)</td></tr>";
  return items.map(function (item) {
    return "<tr><td>" + esc(item.value) + "</td><td>" + esc(item.count) + "</td></tr>";
  }).join("");
}
function render(data) {
  document.getElementById("status").textContent =
    (data.total_events || 0) + " events. Log: " + (data.log_path || "");
  var cards = [
    ["Events", data.total_events],
    ["Sources", data.unique_sources],
    ["Sessions", data.unique_sessions],
    ["Auth", data.auth_attempts],
    ["Indicators", (data.indicators || []).length]
  ];
  document.getElementById("cards").innerHTML = cards.map(function (card) {
    return "<article class='card'><p>" + esc(card[0]) + "</p><strong>" + esc(card[1]) + "</strong></article>";
  }).join("");
  var insights = data.insights || [];
  document.getElementById("insights").innerHTML = insights.map(function (item) {
    return "<li>" + esc(item) + "</li>";
  }).join("") || "<li>No insights yet.</li>";
  document.getElementById("users").innerHTML = rows(data.top_usernames);
  document.getElementById("commands").innerHTML = rows(data.top_commands);
  document.getElementById("paths").innerHTML = rows(data.top_paths);
  var indicators = data.indicators || [];
  document.getElementById("indicators").innerHTML = indicators.map(function (item) {
    return "<li><code>" + esc(item.value) + "</code> (" + esc(item.count) + ")</li>";
  }).join("") || "<li>(none)</li>";
  var recent = data.recent || [];
  var head = "<tr><th>Time</th><th>Service</th><th>Category</th><th>Source</th><th>Summary</th><th>User</th><th>Password</th><th>Status</th></tr>";
  document.getElementById("events").innerHTML = head + recent.map(function (row) {
    return "<tr><td>" + esc(row.timestamp) + "</td><td>" + esc(row.service) + "</td><td>" +
      esc(row.category) + "</td><td>" + esc(row.src_ip) + "</td><td>" + esc(row.summary) +
      "</td><td>" + esc(row.username) + "</td><td>" + esc(row.password) + "</td><td>" +
      esc(row.status) + "</td></tr>";
  }).join("");
}
async function refresh() {
  try {
    var response = await fetch("/api/summary", {cache: "no-store"});
    render(await response.json());
  } catch (err) {
    document.getElementById("status").textContent = "Dashboard lost contact with the local analyzer.";
  }
}
document.getElementById("refresh").addEventListener("click", refresh);
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


def _response(status: str, body: bytes, content_type: str) -> bytes:
    head = "\r\n".join(
        [
            f"HTTP/1.1 {status}",
            "X-Lab-Dashboard: yes",
            "X-Content-Type-Options: nosniff",
            "Cache-Control: no-store",
            "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
    )
    return head.encode("ascii") + b"\r\n\r\n" + body


async def handle_dashboard(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, log: EventLog) -> None:
    peer = parse_peer(writer.get_extra_info("peername"))
    try:
        request = await read_http_request(reader, max_body=1024)
        if request is None:
            return
        if request.path == "/favicon.ico":
            writer.write(_response("204 No Content", b"", "text/plain"))
        elif request.path == "/api/summary":
            events, errors, truncated = log.read()
            payload = build_payload(events, errors, truncated, log.json_path)
            body = json.dumps(payload).encode("ascii")
            writer.write(_response("200 OK", body, "application/json"))
        elif request.path == "/":
            writer.write(_response("200 OK", _PAGE.encode("utf-8"), "text/html; charset=utf-8"))
        else:
            writer.write(_response("404 Not Found", b"Not found", "text/plain"))
        await writer.drain()
    except Exception as exc:
        print(f"dashboard error from {peer[0]}: {type(exc).__name__}", flush=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def serve_dashboard(settings: Settings, log: EventLog) -> asyncio.base_events.Server:
    async def handler(reader, writer):
        await handle_dashboard(reader, writer, log)

    try:
        return await asyncio.start_server(handler, settings.dashboard.bind_host, settings.dashboard.port, limit=32768)
    except OSError as exc:
        raise OSError(
            f"Could not listen on {settings.dashboard.bind_host}:{settings.dashboard.port} ({exc.strerror}). "
            "If the honeypot is already running, open its dashboard instead."
        ) from exc


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(description="Read-only dashboard for an existing honeypot log")
    parser.add_argument("--config")
    parser.add_argument("--log")
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(exc)
        return 1
    log = EventLog(settings.log_dir, echo=False)
    if args.log:
        log.json_path = __import__("pathlib").Path(args.log)

    async def run() -> None:
        server = await serve_dashboard(settings, log)
        port = server.sockets[0].getsockname()[1]
        host = settings.dashboard.bind_host
        shown = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
        print(f"Dashboard at http://{shown}:{port}")
        print("Press Ctrl+C to stop.")
        try:
            await asyncio.Event().wait()
        finally:
            server.close()
            await server.wait_closed()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nStopped.")
    except OSError as exc:
        print(exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
