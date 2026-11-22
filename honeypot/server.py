"""Start the decoys and the local dashboard in one process."""

from __future__ import annotations

import asyncio
import ipaddress

from honeypot.config import Settings
from honeypot.dashboard import handle_dashboard
from honeypot.eventlog import EventLog, Session, parse_peer
from honeypot.services.ftp_session import handle_ftp_client
from honeypot.services.http_honeypot import build_outcome
from honeypot.services.ssh_honeypot import SSHService
from honeypot.httpparse import read_http_request


class StartupError(Exception):
    """A listening socket could not be opened."""


class LabHoneypot:
    def __init__(self, settings: Settings, *, echo: bool = True) -> None:
        self.settings = settings
        self.log = EventLog(settings.log_dir, echo=echo)
        self.ssh = SSHService(settings, self.log)
        self.http_port: int | None = None
        self.ftp_port: int | None = None
        self.dashboard_port: int | None = None
        self._servers: list[asyncio.Server] = []
        self._active = {"http": 0, "ftp": 0}

    async def start(self) -> None:
        try:
            if self.settings.ssh.enabled:
                self.ssh.start()
            if self.settings.http.enabled:
                server = await asyncio.start_server(self._on_http, self.settings.bind_host, self.settings.http.port, limit=32768)
                self.http_port = _bound_port(server)
                self._servers.append(server)
            if self.settings.ftp.enabled:
                server = await asyncio.start_server(self._on_ftp, self.settings.bind_host, self.settings.ftp.port, limit=8192)
                self.ftp_port = _bound_port(server)
                self._servers.append(server)
            if self.settings.dashboard.enabled:
                server = await asyncio.start_server(
                    self._on_dashboard,
                    self.settings.dashboard.bind_host,
                    self.settings.dashboard.port,
                    limit=32768,
                )
                self.dashboard_port = _bound_port(server)
                self._servers.append(server)
        except OSError as exc:
            await self.stop()
            raise StartupError(_bind_message(exc)) from exc
        except Exception:
            await self.stop()
            raise
        _print_ready(self)

    async def stop(self) -> None:
        self.ssh.stop()
        for server in list(self._servers):
            server.close()
            await server.wait_closed()
        self._servers.clear()

    async def serve_forever(self) -> None:
        await self.start()
        try:
            await asyncio.Event().wait()
        finally:
            await self.stop()

    async def _on_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._guard("http", self._http, reader, writer)

    async def _on_ftp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._guard("ftp", self._ftp, reader, writer)

    async def _on_dashboard(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await handle_dashboard(reader, writer, self.log)

    async def _guard(self, name: str, handler, reader, writer) -> None:
        if self._active[name] >= self.settings.max_concurrent_connections:
            writer.close()
            return
        self._active[name] += 1
        try:
            await handler(reader, writer)
        finally:
            self._active[name] -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _http(self, reader, writer) -> None:
        peer = parse_peer(writer.get_extra_info("peername"))
        sockname = writer.get_extra_info("sockname")
        dst = sockname[1] if sockname else (self.http_port or 0)
        session = Session(self.log, "http", peer[0], peer[1], dst)
        try:
            request = await read_http_request(reader)
            if request is not None and request.path == "/favicon.ico":
                session.record = False
                writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            session.emit(event_type="connection", summary="tcp connect", status="open")
            if request is None:
                session.emit(
                    event_type="http_request",
                    summary="unreadable request",
                    status="400",
                    message="The request was not valid HTTP.",
                )
                return
            outcome = build_outcome(request, self.settings.http)
            if outcome.username:
                session.username = outcome.username
            session.emit(
                event_type=outcome.event_type,
                username=outcome.username,
                password=outcome.password,
                command=outcome.command,
                path=outcome.path,
                status=outcome.status,
                summary=outcome.summary,
                message=outcome.message,
                user_agent=outcome.user_agent,
                indicator=outcome.indicator,
            )
            writer.write(outcome.response)
            await writer.drain()
        except Exception as exc:
            session.emit(event_type="http_request", summary="error", status="error", message=type(exc).__name__)
        finally:
            session.finish()

    async def _ftp(self, reader, writer) -> None:
        peer = parse_peer(writer.get_extra_info("peername"))
        sockname = writer.get_extra_info("sockname")
        dst = sockname[1] if sockname else (self.ftp_port or 0)
        session = Session(self.log, "ftp", peer[0], peer[1], dst)
        try:
            session.emit(event_type="connection", summary="tcp connect", status="open")
            await handle_ftp_client(reader, writer, session, self.settings)
        except Exception as exc:
            session.emit(event_type="ftp_command", summary="error", status="error", message=type(exc).__name__)
        finally:
            session.finish()


def _bound_port(server: asyncio.Server) -> int:
    sockets = server.sockets or []
    if not sockets:
        raise StartupError("Listener started without a socket.")
    return sockets[0].getsockname()[1]


def _bind_message(exc: OSError) -> str:
    reason = exc.strerror or "could not bind"
    return f"Could not open a listening socket ({reason}). Change the port in config/honeypot.json or stop the other program."


def _print_ready(lab: LabHoneypot) -> None:
    if not lab.log.echo:
        return
    settings = lab.settings
    print("Training honeypot. It logs traffic sent to it and does not run attacker commands.", flush=True)
    print("Do not type real passwords. Use python -m honeypot.demo or an obvious training password.", flush=True)
    exposed = []
    if not ipaddress.ip_address(settings.bind_host).is_loopback:
        exposed.append(settings.bind_host)
    if settings.dashboard.enabled and not ipaddress.ip_address(settings.dashboard.bind_host).is_loopback:
        exposed.append(settings.dashboard.bind_host)
    if exposed:
        print("WARNING: a service is listening beyond localhost. Run this only on a network you are allowed to use.", flush=True)
    if settings.ssh.enabled:
        print(f"SSH decoy     {settings.bind_host}:{lab.ssh.port}", flush=True)
    if settings.http.enabled:
        print(f"HTTP decoy    http://{settings.bind_host}:{lab.http_port}", flush=True)
    if settings.ftp.enabled:
        print(f"FTP decoy     {settings.bind_host}:{lab.ftp_port}", flush=True)
    if settings.dashboard.enabled and lab.dashboard_port:
        host = settings.dashboard.bind_host
        shown = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
        print(f"Dashboard     http://{shown}:{lab.dashboard_port}", flush=True)
    print(f"Log file      {lab.log.json_path}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
