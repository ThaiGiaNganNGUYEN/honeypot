"""Async control connection for the FTP decoy."""

from __future__ import annotations

import asyncio

from honeypot.config import Settings
from honeypot.eventlog import Session
from honeypot.events import NOT_EXECUTED, UPLOAD_DISCARDED
from honeypot.services.ftp_honeypot import (
    FTPState,
    hash_upload,
    preliminary_reply,
    upload_name,
)

_DATA_CAP = 65536


async def handle_ftp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    session: Session,
    settings: Settings,
) -> None:
    banner = settings.ftp.banner.encode("ascii") + b"\r\n"
    writer.write(banner)
    await writer.drain()
    state = FTPState()
    pending = b""
    passive: tuple[asyncio.AbstractServer, asyncio.Future, str] | None = None
    try:
        while session.count < settings.max_events_per_session:
            try:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=settings.session_timeout_seconds)
            except asyncio.TimeoutError:
                writer.write(b"421 Timeout.\r\n")
                await writer.drain()
                return
            if not chunk:
                return
            pending += chunk
            if len(pending) > 8192:
                writer.write(b"500 Line too long.\r\n")
                await writer.drain()
                return
            while b"\n" in pending and session.count < settings.max_events_per_session:
                raw, pending = pending.split(b"\n", 1)
                line = raw.decode("utf-8", "replace").strip("\r")
                if len(line) > 512:
                    writer.write(b"500 Line too long.\r\n")
                    await writer.drain()
                    continue
                closed = await _command(line, writer, session, state, passive_box := _Box(passive))
                passive = passive_box.value
                if closed:
                    return
    finally:
        if passive is not None:
            passive[0].close()
            await passive[0].wait_closed()


class _Box:
    def __init__(self, value):
        self.value = value


async def _command(line: str, writer: asyncio.StreamWriter, session: Session, state: FTPState, box: _Box) -> bool:
    early = preliminary_reply(line)
    if early is not None:
        session.emit(
            event_type="ftp_command",
            command=line.split(" ", 1)[0].upper(),
            summary=line.split(" ", 1)[0].upper(),
            status="denied",
            message=NOT_EXECUTED,
        )
        writer.write(early)
        await writer.drain()
        return False

    stripped = line.strip()
    if not stripped:
        return False
    verb, _, arg = stripped.partition(" ")
    verb = verb.upper()
    arg = arg.strip()

    if verb == "QUIT":
        session.emit(event_type="ftp_command", command="QUIT", summary="QUIT", status="closed")
        writer.write(b"221 Goodbye.\r\n")
        await writer.drain()
        return True

    if verb == "USER":
        state.username = arg[:128] or "anonymous"
        state.authed = False
        session.username = state.username
        session.emit(
            event_type="ftp_command",
            command="USER",
            username=state.username,
            summary=f"USER {state.username}",
            status="observed",
        )
        writer.write(b"331 Password required.\r\n")
        await writer.drain()
        return False

    if verb == "PASS":
        if not state.username:
            writer.write(b"503 Login with USER first.\r\n")
            await writer.drain()
            session.emit(event_type="auth_attempt", command="PASS", summary="PASS", status="rejected", message="USER was missing.")
            return False
        state.authed = True
        session.emit(
            event_type="auth_attempt",
            command="PASS",
            username=state.username,
            password=arg,
            summary="PASS",
            status="accepted",
            message="Login accepted into the training FTP decoy. Files are not stored.",
        )
        writer.write(b"230 Login recorded by the training decoy. Commands are logged and files are not stored.\r\n")
        await writer.drain()
        return False

    if verb in {"NOOP", "FEAT", "SYST", "TYPE", "OPTS", "PWD", "CWD", "CDUP", "PASV", "EPSV", "LIST", "NLST", "RETR", "STOR", "APPE", "MKD", "RMD", "DELE"}:
        if verb not in {"NOOP", "FEAT", "SYST", "TYPE", "OPTS"} and not state.authed:
            writer.write(b"530 Log in first.\r\n")
            await writer.drain()
            session.emit(event_type="ftp_command", command=verb, summary=verb, status="rejected")
            return False
        await _authed_command(verb, arg, writer, session, state, box)
        return False

    session.emit(event_type="ftp_command", command=verb, summary=verb, status="rejected", message="Command was not implemented.")
    writer.write(b"502 Command not implemented.\r\n")
    await writer.drain()
    return False


async def _authed_command(
    verb: str,
    arg: str,
    writer: asyncio.StreamWriter,
    session: Session,
    state: FTPState,
    box: _Box,
) -> None:
    if verb == "NOOP":
        writer.write(b"200 OK.\r\n")
    elif verb == "SYST":
        writer.write(b"215 UNIX Type: L8\r\n")
    elif verb == "TYPE":
        writer.write(b"200 Type set.\r\n")
    elif verb == "OPTS":
        writer.write(b"200 OK.\r\n")
    elif verb == "FEAT":
        writer.write(b"211-Features:\r\n PASV\r\n EPSV\r\n211 End\r\n")
    elif verb == "PWD":
        writer.write(b'257 "/" is the current directory.\r\n')
    elif verb in {"CWD", "CDUP"}:
        if verb == "CDUP" or arg in {"", "/"}:
            writer.write(b"250 Directory changed.\r\n")
        else:
            writer.write(b"550 No such directory.\r\n")
    elif verb in {"MKD", "RMD", "DELE"}:
        writer.write(b"550 This training decoy does not change stored files.\r\n")
        session.emit(event_type="ftp_command", command=verb, path=upload_name(arg) if arg else None, summary=verb, status="denied", message=NOT_EXECUTED)
        await writer.drain()
        return
    elif verb in {"PASV", "EPSV"}:
        await _open_passive(verb, writer, box)
        session.emit(event_type="ftp_command", command=verb, summary=verb, status="ok")
        return
    elif verb in {"LIST", "NLST"}:
        await _send_data(writer, session, state, box, state.listing(), "LIST", None)
        return
    elif verb == "RETR":
        name = upload_name(arg)
        payload = state.file_bytes(name)
        if payload is None:
            writer.write(b"550 File not available.\r\n")
            await writer.drain()
            session.emit(event_type="ftp_command", command="RETR", path=name, summary=f"RETR {name}", status="missing")
            return
        await _send_data(writer, session, state, box, payload, "RETR", name)
        return
    elif verb in {"STOR", "APPE"}:
        await _receive_upload(writer, session, state, box, upload_name(arg), verb)
        return
    else:
        writer.write(b"502 Command not implemented.\r\n")
    path = arg[:120] if verb == "CWD" and arg else None
    session.emit(event_type="ftp_command", command=verb, summary=verb, status="ok", path=path)
    await writer.drain()


async def _open_passive(verb: str, writer: asyncio.StreamWriter, box: _Box) -> None:
    if box.value is not None:
        box.value[0].close()
        await box.value[0].wait_closed()
        box.value = None
    loop = asyncio.get_running_loop()
    ready: asyncio.Future = loop.create_future()

    async def on_data(data_reader: asyncio.StreamReader, data_writer: asyncio.StreamWriter) -> None:
        if not ready.done():
            ready.set_result((data_reader, data_writer))
        else:
            data_writer.close()

    sockname = writer.get_extra_info("sockname")
    local_ip = sockname[0] if sockname else "127.0.0.1"
    if ":" in local_ip:
        writer.write(b"522 Use IPv4 for this training decoy.\r\n")
        await writer.drain()
        return
    server = await asyncio.start_server(on_data, local_ip, 0)
    port = server.sockets[0].getsockname()[1]
    box.value = (server, ready, local_ip)
    if verb == "EPSV":
        reply = f"229 Entering Extended Passive Mode (|||{port}|).\r\n"
    else:
        p1, p2 = divmod(port, 256)
        octets = local_ip.split(".")
        reply = f"227 Entering Passive Mode ({','.join(octets)},{p1},{p2}).\r\n"
    writer.write(reply.encode("ascii"))
    await writer.drain()


async def _take_data(box: _Box):
    """Return the connected data socket without waiting for the listener to drain.

    The accepted transfer is itself an active connection on the passive
    listener. Waiting for that listener to fully close before using the
    socket deadlocks the transfer.
    """
    if box.value is None:
        return None
    server, ready, _ip = box.value
    box.value = None
    try:
        pair = await asyncio.wait_for(ready, timeout=10)
    except asyncio.TimeoutError:
        pair = None
    server.close()
    if pair is None:
        await server.wait_closed()
        return None
    data_reader, data_writer = pair
    return server, data_reader, data_writer


async def _finish_data(server, data_writer) -> None:
    data_writer.close()
    try:
        await data_writer.wait_closed()
    except Exception:
        pass
    await server.wait_closed()


async def _send_data(writer, session, state, box, payload: bytes, verb: str, path: str | None) -> None:
    if box.value is None:
        writer.write(b"425 Use PASV first.\r\n")
        await writer.drain()
        session.emit(event_type="ftp_command", command=verb, path=path, summary=verb, status="failed")
        return
    writer.write(b"150 Opening data connection.\r\n")
    await writer.drain()
    taken = await _take_data(box)
    if taken is None:
        writer.write(b"425 No data connection.\r\n")
        await writer.drain()
        session.emit(event_type="ftp_command", command=verb, path=path, summary=verb, status="failed")
        return
    server, _reader, data_writer = taken
    data_writer.write(payload)
    await data_writer.drain()
    await _finish_data(server, data_writer)
    writer.write(b"226 Transfer complete.\r\n")
    await writer.drain()
    summary = verb if not path else f"{verb} {path}"
    session.emit(event_type="ftp_command", command=summary, path=path, summary=summary, status="ok", message=NOT_EXECUTED if verb == "RETR" else "")


async def _receive_upload(writer, session, state, box, name: str, verb: str) -> None:
    if box.value is None:
        writer.write(b"425 Use PASV first.\r\n")
        await writer.drain()
        session.emit(event_type="ftp_command", command=verb, path=name, summary=f"{verb} {name}", status="failed")
        return
    writer.write(b"150 Opening data connection.\r\n")
    await writer.drain()
    taken = await _take_data(box)
    if taken is None:
        writer.write(b"425 No data connection.\r\n")
        await writer.drain()
        session.emit(event_type="ftp_command", command=verb, path=name, summary=f"{verb} {name}", status="failed")
        return
    server, data_reader, data_writer = taken
    chunks: list[bytes] = []
    total = 0
    truncated = False
    try:
        while total < _DATA_CAP:
            piece = await asyncio.wait_for(data_reader.read(4096), timeout=10)
            if not piece:
                break
            room = _DATA_CAP - total
            chunks.append(piece[:room])
            total += len(piece[:room])
            if len(piece) > room:
                truncated = True
                break
    except asyncio.TimeoutError:
        truncated = True
    digest, counted, hash_truncated = hash_upload(chunks)
    del chunks
    state.uploads[name] = counted
    await _finish_data(server, data_writer)
    writer.write(b"226 Transfer complete.\r\n")
    await writer.drain()
    message = f"{UPLOAD_DISCARDED} sha256={digest} bytes={counted}"
    if truncated or hash_truncated:
        message += " truncated=yes"
    session.emit(
        event_type="ftp_command",
        command=f"{verb} {name}",
        path=name,
        summary=f"{verb} {name}",
        status="discarded",
        message=message,
    )
