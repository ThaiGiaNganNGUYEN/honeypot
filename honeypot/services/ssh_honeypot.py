"""SSH decoy built on Paramiko.

The server records passwords and key fingerprints, then answers with FakeShell.
Direct TCP forwarding and remote port forwards are denied, so this process
cannot be turned into a proxy.
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import time
from base64 import b64encode
from pathlib import Path

from honeypot.config import Settings
from honeypot.eventlog import EventLog, Session, parse_peer
from honeypot.events import FORWARD_DENIED, NOT_EXECUTED, new_event
from honeypot.shell import FakeShell

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised when the dependency is absent
    paramiko = None

_Base = paramiko.ServerInterface if paramiko is not None else object


class SSHService:
    def __init__(self, settings: Settings, log: EventLog) -> None:
        self.settings = settings
        self.log = log
        self.port: int | None = None
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopped = threading.Event()
        self._slots = threading.BoundedSemaphore(settings.max_concurrent_connections)
        self._failures: dict[str, int] = {}
        self._lock = threading.Lock()
        self._host_key = None

    def decide(self, ip: str) -> str:
        ssh = self.settings.ssh
        with self._lock:
            if len(self._failures) > 10000:
                self._failures.clear()
            if not ssh.accept_passwords:
                return "rejected"
            seen = self._failures.get(ip, 0)
            if seen < ssh.reject_first_n:
                self._failures[ip] = seen + 1
                return "rejected"
            return "accepted"

    def start(self) -> None:
        if paramiko is None:
            raise RuntimeError(
                "SSH is enabled but paramiko is not installed. "
                "From the project folder run: python -m pip install -r requirements.txt"
            )
        logging = __import__("logging")
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        self._host_key = _load_host_key(self.settings.key_dir / "ssh_host_rsa")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.settings.bind_host, self.settings.ssh.port))
            sock.listen(128)
        except OSError:
            sock.close()
            raise
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, name="honeypot-ssh", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopped.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stopped.is_set():
            try:
                client, addr = self._sock.accept()
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                src_ip, src_port = parse_peer(addr)
                self.log.write(
                    new_event(
                        session_id="limit",
                        service="ssh",
                        event_type="connection",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=self.port or 0,
                        summary="connection limit reached",
                        status="dropped",
                    )
                )
                client.close()
                continue
            threading.Thread(target=self._guard, args=(client, addr), name="honeypot-ssh-client", daemon=True).start()

    def _guard(self, client: socket.socket, addr) -> None:
        try:
            self._handle(client, addr)
        finally:
            self._slots.release()

    def _handle(self, client: socket.socket, addr) -> None:
        src_ip, src_port = parse_peer(addr)
        session = Session(self.log, "ssh", src_ip, src_port, self.port or 0)
        transport = None
        try:
            client.settimeout(self.settings.session_timeout_seconds)
            try:
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            session.emit(event_type="connection", summary="tcp connect", status="open")
            transport = paramiko.Transport(client)
            transport.local_version = self.settings.ssh.banner
            transport.add_server_key(self._host_key)
            handler = HoneyHandler(self, session)
            try:
                transport.start_server(server=handler)
            except Exception as exc:
                session.emit(
                    event_type="session_end",
                    summary="handshake failed",
                    status="error",
                    message=type(exc).__name__,
                )
                return
            channel = transport.accept(15)
            if channel is None:
                return
            if not _wait_ready(handler, 10):
                return
            if handler.exec_ready.is_set() and not handler.shell_ready.is_set():
                _run_exec(channel, handler, session, self.settings.ssh.hostname)
            elif handler.shell_ready.is_set():
                _run_shell(channel, handler, session, self.settings)
        except Exception as exc:
            session.emit(event_type="session_end", summary="error", status="error", message=type(exc).__name__)
        finally:
            session.finish()
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client.close()
            except OSError:
                pass


class HoneyHandler(_Base):
    def __init__(self, service: SSHService, session: Session) -> None:
        self.service = service
        self.session = session
        self.username: str | None = None
        self.shell_ready = threading.Event()
        self.exec_ready = threading.Event()
        self.exec_command = ""
        self.auth_attempts = 0

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.auth_attempts += 1
        self.username = username
        self.session.username = username
        status = self.service.decide(self.session.src_ip)
        if self.auth_attempts > self.service.settings.ssh.max_auth_attempts:
            status = "rejected"
        self.session.emit(
            event_type="auth_attempt",
            username=username,
            password=password,
            summary=f"ssh login {username}",
            status=status,
            message="Password recorded. A successful result only opens the training shell.",
        )
        if status == "accepted":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.username = username
        self.session.username = username
        self.session.emit(
            event_type="auth_attempt",
            username=username,
            summary=f"public key for {username}",
            status="rejected",
            indicator=_fingerprint(key),
            message="Public key rejected. The key material was not stored, only the fingerprint.",
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        self.session.emit(
            event_type="command",
            command=str(kind),
            summary=f"channel {kind} denied",
            status="denied",
            message=FORWARD_DENIED,
        )
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        dest = ""
        if isinstance(destination, tuple) and len(destination) >= 2:
            dest = f"{destination[0]}:{destination[1]}"
        self.session.emit(
            event_type="command",
            command="direct-tcpip",
            summary="direct-tcpip denied",
            status="denied",
            indicator=dest or None,
            message=FORWARD_DENIED,
        )
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, address, port):
        self.session.emit(
            event_type="command",
            command="tcpip-forward",
            summary="remote forward denied",
            status="denied",
            indicator=f"{address}:{port}",
            message=FORWARD_DENIED,
        )
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        if isinstance(command, bytes):
            command = command.decode("utf-8", "replace")
        self.exec_command = str(command)
        self.exec_ready.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        self.session.emit(
            event_type="command",
            command=str(name),
            summary=f"subsystem {name} denied",
            status="denied",
            message=NOT_EXECUTED,
        )
        return False


def _wait_ready(handler: HoneyHandler, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if handler.shell_ready.is_set() or handler.exec_ready.is_set():
            return True
        time.sleep(0.05)
    return False


def _welcome(hostname: str) -> str:
    return (
        "Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-122-generic x86_64)\r\n"
        "\r\n"
        "Last login: the previous session on this training decoy was simulated.\r\n"
        f"This is a training shell on {hostname}. Commands are logged and are not executed.\r\n"
        "Do not enter real passwords or real secrets.\r\n"
    )


def _run_exec(channel, handler: HoneyHandler, session: Session, hostname: str) -> None:
    shell = FakeShell(handler.username or "unknown", hostname)
    output = shell.handle(handler.exec_command)
    session.emit(
        event_type="command",
        command=handler.exec_command,
        summary=handler.exec_command or "exec",
        status="logged",
        message=NOT_EXECUTED,
    )
    if output:
        channel.send(output.replace("\n", "\r\n") + "\r\n")
    channel.send_exit_status(0)
    channel.close()


def _run_shell(channel, handler: HoneyHandler, session: Session, settings: Settings) -> None:
    hostname = settings.ssh.hostname
    shell = FakeShell(handler.username or "unknown", hostname)
    channel.send(_welcome(hostname))
    deadline = time.monotonic() + settings.session_timeout_seconds
    channel.settimeout(1.0)
    buf = bytearray()
    just_cr = False
    channel.send(shell.prompt())
    while time.monotonic() < deadline and not shell.closed:
        if session.count >= settings.max_events_per_session:
            channel.send("\r\nsession limit reached\r\n")
            break
        try:
            data = channel.recv(256)
        except socket.timeout:
            continue
        except Exception:
            break
        if not data:
            break
        for byte in data:
            if byte == 13:
                just_cr = True
                _submit(channel, shell, session, buf)
                buf.clear()
                if shell.closed:
                    channel.send("logout\r\n")
                    return
                channel.send(shell.prompt())
                continue
            if byte == 10:
                if just_cr:
                    just_cr = False
                    continue
                _submit(channel, shell, session, buf)
                buf.clear()
                if shell.closed:
                    channel.send("logout\r\n")
                    return
                channel.send(shell.prompt())
                continue
            just_cr = False
            if byte in {8, 127}:
                if buf:
                    buf.pop()
                    channel.send("\b \b")
                continue
            if byte == 3:
                buf.clear()
                channel.send("^C\r\n" + shell.prompt())
                continue
            if byte < 32:
                continue
            if len(buf) >= 512:
                buf.clear()
                session.emit(
                    event_type="command",
                    summary="command discarded; longer than 512 characters",
                    status="discarded",
                    message=NOT_EXECUTED,
                )
                channel.send("\r\nbash: command too long\r\n" + shell.prompt())
                continue
            buf.append(byte)
            channel.send(bytes([byte]))


def _submit(channel, shell: FakeShell, session: Session, buf: bytearray) -> None:
    line = buf.decode("utf-8", "replace").strip()
    if not line:
        return
    output = shell.handle(line)
    session.emit(
        event_type="command",
        command=line,
        summary=line,
        status="logged",
        message=NOT_EXECUTED,
        username=shell.username,
    )
    if output:
        channel.send("\r\n" + output.replace("\n", "\r\n") + "\r\n")
    else:
        channel.send("\r\n")


def _fingerprint(key) -> str:
    try:
        raw = key.asbytes()
    except Exception:
        try:
            raw = key.get_fingerprint()
        except Exception:
            return "SHA256:unavailable"
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + b64encode(digest).decode("ascii").rstrip("=")


def _load_host_key(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            return paramiko.RSAKey.from_private_key_file(str(path))
        except Exception:
            pass
    key = paramiko.RSAKey.generate(2048)
    old = os.umask(0o077)
    try:
        key.write_private_key_file(str(path))
    finally:
        os.umask(old)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key
