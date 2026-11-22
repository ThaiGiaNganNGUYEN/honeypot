import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot.config import HTTPSettings  # noqa: E402
from honeypot.httpparse import HttpRequest  # noqa: E402
from honeypot.services.ftp_honeypot import preliminary_reply, upload_name  # noqa: E402
from honeypot.services.http_honeypot import build_outcome  # noqa: E402


def _request(method: str, target: str, body: bytes = b"", content_type: str | None = None, username=None, password=None):
    path = target.split("?", 1)[0] or "/"
    return HttpRequest(
        method=method,
        target=target,
        path=path,
        query="",
        headers={},
        body=body,
        username=username,
        password=password,
        user_agent="lab",
        content_type=content_type,
    )


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.settings = HTTPSettings(True, 0, "Apache/2.4.41 (Ubuntu)", "Branch Gateway")

    def test_password_is_not_reflected(self):
        request = _request("POST", "/login", username="admin", password="training-only")
        outcome = build_outcome(request, self.settings)
        self.assertEqual(outcome.password, "training-only")
        self.assertNotIn(b"training-only", outcome.response)
        self.assertIn(b"X-Lab-Decoy: yes", outcome.response)

    def test_pages_escape_and_hide_real_secrets(self):
        missing = build_outcome(_request("GET", "/<script>"), self.settings)
        self.assertNotIn(b"<script>", missing.response)
        self.assertIn(b"&lt;script&gt;", missing.response)
        env = build_outcome(_request("GET", "/.env"), self.settings)
        self.assertIn(b"training-decoy-not-real", env.response)
        key = build_outcome(_request("GET", "/.ssh/id_rsa"), self.settings)
        self.assertNotIn(b"BEGIN OPENSSH PRIVATE KEY", key.response)
        self.assertIn(b"no key material", key.response)

    def test_site_name_is_escaped(self):
        settings = HTTPSettings(True, 0, "Apache", "<b>")
        page = build_outcome(_request("GET", "/"), settings)
        self.assertNotIn(b"<h1><b>", page.response)
        self.assertIn(b"&lt;b&gt;", page.response)


class FTPHelperTests(unittest.TestCase):
    def test_active_mode_is_refused(self):
        self.assertIn(b"502", preliminary_reply("PORT 127,0,0,1,0,80"))
        self.assertIn(b"502", preliminary_reply("EPRT |1|10.0.0.5|80|"))
        self.assertIsNone(preliminary_reply("USER backup"))

    def test_upload_name_strips_paths(self):
        self.assertEqual(upload_name("../../etc/passwd"), "passwd")
        self.assertEqual(upload_name(".."), "upload.bin")
        self.assertEqual(upload_name("drop.bin"), "drop.bin")


if __name__ == "__main__":
    unittest.main()
