import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot import demo  # noqa: E402


class SafetyTests(unittest.TestCase):
    def test_services_do_not_call_out(self):
        package = ROOT / "honeypot"
        banned = ("subprocess", "os.system", "os.popen", "urlopen", "create_connection", "Popen")
        for path in package.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if path.name == "demo.py":
                continue
            for word in banned:
                self.assertNotIn(word, text, f"{path.name} contains {word}")
            if path.name == "shell.py":
                self.assertNotIn("open(", text)
                self.assertNotIn("socket", text)

    def test_demo_cannot_leave_loopback(self):
        self.assertEqual(demo.LAB_HOST, "127.0.0.1")
        self.assertEqual(demo._check_lab_host("127.0.0.1"), "127.0.0.1")
        for host in ("8.8.8.8", "10.0.0.5", "localhost", "127.0.0.2"):
            with self.assertRaises(RuntimeError):
                demo._check_lab_host(host)
        source = (ROOT / "honeypot" / "demo.py").read_text(encoding="utf-8")
        self.assertNotIn('"--host"', source)
        self.assertNotIn("'--host'", source)


if __name__ == "__main__":
    unittest.main()
