import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honeypot.config import ConfigError, load_settings  # noqa: E402
from honeypot.privileges import maybe_drop  # noqa: E402


class ConfigTests(unittest.TestCase):
    def test_checked_in_config_stays_on_localhost(self):
        settings = load_settings(ROOT / "config" / "honeypot.json")
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertEqual(settings.dashboard.bind_host, "127.0.0.1")
        self.assertTrue(settings.ssh.banner.startswith("SSH-2.0-"))
        for port in (
            settings.ssh.port,
            settings.http.port,
            settings.ftp.port,
            settings.dashboard.port,
        ):
            self.assertGreaterEqual(port, 1024)

    def test_hostname_bind_is_rejected(self):
        settings = load_settings(ROOT / "config" / "honeypot.json")
        with self.assertRaises(ConfigError):
            load_settings(ROOT / "config" / "honeypot.json", bind_host="example.com")
        self.assertEqual(settings.bind_host, "127.0.0.1")

    def test_drop_privileges_is_a_noop_without_root_env(self):
        maybe_drop(ROOT / "logs", ROOT / "keys")


if __name__ == "__main__":
    unittest.main()
