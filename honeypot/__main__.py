"""Run the training honeypot."""

from __future__ import annotations

import argparse
import asyncio

from honeypot.config import ConfigError, load_settings
from honeypot.events import configure_stdio
from honeypot.privileges import maybe_drop
from honeypot.server import LabHoneypot, StartupError


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(description="Training honeypot with SSH, HTTP, and FTP decoys")
    parser.add_argument("--config", help="Path to honeypot.json")
    parser.add_argument("--bind", help="Override the decoy bind address")
    parser.add_argument("--dashboard-bind", help="Override the dashboard bind address")
    parser.add_argument("--log-dir", help="Directory for events.jsonl")
    parser.add_argument("--key-dir", help="Directory for the SSH host key")
    args = parser.parse_args(argv)
    try:
        settings = load_settings(
            args.config,
            bind_host=args.bind,
            dashboard_bind=args.dashboard_bind,
            log_dir=args.log_dir,
            key_dir=args.key_dir,
        )
    except ConfigError as exc:
        print(exc)
        return 1
    maybe_drop(settings.log_dir, settings.key_dir)
    lab = LabHoneypot(settings)
    try:
        asyncio.run(lab.serve_forever())
    except KeyboardInterrupt:
        print("\nStopped.")
    except (StartupError, RuntimeError) as exc:
        print(exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
