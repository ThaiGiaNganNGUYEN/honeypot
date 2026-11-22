"""Drop root inside the container after the log directory is writable."""

from __future__ import annotations

import os
from pathlib import Path


def maybe_drop(log_dir: Path, key_dir: Path) -> None:
    if os.environ.get("HONEYPOT_DROP_PRIVILEGES") != "1":
        return
    if os.name != "posix":
        return
    if os.geteuid() != 0:
        return
    import pwd

    try:
        account = pwd.getpwnam("honeypot")
    except KeyError:
        print("Privilege drop skipped: user 'honeypot' does not exist.")
        return
    for path in (log_dir, key_dir):
        try:
            path.mkdir(parents=True, exist_ok=True)
            os.chown(path, account.pw_uid, account.pw_gid)
        except OSError as exc:
            print(f"Privilege drop skipped: could not prepare {path} ({exc}).")
            return
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    os.environ["HOME"] = account.pw_dir
    print(f"Dropped privileges to uid {account.pw_uid} ({account.pw_name}).")
