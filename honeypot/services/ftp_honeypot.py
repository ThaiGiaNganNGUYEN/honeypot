"""Low-interaction FTP decoy.

Active mode (PORT and EPRT) is refused so the process never connects to an
address supplied by the client. Uploaded bytes are hashed and discarded.
"""

from __future__ import annotations

import hashlib

ACTIVE_MODE_REPLY = b"502 Active mode is disabled on this training decoy.\r\n"
README_BYTES = b"Training decoy file. Not a backup.\r\n"
DISCARDED_TEXT = b"This training decoy discarded the upload. Nothing was saved.\r\n"
MAX_UPLOAD = 65536


def upload_name(raw: str) -> str:
    name = raw.replace("\\", "/").split("/")[-1].strip()
    cleaned = "".join(ch for ch in name if ch.isascii() and (ch.isalnum() or ch in "._-"))
    if cleaned in {"", ".", ".."}:
        return "upload.bin"
    return cleaned[:80]


def preliminary_reply(line: str) -> bytes | None:
    stripped = line.strip()
    if not stripped:
        return None
    verb = stripped.split(" ", 1)[0].upper()
    if verb in {"PORT", "EPRT"}:
        return ACTIVE_MODE_REPLY
    return None


class FTPState:
    def __init__(self) -> None:
        self.username: str | None = None
        self.authed = False
        self.uploads: dict[str, int] = {}

    def listing(self) -> bytes:
        lines = ["-rw-r--r-- 1 ftp ftp 32 Nov 22 09:00 README.txt"]
        for name, size in self.uploads.items():
            lines.append(f"-rw-r--r-- 1 ftp ftp {size} Nov 22 09:00 {name}")
        return ("\r\n".join(lines) + "\r\n").encode("ascii", "replace")

    def file_bytes(self, name: str) -> bytes | None:
        if name in self.uploads:
            return DISCARDED_TEXT
        if name == "README.txt":
            return README_BYTES
        return None


def hash_upload(chunks: list[bytes]) -> tuple[str, int, bool]:
    """Hash a capped upload. The caller drops the chunks after this returns."""
    digest = hashlib.sha256()
    total = 0
    truncated = False
    for chunk in chunks:
        room = MAX_UPLOAD - total
        if room <= 0:
            truncated = True
            break
        piece = chunk[:room]
        digest.update(piece)
        total += len(piece)
        if len(chunk) > room:
            truncated = True
            break
    return digest.hexdigest(), total, truncated
