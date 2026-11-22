"""Shared event schema.

Every decoy writes the same flat record so the local report, the dashboard,
Filebeat, and Splunk can read one JSON object per line.
"""

from __future__ import annotations

import re
import sys
import uuid
from datetime import datetime, timezone

CATEGORIES = {
    "connection",
    "authentication",
    "recon",
    "collection",
    "egress_attempt",
}

NOT_EXECUTED = "Logged only. The command was not run, and no outbound connection was opened."
UPLOAD_DISCARDED = "Upload was hashed in memory and discarded. The bytes were not written to disk."
BODY_DISCARDED = "Request body was discarded and was not stored."
FORWARD_DENIED = "Forwarding was denied. No outbound connection was opened."

_EGRESS_TOKENS = {
    "wget",
    "curl",
    "tftp",
    "scp",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "base64",
}
_EGRESS_SNIPPETS = ("/dev/tcp", "/dev/udp", "bash -i")
_COLLECTION_MARKERS = (
    "/etc/shadow",
    "/etc/passwd",
    "/etc/gshadow",
    ".env",
    "id_rsa",
    "id_ed25519",
    ".git",
    "wp-config",
    "phpmyadmin",
    ".bash_history",
    "config.php",
)
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,180}", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9_./:+-]+")


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def clean(value: object, limit: int) -> str | None:
    """Drop control characters so one event stays on one log line."""
    if value is None:
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in str(value)).strip()
    if not text:
        return None
    if len(text) <= limit:
        return text
    if limit < 4:
        return text[:limit]
    return text[: limit - 3] + "..."


def as_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def extract_url(text: str | None) -> str | None:
    if not text:
        return None
    match = _URL_RE.search(text)
    if match is None:
        return None
    return match.group(0).rstrip(".,)")


def has_egress(text: str) -> bool:
    lowered = text.lower()
    if any(snippet in lowered for snippet in _EGRESS_SNIPPETS):
        return True
    tokens = _TOKEN_RE.findall(lowered)
    return any(token in _EGRESS_TOKENS for token in tokens)


def has_collection(command: str | None, path: str | None) -> bool:
    blob = f"{command or ''} {path or ''}".lower()
    if any(marker in blob for marker in _COLLECTION_MARKERS):
        return True
    first = (command or "").split(" ", 1)[0].upper()
    return first in {"RETR", "STOR", "APPE"}


def infer_category(event_type: str, command: str | None, path: str | None) -> str:
    if event_type in {"connection", "session_end"}:
        return "connection"
    if event_type == "auth_attempt":
        return "authentication"
    blob = f"{command or ''} {path or ''}"
    if has_egress(blob):
        return "egress_attempt"
    if has_collection(command, path):
        return "collection"
    return "recon"


def new_event(
    *,
    session_id: str,
    service: str,
    event_type: str,
    src_ip: str,
    src_port: int,
    dst_port: int,
    summary: str,
    category: str | None = None,
    username: str | None = None,
    password: str | None = None,
    command: str | None = None,
    path: str | None = None,
    status: str | None = None,
    indicator: str | None = None,
    user_agent: str | None = None,
    duration_ms: int | None = None,
    message: str = "",
    timestamp: str | None = None,
) -> dict:
    command_c = clean(command, 512)
    path_c = clean(path, 512)
    if indicator is None:
        indicator = extract_url(" ".join(part for part in (command_c, path_c) if part))
    chosen = category if category in CATEGORIES else None
    if chosen is None:
        chosen = infer_category(event_type, command_c, path_c)
    duration = as_int(duration_ms) if duration_ms is not None else None
    return {
        "timestamp": clean(timestamp, 40) or utcnow(),
        "event_id": uuid.uuid4().hex,
        "session_id": clean(session_id, 64) or "unknown",
        "service": clean(service, 20) or "unknown",
        "event_type": clean(event_type, 40) or "unknown",
        "category": chosen,
        "src_ip": clean(src_ip, 64) or "unknown",
        "src_port": as_int(src_port),
        "dst_port": as_int(dst_port),
        "username": clean(username, 128),
        "password": clean(password, 256),
        "command": command_c,
        "path": path_c,
        "status": clean(status, 40),
        "indicator": clean(indicator, 200),
        "user_agent": clean(user_agent, 200),
        "duration_ms": duration,
        "summary": clean(summary, 300) or (clean(event_type, 40) or "event"),
        "message": clean(message, 300) or "",
    }


def format_text(event: dict) -> str:
    parts = [
        str(event.get("timestamp", "")),
        str(event.get("session_id", ""))[:8],
        str(event.get("service", "")),
        str(event.get("category", "")),
        f"{event.get('src_ip', '')}:{event.get('src_port', '')}",
        str(event.get("summary", "")),
    ]
    if event.get("username"):
        parts.append(f"user={event['username']}")
    if event.get("password"):
        parts.append(f"password={event['password']}")
    if event.get("status"):
        parts.append(str(event["status"]))
    return " ".join(part for part in parts if part)
