"""Append-only JSONL log plus a one-line text log for the console."""

from __future__ import annotations

import json
import threading
import uuid
from collections import deque
from pathlib import Path

from honeypot.events import format_text, new_event

MAX_EVENTS = 10000


def parse_peer(peer: object) -> tuple[str, int]:
    if isinstance(peer, tuple) and len(peer) >= 2:
        host = "".join(ch for ch in str(peer[0]) if ch.isprintable())
        try:
            port = int(peer[1])
        except (TypeError, ValueError):
            port = 0
        return host or "unknown", port
    return "unknown", 0


def load_events(path: Path, limit: int = MAX_EVENTS) -> tuple[list[dict], int, bool]:
    if not path.exists():
        return [], 0, False
    kept: deque[dict] = deque(maxlen=limit)
    errors = 0
    truncated = False
    with path.open(encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                errors += 1
                continue
            if not isinstance(item, dict):
                errors += 1
                continue
            if len(kept) == limit:
                truncated = True
            kept.append(item)
    return list(kept), errors, truncated


class EventLog:
    def __init__(self, directory: Path, *, echo: bool = True) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.json_path = directory / "events.jsonl"
        self.text_path = directory / "events.log"
        self.echo = echo
        self._lock = threading.Lock()

    def write(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        text = format_text(event)
        with self._lock:
            with self.json_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
            with self.text_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(text + "\n")
        if self.echo:
            print(text, flush=True)

    def read(self, limit: int = MAX_EVENTS) -> tuple[list[dict], int, bool]:
        with self._lock:
            return load_events(self.json_path, limit=limit)


class Session:
    """One TCP connection. Events from that connection share session_id."""

    def __init__(
        self,
        log: EventLog,
        service: str,
        src_ip: str,
        src_port: int,
        dst_port: int,
    ) -> None:
        self.log = log
        self.service = service
        self.session_id = uuid.uuid4().hex
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.username: str | None = None
        self.count = 0
        self.record = True
        self._finished = False
        self._started = __import__("time").monotonic()

    def emit(self, **kwargs: object) -> dict | None:
        if not self.record:
            return None
        self.count += 1
        username = kwargs.pop("username", self.username)
        event = new_event(
            session_id=self.session_id,
            service=self.service,
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            username=username if isinstance(username, str) or username is None else str(username),
            **kwargs,  # type: ignore[arg-type]
        )
        self.log.write(event)
        return event

    def finish(self) -> None:
        if not self.record or self._finished:
            return
        self._finished = True
        import time

        duration_ms = int((time.monotonic() - self._started) * 1000)
        self.emit(
            event_type="session_end",
            summary="closed",
            status="closed",
            message=f"closed after {duration_ms} ms",
            duration_ms=duration_ms,
        )
