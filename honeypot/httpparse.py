"""Small HTTP reader shared by the decoy site and the analyst dashboard.

The reader keeps a capped amount of the body in memory so a client cannot
stream an unlimited upload into the process. Callers decide what, if anything,
is written to the log.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

_USER_KEYS = ("username", "user", "login", "email")
_PASSWORD_KEYS = ("password", "pass", "passwd", "pwd")


@dataclass
class HttpRequest:
    method: str
    target: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes
    username: str | None
    password: str | None
    user_agent: str | None
    content_type: str | None
    too_large: bool = False
    malformed: bool = False


def _first(values: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = values.get(key)
        if value:
            return value[:256]
    return None


def _form_values(text: str) -> dict[str, str]:
    if len(text) > 4000:
        text = text[:4000]
    parsed = parse_qs(text, keep_blank_values=False, max_num_fields=30)
    values: dict[str, str] = {}
    for key, items in parsed.items():
        if not items:
            continue
        values[key.lower()[:64]] = items[0][:256]
    return values


def credentials_from(target: str, body: bytes, content_type: str | None) -> tuple[str | None, str | None]:
    values = _form_values(urlsplit(target).query)
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if media == "application/x-www-form-urlencoded":
        values.update(_form_values(body.decode("utf-8", "replace")))
    elif media == "application/json" and body:
        try:
            data = json.loads(body[:16384].decode("utf-8", "replace"))
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for key, value in list(data.items())[:30]:
                if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    values[str(key).lower()[:64]] = str(value)[:256]
    return _first(values, _USER_KEYS), _first(values, _PASSWORD_KEYS)


def _parse_header(header: bytes, body: bytes, too_large: bool) -> HttpRequest | None:
    text = header.decode("iso-8859-1", "replace")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None
    parts = lines[0].split(" ")
    malformed = len(parts) < 2
    method = parts[0].upper() if parts else ""
    target = parts[1] if len(parts) > 1 else "/"
    if len(target) > 2000:
        target = target[:2000]
        too_large = True
    if not method.isalpha() or len(method) > 10:
        malformed = True
    split = urlsplit(target)
    path = split.path or "/"
    headers: dict[str, str] = {}
    for line in lines[1:51]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()[:64]] = value.strip()[:400]
    content_type = headers.get("content-type")
    username, password = credentials_from(target, body, content_type)
    return HttpRequest(
        method=method,
        target=target,
        path=path[:512],
        query=split.query[:1000],
        headers=headers,
        body=body,
        username=username,
        password=password,
        user_agent=headers.get("user-agent"),
        content_type=content_type,
        too_large=too_large,
        malformed=malformed,
    )


async def read_http_request(reader: asyncio.StreamReader, max_body: int = 16384) -> HttpRequest | None:
    try:
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=8)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return None
    head_text = header.decode("iso-8859-1", "replace")
    content_length = 0
    too_large = False
    for line in head_text.split("\r\n")[1:]:
        if line.lower().startswith("content-length:"):
            raw = line.split(":", 1)[1].strip()
            try:
                content_length = int(raw)
            except ValueError:
                return _parse_header(header, b"", True)
            break
        if line.lower().startswith("transfer-encoding:"):
            too_large = True
            content_length = 0
            break
    if content_length < 0:
        return _parse_header(header, b"", True)
    to_read = content_length
    if to_read > max_body:
        to_read = max_body
        too_large = True
    body = b""
    if to_read:
        try:
            body = await asyncio.wait_for(reader.readexactly(to_read), timeout=8)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None
    return _parse_header(header, body, too_large)
