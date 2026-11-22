"""Load and check config/honeypot.json.

Paths inside the file are relative to the project root (the parent of config/).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path


class ConfigError(ValueError):
    """The honeypot config file is missing a value or has a bad one."""


def _require_object(data: object, label: str, allowed: set[str], required: set[str]) -> dict:
    if not isinstance(data, dict):
        raise ConfigError(f"{label} must be a JSON object")
    extra = set(data) - allowed
    if extra:
        names = ", ".join(sorted(extra))
        raise ConfigError(f"{label} has unknown settings: {names}")
    missing = required - set(data)
    if missing:
        names = ", ".join(sorted(missing))
        raise ConfigError(f"{label} is missing: {names}")
    return data


def _ascii(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ConfigError(f"{label} must be 1 to {limit} printable ASCII characters")
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in value):
        raise ConfigError(f"{label} must be printable ASCII")
    return value


def _text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ConfigError(f"{label} must be 1 to {limit} characters")
    if any(not ch.isprintable() for ch in value):
        raise ConfigError(f"{label} contains a control character")
    return value.strip()


def _port(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer port")
    if value < 0 or value > 65535:
        raise ConfigError(f"{label} must be between 0 and 65535")
    return value


def _bounded(value: object, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer")
    if value < low or value > high:
        raise ConfigError(f"{label} must be between {low} and {high}")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{label} must be true or false")
    return value


def _ip(value: object, label: str) -> str:
    text = _ascii(value, label, 64)
    try:
        ipaddress.ip_address(text)
    except ValueError as exc:
        raise ConfigError(f"{label} must be an IP address, not a hostname") from exc
    return text


def _hostname(value: object) -> str:
    text = _ascii(value, "ssh.hostname", 63)
    if not text[0].isalnum() or not all(ch.isalnum() or ch in ".-" for ch in text):
        raise ConfigError("ssh.hostname may contain only letters, digits, dots, and hyphens")
    return text


@dataclass
class SSHSettings:
    enabled: bool
    port: int
    banner: str
    hostname: str
    accept_passwords: bool
    reject_first_n: int
    max_auth_attempts: int


@dataclass
class HTTPSettings:
    enabled: bool
    port: int
    server_header: str
    site_name: str


@dataclass
class FTPSettings:
    enabled: bool
    port: int
    banner: str


@dataclass
class DashboardSettings:
    enabled: bool
    bind_host: str
    port: int


@dataclass
class Settings:
    bind_host: str
    log_dir: Path
    key_dir: Path
    session_timeout_seconds: int
    max_events_per_session: int
    max_concurrent_connections: int
    ssh: SSHSettings
    http: HTTPSettings
    ftp: FTPSettings
    dashboard: DashboardSettings
    project_root: Path

    @classmethod
    def from_dict(cls, data: object, project_root: Path) -> Settings:
        top = _require_object(
            data,
            "config",
            {
                "bind_host",
                "log_dir",
                "session_timeout_seconds",
                "max_events_per_session",
                "max_concurrent_connections",
                "ssh",
                "http",
                "ftp",
                "dashboard",
            },
            {
                "bind_host",
                "log_dir",
                "session_timeout_seconds",
                "max_events_per_session",
                "max_concurrent_connections",
                "ssh",
                "http",
                "ftp",
                "dashboard",
            },
        )
        ssh = _require_object(
            top["ssh"],
            "ssh",
            {
                "enabled",
                "port",
                "banner",
                "hostname",
                "accept_passwords",
                "reject_first_n",
                "max_auth_attempts",
            },
            {
                "enabled",
                "port",
                "banner",
                "hostname",
                "accept_passwords",
                "reject_first_n",
                "max_auth_attempts",
            },
        )
        http = _require_object(
            top["http"],
            "http",
            {"enabled", "port", "server_header", "site_name"},
            {"enabled", "port", "server_header", "site_name"},
        )
        ftp = _require_object(
            top["ftp"],
            "ftp",
            {"enabled", "port", "banner"},
            {"enabled", "port", "banner"},
        )
        dashboard = _require_object(
            top["dashboard"],
            "dashboard",
            {"enabled", "bind_host", "port"},
            {"enabled", "bind_host", "port"},
        )
        banner = _ascii(ssh["banner"], "ssh.banner", 200)
        if not banner.startswith("SSH-2.0-"):
            raise ConfigError("ssh.banner must start with SSH-2.0-")
        ftp_banner = _ascii(ftp["banner"], "ftp.banner", 200)
        if not ftp_banner.startswith("220 "):
            raise ConfigError("ftp.banner must start with '220 '")
        log_dir = _text(top["log_dir"], "log_dir", 200)
        return cls(
            bind_host=_ip(top["bind_host"], "bind_host"),
            log_dir=_resolve(project_root, log_dir),
            key_dir=project_root / "keys",
            session_timeout_seconds=_bounded(top["session_timeout_seconds"], "session_timeout_seconds", 5, 3600),
            max_events_per_session=_bounded(top["max_events_per_session"], "max_events_per_session", 10, 5000),
            max_concurrent_connections=_bounded(
                top["max_concurrent_connections"], "max_concurrent_connections", 1, 500
            ),
            ssh=SSHSettings(
                enabled=_bool(ssh["enabled"], "ssh.enabled"),
                port=_port(ssh["port"], "ssh.port"),
                banner=banner,
                hostname=_hostname(ssh["hostname"]),
                accept_passwords=_bool(ssh["accept_passwords"], "ssh.accept_passwords"),
                reject_first_n=_bounded(ssh["reject_first_n"], "ssh.reject_first_n", 0, 20),
                max_auth_attempts=_bounded(ssh["max_auth_attempts"], "ssh.max_auth_attempts", 1, 20),
            ),
            http=HTTPSettings(
                enabled=_bool(http["enabled"], "http.enabled"),
                port=_port(http["port"], "http.port"),
                server_header=_ascii(http["server_header"], "http.server_header", 80),
                site_name=_text(http["site_name"], "http.site_name", 60),
            ),
            ftp=FTPSettings(
                enabled=_bool(ftp["enabled"], "ftp.enabled"),
                port=_port(ftp["port"], "ftp.port"),
                banner=ftp_banner,
            ),
            dashboard=DashboardSettings(
                enabled=_bool(dashboard["enabled"], "dashboard.enabled"),
                bind_host=_ip(dashboard["bind_host"], "dashboard.bind_host"),
                port=_port(dashboard["port"], "dashboard.port"),
            ),
            project_root=project_root,
        )


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path


def project_root_from_config(path: Path) -> Path:
    path = path.resolve()
    if path.parent.name == "config":
        return path.parent.parent
    return path.parent


def resolve_config_path(given: str | None) -> Path:
    if given:
        return Path(given)
    cwd_candidate = Path.cwd() / "config" / "honeypot.json"
    if cwd_candidate.exists():
        return cwd_candidate
    packaged = Path(__file__).resolve().parents[1] / "config" / "honeypot.json"
    return packaged


def load_settings(
    config_path: str | Path | None = None,
    *,
    bind_host: str | None = None,
    dashboard_bind: str | None = None,
    log_dir: str | None = None,
    key_dir: str | None = None,
) -> Settings:
    path = resolve_config_path(str(config_path) if config_path else None)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file is not valid JSON: {exc}") from exc
    settings = Settings.from_dict(data, project_root_from_config(path))
    if bind_host is not None:
        settings.bind_host = _ip(bind_host, "bind host")
    if dashboard_bind is not None:
        settings.dashboard.bind_host = _ip(dashboard_bind, "dashboard bind host")
    if log_dir is not None:
        settings.log_dir = _resolve(Path.cwd(), _text(log_dir, "log dir", 200))
    if key_dir is not None:
        settings.key_dir = _resolve(Path.cwd(), _text(key_dir, "key dir", 200))
    if not any((settings.ssh.enabled, settings.http.enabled, settings.ftp.enabled)):
        raise ConfigError("Enable at least one of ssh, http, or ftp")
    return settings
