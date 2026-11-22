"""Turn the JSONL log into a short analyst report."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from honeypot.config import ConfigError, load_settings
from honeypot.eventlog import load_events
from honeypot.events import configure_stdio


def _top(events: list[dict], key: str, limit: int = 8) -> list[dict]:
    counter: Counter[str] = Counter()
    for event in events:
        value = event.get(key)
        if isinstance(value, str) and value:
            counter[value] += 1
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def summarize(events: list[dict], parse_errors: int = 0, truncated: bool = False) -> dict:
    auth = [event for event in events if event.get("event_type") == "auth_attempt"]
    timestamps = [event.get("timestamp") for event in events if event.get("timestamp")]
    by_service = Counter(str(event.get("service") or "unknown") for event in events)
    by_category = Counter(str(event.get("category") or "unknown") for event in events)
    sources = {str(event.get("src_ip")) for event in events if event.get("src_ip")}
    sessions = {str(event.get("session_id")) for event in events if event.get("session_id")}
    return {
        "total_events": len(events),
        "parse_errors": parse_errors,
        "truncated": truncated,
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "unique_sources": len(sources),
        "unique_sessions": len(sessions),
        "by_service": dict(by_service.most_common()),
        "by_category": dict(by_category.most_common()),
        "top_sources": _top(events, "src_ip"),
        "top_usernames": _top(events, "username"),
        "top_passwords": _top(events, "password"),
        "top_commands": _top(events, "command"),
        "top_paths": _top(events, "path"),
        "indicators": _top(events, "indicator"),
        "auth_attempts": len(auth),
        "auth_accepted": sum(1 for event in auth if event.get("status") == "accepted"),
        "auth_rejected": sum(1 for event in auth if event.get("status") == "rejected"),
    }


def build_insights(summary: dict) -> list[str]:
    total = summary["total_events"]
    if total == 0:
        return [
            "No events yet. Start the honeypot, then run python -m honeypot.demo from a second terminal."
        ]
    insights = [
        (
            f"{total} events across {summary['unique_sessions']} sessions "
            f"from {summary['unique_sources']} source address(es)."
        )
    ]
    if summary["truncated"]:
        insights.append("This report uses the newest 10000 events. Older lines are still in the log file.")
    services = ", ".join(f"{name} ({count})" for name, count in summary["by_service"].items())
    if services:
        insights.append(f"Decoy services that received traffic: {services}.")
    if summary["auth_attempts"]:
        insights.append(
            f"{summary['auth_attempts']} credential submissions were recorded "
            f"({summary['auth_accepted']} accepted into a fake session, "
            f"{summary['auth_rejected']} rejected). "
            "Compare these passwords with real accounts. Acceptance only opened the decoy."
        )
    if summary["top_paths"]:
        path = summary["top_paths"][0]
        insights.append(
            f"The most requested path was {path['value']} ({path['count']} hits). "
            "On the real systems this personality imitates, confirm that path is not exposed."
        )
    if summary["indicators"]:
        shown = ", ".join(item["value"] for item in summary["indicators"][:5])
        insights.append(
            "These indicators were submitted to the decoy. Nothing was downloaded or executed. "
            f"Search DNS and proxy logs on the real network for: {shown}."
        )
    elif summary["by_category"].get("egress_attempt", 0):
        count = summary["by_category"]["egress_attempt"]
        insights.append(f"{count} commands looked like download or remote-access attempts. They were logged and not run.")
    collection = summary["by_category"].get("collection", 0)
    if collection:
        insights.append(
            f"{collection} events asked for sensitive-looking files. "
            "The decoy served only training content. Confirm the real servers do not expose those paths."
        )
    return insights[:6]


def _rows(title: str, items: list[dict]) -> list[str]:
    lines = [title]
    if not items:
        lines.append("  (none)")
        return lines
    for item in items:
        lines.append(f"  {item['value']}  {item['count']}")
    return lines


def format_report(summary: dict, insights: list[str], log_path: str | None = None) -> str:
    lines = ["Honeypot lab report"]
    if log_path:
        lines.append(f"Log: {log_path}")
    lines.append(f"Events: {summary['total_events']}")
    if summary.get("parse_errors"):
        lines.append(f"Unreadable lines skipped: {summary['parse_errors']}")
    window = "n/a"
    if summary.get("first_seen"):
        window = f"{summary['first_seen']} -> {summary['last_seen']}"
    lines.append(f"Window: {window}")
    lines.append(f"Sources: {summary['unique_sources']}")
    lines.append(f"Sessions: {summary['unique_sessions']}")
    lines.append("")
    lines.append("Services")
    if summary["by_service"]:
        for name, count in summary["by_service"].items():
            lines.append(f"  {name}  {count}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Categories")
    if summary["by_category"]:
        for name, count in summary["by_category"].items():
            lines.append(f"  {name}  {count}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Credential submissions")
    lines.append(f"  accepted into the decoy: {summary['auth_accepted']}")
    lines.append(f"  rejected: {summary['auth_rejected']}")
    if summary["top_passwords"]:
        lines.append("  These passwords were typed into the decoy. They did not open a real system.")
    lines.extend(["", *_rows("Top usernames", summary["top_usernames"])])
    lines.extend(["", *_rows("Top passwords", summary["top_passwords"])])
    lines.extend(["", *_rows("Top commands", summary["top_commands"])])
    lines.extend(["", *_rows("Top paths", summary["top_paths"])])
    lines.extend(["", *_rows("Indicators", summary["indicators"])])
    lines.extend(["", "Insights"])
    if insights:
        lines.extend(f"  - {item}" for item in insights)
    else:
        lines.append("  (none)")
    lines.append("")
    return "\n".join(lines)


def write_reports(summary: dict, insights: list[str], directory: Path, log_path: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    payload = dict(summary)
    payload["insights"] = insights
    (directory / "summary.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (directory / "report.txt").write_text(format_report(summary, insights, str(log_path)), encoding="utf-8")


def build_payload(events: list[dict], parse_errors: int, truncated: bool, log_path: Path) -> dict:
    summary = summarize(events, parse_errors, truncated)
    summary["insights"] = build_insights(summary)
    recent = list(reversed(events[-30:]))
    summary["recent"] = [
        {
            "timestamp": event.get("timestamp"),
            "service": event.get("service"),
            "category": event.get("category"),
            "src_ip": event.get("src_ip"),
            "src_port": event.get("src_port"),
            "summary": event.get("summary"),
            "username": event.get("username"),
            "password": event.get("password"),
            "status": event.get("status"),
            "indicator": event.get("indicator"),
            "message": event.get("message"),
        }
        for event in recent
    ]
    summary["log_path"] = str(log_path)
    return summary


def main(argv: list[str] | None = None) -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(description="Summarize the honeypot log")
    parser.add_argument("--config", help="Path to honeypot.json")
    parser.add_argument("--log", help="Path to events.jsonl")
    parser.add_argument("--out", default="reports", help="Directory for report.txt and summary.json")
    args = parser.parse_args(argv)
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(exc)
        return 1
    log_path = Path(args.log) if args.log else settings.log_dir / "events.jsonl"
    if not log_path.exists():
        print(f"No log file yet at {log_path}.")
        print("Start the honeypot and run: python -m honeypot.demo")
        return 1
    events, errors, truncated = load_events(log_path)
    summary = summarize(events, errors, truncated)
    insights = build_insights(summary)
    out = Path(args.out)
    if not out.is_absolute():
        out = Path.cwd() / out
    write_reports(summary, insights, out, log_path)
    print(format_report(summary, insights, str(log_path)))
    print(f"Wrote {out / 'report.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
