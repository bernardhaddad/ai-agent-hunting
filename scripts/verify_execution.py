# Which Hermes tool calls actually ran. Joins state.db with 4688 / Sysmon 1 events
# exported by export_lab_events.ps1. The model sometimes answers without running anything,
# so a transcript on its own doesn't prove execution.
#
#   python verify_execution.py state.db lab_events.jsonl [--window 60]
#
# Copy state.db with its -wal and -shm first, it's opened read-only.

from __future__ import annotations

import argparse
import json
import re
import shlex
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def _program(command: str) -> str:
    first = re.split(r"[|;&]", command, maxsplit=1)[0].strip()
    try:
        token = shlex.split(first, posix=False)[0]
    except (IndexError, ValueError):
        return ""
    return re.sub(r"\.exe$", "", re.split(r"[\\/]", token.strip("\"'"))[-1].lower())


def _process_times(events_path: Path) -> list[tuple[float, str, str]]:
    out = []
    for line in events_path.read_text(encoding="utf-8-sig").splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if int(e.get("EventID", 0)) not in (1, 4688) or not e.get("Image"):
            continue
        ts = datetime.fromisoformat(e["TimeCreated"].replace("Z", "+00:00")).timestamp()
        name = re.sub(r"\.exe$", "", re.split(r"[\\/]", e["Image"])[-1].lower())
        out.append((ts, name, e["Image"]))
    return out


def _prompt_text(content) -> str:
    text = str(content or "")
    if text.startswith("Gateway message origin"):
        lines = [line for line in text.splitlines() if line.strip()]
        text = lines[-1] if len(lines) > 1 else text
    return " ".join(text.split())[:80]


def load_turns(db: Path) -> list[dict]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """SELECT m.session_id, m.role, m.timestamp, m.content, m.tool_calls, s.source, s.user_id
           FROM messages m LEFT JOIN sessions s ON s.id = m.session_id
           ORDER BY m.session_id, m.timestamp, m.id"""
    ).fetchall()
    con.close()
    turns: list[dict] = []
    for r in rows:
        if r["role"] == "user":
            turns.append({**dict(r), "calls": []})
            continue
        if r["role"] != "assistant" or not r["tool_calls"] or not turns:
            continue
        if turns[-1]["session_id"] != r["session_id"]:
            continue
        parsed = json.loads(r["tool_calls"])
        for tc in parsed if isinstance(parsed, list) else [parsed]:
            fn = tc.get("function", tc)
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}
            command = args.get("command") if isinstance(args, dict) else None
            turns[-1]["calls"].append(
                {
                    "timestamp": r["timestamp"],
                    "tool": fn.get("name"),
                    "command": command,
                }
            )
    return turns


def main() -> int:
    ap = argparse.ArgumentParser(description="check Hermes tool calls against process events")
    ap.add_argument("state_db", type=Path)
    ap.add_argument("events", type=Path)
    ap.add_argument(
        "--window", type=float, default=60.0, help="seconds after the tool call"
    )
    args = ap.parse_args()

    procs = _process_times(args.events)
    first_event = min((p[0] for p in procs), default=float("inf"))
    for t in load_turns(args.state_db):
        when = datetime.fromtimestamp(t["timestamp"], tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        prompt = _prompt_text(t["content"])
        print(f"[{when} UTC] {t['source'] or '?'} user {t['user_id'] or '?'}: {prompt}")
        if not t["calls"]:
            print("    NO TOOL CALL: the reply was not backed by any execution")
        for c in t["calls"]:
            if not c["command"]:
                print(f"    tool {c['tool']} (no shell command)")
                continue
            prog = _program(c["command"])
            seen = [
                p
                for p in procs
                if p[1] == prog and 0 <= p[0] - c["timestamp"] <= args.window
            ]
            if seen:
                verdict = "EXECUTED"
            elif c["timestamp"] < first_event:
                verdict = "BEFORE EXPORT"
            else:
                verdict = "NO PROCESS EVENT"
            print(f"    {verdict:16} {c['command']}")
            for p in seen[:3]:
                print(f"    {'':16} -> {p[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
