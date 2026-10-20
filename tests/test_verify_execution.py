# verify_execution.py against a fake state.db, no pysigma needed

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
import unittest.mock
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import verify_execution  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def _tool_call(command: str) -> str:
    # The shape Hermes stores: a JSON list of OpenAI-style tool calls.
    return json.dumps(
        [
            {
                "id": "c1",
                "type": "function",
                "function": {
                    "name": "terminal",
                    "arguments": json.dumps({"command": command}),
                },
            }
        ]
    )


class VerifyExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "state.db"
        con = sqlite3.connect(self.db)
        con.execute(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, user_id TEXT)"
        )
        con.execute(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, role TEXT,"
            " content TEXT, tool_calls TEXT, timestamp REAL)"
        )
        con.execute("INSERT INTO sessions VALUES ('s1', 'telegram', '111222333')")
        rows = [
            ("user", "whoami", None, "2026-10-12T12:24:09+03:00"),
            ("assistant", None, _tool_call("whoami"), "2026-10-12T12:24:10+03:00"),
            (
                "tool",
                '{"output": "lab\\\\lab", "exit_code": 0}',
                None,
                "2026-10-12T12:24:13+03:00",
            ),
            ("assistant", "You are lab\\lab.", None, "2026-10-12T12:24:15+03:00"),
            ("user", "whoami again", None, "2026-10-12T12:40:00+03:00"),
            ("assistant", "You are lab\\lab.", None, "2026-10-12T12:40:02+03:00"),
            ("user", "systeminfo", None, "2026-10-12T12:50:00+03:00"),
            (
                "assistant",
                None,
                _tool_call("systeminfo | findstr OS"),
                "2026-10-12T12:50:01+03:00",
            ),
        ]
        for role, content, calls, ts in rows:
            con.execute(
                "INSERT INTO messages (session_id, role, content, tool_calls, timestamp) VALUES ('s1', ?, ?, ?, ?)",
                (role, content, calls, _epoch(ts)),
            )
        con.commit()
        con.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_turns(self):
        turns = verify_execution.load_turns(self.db)
        self.assertEqual(
            [t["content"] for t in turns], ["whoami", "whoami again", "systeminfo"]
        )
        self.assertEqual([len(t["calls"]) for t in turns], [1, 0, 1])
        self.assertEqual(turns[0]["source"], "telegram")
        self.assertEqual(turns[0]["user_id"], "111222333")

    def test_program_name(self):
        self.assertEqual(verify_execution._program("whoami"), "whoami")
        self.assertEqual(
            verify_execution._program('"C:\\Windows\\System32\\ipconfig.exe" /all'),
            "ipconfig",
        )
        self.assertEqual(
            verify_execution._program("systeminfo | findstr OS"), "systeminfo"
        )

    def test_report_against_lab_events(self):
        out = io.StringIO()
        argv = [
            "verify_execution.py",
            str(self.db),
            str(FIXTURES / "hermes_lab_modelled.jsonl"),
        ]
        with (
            contextlib.redirect_stdout(out),
            unittest.mock.patch.object(sys, "argv", argv),
        ):
            verify_execution.main()
        report = out.getvalue()
        self.assertIn("EXECUTED         whoami", report)
        self.assertIn(r"usr\bin\whoami.exe", report)
        self.assertIn("NO TOOL CALL", report)  # the answer from memory
        self.assertIn("NO PROCESS EVENT systeminfo | findstr OS", report)


if __name__ == "__main__":
    unittest.main()
