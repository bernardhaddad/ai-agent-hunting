"""Regression tests for the Sigma rules: run with `python -m unittest` from this folder.

Requires pySigma (pip install pysigma). See fixtures/build_fixtures.py for what the
fixtures model and what is observed vs modelled.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

try:
    import replay
except ImportError as exc:  # pySigma missing
    raise unittest.SkipTest(f"pySigma not installed: {exc}") from exc

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Alerting rules: anything at low or informational is a building block for a correlation.
RECON = "AI Agent Style Recon - Interpreter Shell And Discovery Together"
BURST = "Burst Of Processes From A Bundled POSIX Shell Under AppData"
C2 = "Chat-Controlled Agent - Telegram Connection And Shell Execution"
CORRELATIONS = {RECON, BURST, C2}
HERMES_SPECIFIC = {
    "Command Executed By Hermes Agent Terminal Tool",
    "Hermes Agent Gateway Launched Via VBScript",
}
DEFENDER = "Defender Exclusion Added For An AI Agent Folder"
BUILDING_BLOCKS = {
    "Script Interpreter Under AppData Spawns A Shell",
    "Discovery Utility Started From A Process Under AppData",
    "Process Started By A POSIX Shell Under AppData",
    "Script Interpreter Under AppData Connects To Telegram",
}


def _renamed(events: list[dict]) -> list[dict]:
    """The same intrusion with the agent's folder, module and launcher renamed."""
    text = json.dumps(events)
    for old, new in (
        (r"\\hermes", r"\\notes-sync"),
        ("hermes_cli.main", "nsync.main"),
        ("Hermes_Gateway", "NotesSync"),
    ):
        text = text.replace(old, new)
    assert "hermes" not in text.lower()
    return json.loads(text)


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = replay.load_events(FIXTURES / "hermes_lab_modelled.jsonl")
        cls.benign = replay.load_events(FIXTURES / "benign.jsonl")

    def test_lab_fires_every_correlation_and_hermes_rule(self):
        fired = replay.run(self.lab)
        for title in CORRELATIONS | HERMES_SPECIFIC | {DEFENDER}:
            self.assertIn(title, fired)

    def test_startup_chain_rule_needs_parent_command_line(self):
        # 4688 has no ParentCommandLine, so this Sysmon/EDR rule stays silent on native logs.
        fired = replay.run(self.lab)
        self.assertNotIn(
            "Startup Folder VBScript Launching A Second Script Host", fired
        )

    def test_benign_raises_no_alert(self):
        fired = replay.run(self.benign)
        self.assertEqual(set(fired) - BUILDING_BLOCKS, set())

    def test_renamed_agent_evades_hermes_rules_but_not_correlations(self):
        fired = replay.run(_renamed(self.lab))
        self.assertEqual(set(fired) & HERMES_SPECIFIC, set())
        self.assertEqual(set(fired) & CORRELATIONS, CORRELATIONS)

    def test_bundled_whoami_is_caught_by_name_not_path(self):
        fired = replay.run(self.lab)
        images = {
            e["Image"]
            for e in fired["Discovery Utility Started From A Process Under AppData"]
        }
        self.assertTrue(any(r"\usr\bin\whoami.exe" in i for i in images))

    def test_burst_threshold(self):
        bash = next(e for e in self.lab if e.get("Image", "").endswith(r"\bash.exe"))
        children = [e for e in self.lab if e.get("ParentImage") == bash["Image"]]
        first_message = [e for e in children if e["TimeCreated"] < "2026-10-12T12:24"]
        self.assertNotIn(BURST, replay.run(first_message[:9]))
        self.assertIn(BURST, replay.run(first_message[:10]))


if __name__ == "__main__":
    unittest.main()
