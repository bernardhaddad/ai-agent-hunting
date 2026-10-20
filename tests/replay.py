# Replays exported events (jsonl, Sigma field names) through the rules in ../sigma,
# correlations too. Only handles what these rules use: wildcards, cidr, and/or/not,
# temporal and event_count. Test harness, not a SIEM.
#
#   python replay.py lab_events.jsonl [--rules DIR]

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.types import SigmaCIDRExpression, SigmaNumber, SigmaString, SpecialChars

RULES_DIR = Path(__file__).resolve().parent.parent / "sigma"

# Which events each logsource applies to.
PROCESS_CREATION_IDS = {1, 4688}
REGISTRY_SET_IDS = {13, 4657}


def _logsource_applies(rule: SigmaRule, event: dict) -> bool:
    ls = rule.logsource
    eid = int(event.get("EventID", -1))
    channel = str(event.get("Channel", ""))
    if ls.category == "process_creation":
        return eid in PROCESS_CREATION_IDS
    if ls.category == "registry_set":
        return eid in REGISTRY_SET_IDS
    if ls.service == "windefend":
        return "Windows Defender" in channel
    if ls.service == "security":
        return channel == "Security"
    return True


def _string_regex(value: SigmaString) -> re.Pattern:
    parts = []
    for p in value.s:
        if p == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif p == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(p))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE | re.DOTALL)


def _value_matches(value, actual) -> bool:
    if actual is None:
        return False
    if isinstance(value, SigmaCIDRExpression):
        try:
            return ipaddress.ip_address(str(actual)) in value.network
        except ValueError:
            return False
    if isinstance(value, SigmaNumber):
        try:
            return int(actual) == int(value.number)
        except (TypeError, ValueError):
            return False
    if isinstance(value, SigmaString):
        return bool(_string_regex(value).match(str(actual)))
    raise NotImplementedError(f"value type {type(value).__name__}")


def _eval(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _value_matches(node.value, event.get(node.field))
    raise NotImplementedError(f"condition node {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    if not _logsource_applies(rule, event):
        return False
    return any(_eval(c.parse(), event) for c in rule.detection.parsed_condition)


def _ts(event: dict) -> float:
    return datetime.fromisoformat(
        event["TimeCreated"].replace("Z", "+00:00")
    ).timestamp()


def _windows(times: list[float], span: float):
    j = 0
    for i in range(len(times)):
        while times[i] - times[j] > span:
            j += 1
        yield j, i


def evaluate_correlation(
    corr: SigmaCorrelationRule, hits: dict[str, list[dict]]
) -> list[dict]:
    span = corr.timespan.seconds
    names = [r.rule.name if hasattr(r, "rule") else r.reference for r in corr.rules]
    grouped: dict[tuple, list[tuple[float, str]]] = defaultdict(list)
    for name in names:
        for ev in hits.get(name, []):
            key = tuple(str(ev.get(f, "")).lower() for f in corr.group_by)
            grouped[key].append((_ts(ev), name))
    alerts = []
    for key, items in grouped.items():
        items.sort()
        times = [t for t, _ in items]
        for j, i in _windows(times, span):
            window = items[j : i + 1]
            if corr.type.name == "TEMPORAL":
                ok = {n for _, n in window} >= set(names)
            elif corr.type.name == "EVENT_COUNT":
                ok = (
                    corr.condition.op.name == "GTE"
                    and len(window) >= corr.condition.count
                )
            else:
                raise NotImplementedError(f"correlation type {corr.type.name}")
            if ok:
                alerts.append(
                    {
                        "group": dict(zip(corr.group_by, key)),
                        "first": window[0][0],
                        "events": len(window),
                    }
                )
                break
    return alerts


def run(events: list[dict], rules_dir: Path = RULES_DIR) -> dict[str, list]:
    col = SigmaCollection.load_ruleset([rules_dir])
    col.resolve_rule_references()
    rules = [r for r in col.rules if isinstance(r, SigmaRule)]
    corrs = [r for r in col.rules if isinstance(r, SigmaCorrelationRule)]
    hits_by_name: dict[str, list[dict]] = defaultdict(list)
    fired: dict[str, list] = {}
    for rule in rules:
        matched = [e for e in events if rule_matches(rule, e)]
        if rule.name:
            hits_by_name[rule.name] = matched
        if matched:
            fired[rule.title] = matched
    for corr in corrs:
        alerts = evaluate_correlation(corr, hits_by_name)
        if alerts:
            fired[corr.title] = alerts
    return fired


def load_events(path: Path) -> list[dict]:
    events = []
    text = path.read_text(encoding="utf-8-sig")
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"{path}:{n}: not valid JSON ({exc}): {line[:200]}"
            ) from exc
    return events


def main() -> int:
    ap = argparse.ArgumentParser(description="replay events through the sigma rules")
    ap.add_argument("events", type=Path)
    ap.add_argument("--rules", type=Path, default=RULES_DIR)
    args = ap.parse_args()
    fired = run(load_events(args.events), args.rules)
    if not fired:
        print("No rules fired.")
    for title, items in fired.items():
        print(f"[{len(items):>3}] {title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
