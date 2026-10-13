"""Write the replay fixtures: the Hermes lab modelled as events, and benign look-alikes.

The lab fixture rebuilds the events seen in the Hermes Agent lab (see ../../README.md,
Timeline). Lineage, paths, timings, the Telegram address and the order of events are taken
from the lab's Security 4688, Defender 5007 and netstat output; host and user are renamed
and the Python folder name is shortened. Two things are modelled, not observed:
  - 5156 events: the lab had Filtering Platform auditing off; the connection itself
    (bundled python.exe -> 149.154.166.110:443) was seen with netstat.
  - burst-child-NN.exe: the lab showed 10 to 40 process creations under bash.exe per chat
    message; only whoami, hostname, ipconfig and ls are named here, the rest are placeholders.
For a real replay, export your own events with ../../scripts/export_lab_events.ps1.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOST = "LAB-WIN11"
HOME = r"C:\Users\lab\AppData\Local\hermes"
PY = HOME + r"\tools\python-3.14.7\python.exe"
PY_DEV = r"\device\harddiskvolume3" + PY[2:]
GITBIN = HOME + r"\tools\git-2.53.0+3-win32-x64\usr\bin"
SYS32 = r"C:\Windows\System32"
STARTUP_VBS = r"C:\Users\lab\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Hermes_Gateway.vbs"
DAY = "2026-10-12T"


def proc(t, image, parent, cmd):
    return {
        "TimeCreated": DAY + t + "+03:00",
        "Channel": "Security",
        "EventID": 4688,
        "Computer": HOST,
        "Image": image,
        "ParentImage": parent,
        "CommandLine": cmd,
    }


def wfp(t, app, dest, port=443):
    return {
        "TimeCreated": DAY + t + "+03:00",
        "Channel": "Security",
        "EventID": 5156,
        "Computer": HOST,
        "Application": app,
        "Direction": "%%14593",
        "DestAddress": dest,
        "DestPort": port,
    }


def defender(t, path):
    return {
        "TimeCreated": DAY + t + "+03:00",
        "Channel": "Microsoft-Windows-Windows Defender/Operational",
        "EventID": 5007,
        "Computer": HOST,
        "NewValue": rf"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\{path} = 0x0",
    }


def chat_message(t0, command, image):
    """One Telegram message: python -> bash -> the command, plus the rest of the burst."""
    hh, mm, ss = (int(x) for x in t0.split(":"))
    events = [proc(t0, GITBIN + r"\bash.exe", PY, f'"{GITBIN}\\bash.exe"')]
    events.append(
        proc(f"{hh:02}:{mm:02}:{ss + 2:02}", image, GITBIN + r"\bash.exe", command)
    )
    for n in range(11):
        events.append(
            proc(
                f"{hh:02}:{mm:02}:{ss + 3 + n:02}",
                GITBIN + rf"\burst-child-{n:02}.exe",
                GITBIN + r"\bash.exe",
                f"burst-child-{n:02}.exe",
            )
        )
    return events


def lab_events() -> list[dict]:
    ps = SYS32 + r"\WindowsPowerShell\v1.0\powershell.exe"
    ev = [
        proc(
            "07:45:49",
            SYS32 + r"\schtasks.exe",
            ps,
            'schtasks /create /tn OneDriveSync /tr "powershell -NoProfile -ExecutionPolicy Bypass '
            '-WindowStyle Hidden -File C:\\Users\\Public\\stage.ps1"',
        ),
        proc(
            "07:45:54",
            ps,
            SYS32 + r"\svchost.exe",
            "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Users\\Public\\stage.ps1",
        ),
        defender("08:32:22", HOME),
        wfp("12:14:13", PY_DEV, "149.154.166.110"),
        proc(
            "12:14:20",
            ps,
            PY,
            "powershell.exe -NoProfile -Command \"Get-CimInstance Win32_Process | ForEach-Object { 'CommandLine=' + $_.CommandLine }\"",
        ),
    ]
    ev += chat_message("12:23:05", "hostname", GITBIN + r"\hostname.exe")
    ev += chat_message("12:24:10", "whoami", GITBIN + r"\whoami.exe")
    ev += chat_message("12:25:20", "ipconfig /all", SYS32 + r"\ipconfig.exe")
    ev += [
        proc(
            "15:20:06",
            SYS32 + r"\wscript.exe",
            SYS32 + r"\explorer.exe",
            f'"{SYS32}\\wscript.exe" "{STARTUP_VBS}"',
        ),
        proc(
            "15:20:06",
            SYS32 + r"\wscript.exe",
            SYS32 + r"\wscript.exe",
            f'"{SYS32}\\wscript.exe" "{HOME}\\gateway-service\\Hermes_Gateway.vbs"',
        ),
        proc(
            "15:20:06",
            PY,
            SYS32 + r"\wscript.exe",
            f'"{PY}" -m hermes_cli.main gateway run',
        ),
        wfp("15:20:09", PY_DEV, "149.154.166.110"),
    ]
    return ev


def benign_events() -> list[dict]:
    dev_py = r"C:\Users\dev\AppData\Local\Programs\Python\Python312\python.exe"
    user_git = r"C:\Users\dev\AppData\Local\Programs\Git\usr\bin"
    pf_git = r"C:\Program Files\Git\usr\bin"
    ev = [
        # Admin checks identity from an interactive prompt.
        proc("09:00:00", SYS32 + r"\cmd.exe", SYS32 + r"\explorer.exe", "cmd.exe"),
        proc("09:00:05", SYS32 + r"\whoami.exe", SYS32 + r"\cmd.exe", "whoami /all"),
        # pip builds a package: per-user Python spawns cmd, no discovery, no Telegram.
        proc("09:10:00", SYS32 + r"\cmd.exe", dev_py, 'cmd.exe /c "build_ext.bat"'),
        # Same Python talks to GitHub, not Telegram.
        wfp("09:10:02", r"\device\harddiskvolume3" + dev_py[2:], "140.82.112.3"),
        # Telegram Web in a browser.
        wfp(
            "09:20:00",
            r"\device\harddiskvolume3\program files\google\chrome\application\chrome.exe",
            "149.154.167.99",
        ),
        # Defender exclusion for a build folder.
        defender("09:30:00", r"C:\Builds"),
    ]
    # Machine-wide Git Bash running a script: 15 children in a minute, outside AppData.
    ev += [
        proc(f"10:00:{s:02}", pf_git + r"\sed.exe", pf_git + r"\bash.exe", "sed")
        for s in range(15)
    ]
    # Per-user Git Bash used by hand: 5 commands in a minute, below the burst threshold.
    ev += [
        proc(f"10:30:{s * 10:02}", user_git + r"\ls.exe", user_git + r"\bash.exe", "ls")
        for s in range(5)
    ]
    return ev


def write(name: str, events: list[dict]) -> None:
    with (HERE / name).open("w", encoding="utf-8", newline="\n") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


if __name__ == "__main__":
    write("hermes_lab_modelled.jsonl", lab_events())
    write("benign.jsonl", benign_events())
    print("fixtures written")
