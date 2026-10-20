# ai-agent-hunting

Notes from treating AI agents like RMM tools: trusted, already installed, and happy to
take instructions from whoever is talking to them. One lab VM, versions below. Anything
not in the vendor docs can change between releases.

## Claude Code / Claude Desktop

A shell spawned by Claude Desktop (2.31226.1) had these in its environment:
`CLAUDECODE=1`, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_ENTRYPOINT=claude-desktop`,
`CLAUDE_CODE_USER_EMAIL`, `CLAUDE_CODE_ORGANIZATION_UUID`, `CLAUDE_CODE_OAUTH_SCOPES`.
The entrypoint, email and org UUID ones aren't documented, and the OAuth scopes one is only
documented as something you set yourself for token login. Good for attribution, but a
prompt-injected command inherits them too.

Worth collecting:
- `~/.claude/projects/<project>/<session>.jsonl` - every tool call and its output, plaintext
- `~/.claude/history.jsonl` - every prompt with timestamp, not cleaned up by default
- terminal sessions are deleted after 30 days by default, Desktop/Cowork ones are kept
  unless `desktopSessionCleanupPeriodDays` is set
- Desktop's files are under `AppData\Local\Packages\Claude_pzs8sxrjxfjjc\`, not `%APPDATA%`
- `HKCU\SOFTWARE\Policies\ClaudeCode` is read when there's no admin policy, and users can
  write to it

## Hermes Agent driven from Telegram

Hermes (Nous Research, 0.21.7) installed the way an attacker with a foothold would:
own Telegram bot, approvals off, persistent. Carbonato already does this on Docker hosts.

What stood out:
- Persistence fell back to the Startup folder: `wscript > wscript > hidden python ... gateway run`
- Commands run through Hermes' own Git Bash, so `whoami.exe` and `hostname.exe` come from
  `%LOCALAPPDATA%\hermes\tools\git-*\usr\bin`, not System32
- It runs `Get-CimInstance Win32_Process` over and over
- Output goes to Telegram and to the LLM provider
- The model sometimes answers without running anything (5 of my 12 requests)

Where the evidence is:
- `%LOCALAPPDATA%\hermes\state.db` (copy `-wal`/`-shm` too): `sessions` has the
  controller's Telegram ID, `messages` has every prompt, `tool_calls` and output
- `cron\jobs.json` - scheduled jobs and the chat they report to
- `config.yaml` - `approvals.mode`
- `.env` - bot token and API keys

## Rules

In `sigma/`. Two that name Hermes, a few generic ones (Defender exclusion on an agent
folder, approvals disabled, the ClaudeCode HKCU key, Startup vbs chain), and three
correlations that don't care what the agent is called:

- interpreter under AppData talking to Telegram + the same kind of interpreter starting a shell
- interpreter starting a shell + whoami/hostname/ipconfig with an AppData parent
- 10+ processes a minute from a bash.exe under AppData

On the lab events all three fired, and still fired after I renamed the agent. The
Hermes-named rules didn't.

## Scripts

- `tests/` - replays events through the rules, `python -m unittest discover -s tests`
- `scripts/export_lab_events.ps1` - exports events for `tests\replay.py`
- `scripts/verify_execution.py` - matches state.db against process events, shows which
  requests actually ran
- `scripts/hermes_triage.ps1` - collects the Hermes files (not the .env values)
- `scripts/run_lab_validation.ps1` - all of the above in one go on a lab VM

Rules are DRL 1.1, everything else MIT.
