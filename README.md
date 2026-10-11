# mod-audit

Static supply-chain auditor for **Claude Code Mods** — local, offline, stdlib-only.

Claude Code Mods are TypeScript plugin packages that usually live under
`~/.claude/plugins/` and run **lifecycle hooks with your shell privileges**.
A single trojanized mod update can pipe `curl | sh` straight into your
machine. mod-audit scans a mod before you install it, snapshots the trusted
state, and diffs later updates against that snapshot — so a pin-swap style
update hijack lights up instead of slipping through.

Zero third-party dependencies. Python >= 3.9. No network calls, ever.

## Why this exists

The agent supply chain is getting hit, repeatedly, in public:

- **AIR SkillJacking** — 925 skills hijacked, reaching an estimated 134k agents.
- **Plugin4Shell** — pin-swap attacks bypass SHA-pinning on plugin updates,
  swapping trusted code for malicious code between the pin check and install.
- **Pwn2Own Ireland** — a Codex argument-injection flaw worth $40k showed how
  agent tooling becomes a shell-execution primitive.
- **SKILLCLOAK** — cloaking techniques that bypass 90%+ of existing scanners.

Most defenses are either cloud-based scanners (your mod source leaves your
machine) or metadata-only reviewers that never look at the TypeScript that
actually runs. mod-audit does the opposite: it runs on your machine, offline,
and reads the code.

## How it differs

| | mod-audit | ClawSecure Watchtower | rad-security AgentKeeper |
|---|---|---|---|
| Where it runs | Local / offline | Cloud scan | Cloud scan |
| Audits Mod TypeScript source | Yes | Partial | No — plugin/skill metadata only |
| Lifecycle hook analysis | Yes (shell patterns) | Generic | Metadata-level |
| Trojanized-update diffing | Yes (`snapshot`/`diff`) | No | No |
| Dependencies | Zero (stdlib only) | SaaS | SaaS |

Positioning: **local + offline + Mod TypeScript code specialist**. It does not
replace a metadata/policy reviewer — it covers the layer those tools skip:
the code that actually executes on your box.

## Install

```bash
pip install mod-audit
```

## Quick start

```bash
# 1. Audit a mod before installing it
mod-audit scan ~/.claude/plugins/some-mod

# 2. Snapshot the trusted state right after a clean install
mod-audit snapshot ~/.claude/plugins/some-mod --out ~/snapshots/some-mod.snapshot

# 3. After every update, diff against the snapshot
mod-audit diff ~/.claude/plugins/some-mod --against ~/snapshots/some-mod.snapshot
```

JSON output for scripting:

```bash
mod-audit scan ./my-mod --format json
```

## What it checks

### 1. Dangerous lifecycle hooks (`plugin.json` / `hooks.json` / `package.json`)

| Rule | Severity | What it catches |
|---|---|---|
| `HOOK-PIPED-DOWNLOAD` | high | `curl … \| sh`, `wget … \| bash` in hooks |
| `HOOK-B64-EXEC` | high | base64 decode piped into execution |
| `HOOK-EXFIL` | high | `curl --data` exfiltrating data from a hook |
| `HOOK-REVERSE-SHELL` | critical | `nc -e`, `/dev/tcp/` reverse shells |
| `HOOK-SUDO` | high | privilege escalation in hooks |
| `HOOK-RM-RF` | high | destructive recursive deletes |
| `HOOK-CHMOD-EXEC` | medium | flipping files executable at install time |
| `HOOK-SHELL-EXEC` | medium | any other shell hook (runs as you) |

### 2. Shell-execution patterns in `.ts`/`.js` source

| Rule | Severity | What it catches |
|---|---|---|
| `TS-SHELL-TRUE` | high | `exec/spawn` with `shell: true` |
| `TS-EXEC-CONCAT` | high | concatenated/interpolated command strings |
| `TS-EXEC` | medium | `child_process` usage to review |
| `TS-EVAL` | high | `eval()` / `new Function()` |
| `TS-DYN-IMPORT` | medium | dynamic `require()`/`import()` with non-literal specifiers |
| `TS-PERSISTENCE` | high | cron/launchd persistence references |
| `TS-DOTFILE-WRITE` | medium | writes derived from `$HOME`/`$PATH` |

### 3. Env / API-key exfiltration

| Rule | Severity | What it catches |
|---|---|---|
| `ENV-EXFIL` | high | `process.env.*(API_KEY\|TOKEN\|SECRET\|PRIVATE)` within a few lines of a network sink (`fetch`, `axios`, `http.request`, …) |

### 4. Trojanized-update diff (`snapshot` / `diff`)

| Rule | Severity | What it catches |
|---|---|---|
| `DIFF-NEW-FILE` | medium | files that appeared since the snapshot |
| `DIFF-CHANGED-FILE` | medium | files whose hash changed |
| `DIFF-REMOVED-FILE` | low | files that disappeared |
| `DIFF-HOOK-CHANGED` | high | hook commands added or swapped since the snapshot |
| `DIFF-HOOK-REMOVED` | low | hook commands removed |

New and changed files are re-scanned with all content rules during `diff`.

### 5. Permissions manifest review

| Rule | Severity | What it catches |
|---|---|---|
| `PERM-SHELL-OVERGRANT` | high | shell granted without per-action confirmation |
| `PERM-TOOL-SHELL` | high | shell-capable tool granted without constraints |
| `PERM-NETWORK-OVERGRANT` | medium | unrestricted network access |
| `PERM-FS-OVERGRANT` | medium | broad filesystem write access |

Every finding includes the rule id, severity, `file:line`, an explanation,
and a concrete fix.

## CI integration

mod-audit is CI-ready: it exits `1` when any finding meets `--fail-on`
(default `high`), `0` when clean, `2` on usage errors.

```yaml
# .github/workflows/mod-audit.yml
name: mod-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install mod-audit
      - run: mod-audit scan ./my-mod --format json
```

Gate updates in a scheduled job:

```bash
mod-audit diff ~/.claude/plugins/my-mod --against ~/snapshots/my-mod.snapshot --fail-on medium
```

## Limitations

- **Offline heuristics, not a sandbox.** Rules are pattern-based and can miss
  obfuscated code or flag benign code. Treat findings as triage signals.
- **No execution.** The tool never runs mod code, which is the point — but it
  also means runtime-only behavior (e.g. payloads fetched at runtime) is out
  of scope.
- **Snapshot trust.** `diff` is only as trustworthy as the snapshot: take it
  from a clean install and store it where the mod updater cannot modify it.
- **TypeScript via regex, not a parser.** Keeps the tool stdlib-only and fast;
  heavily minified or dynamically generated code may need manual review.

## License

MIT — see [LICENSE](LICENSE).
