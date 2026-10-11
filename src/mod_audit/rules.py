"""Audit rules: hooks, TypeScript source, env exfiltration, permissions.

All rules are offline heuristics over static text. No code is executed.
Findings carry a stable rule id, severity, file:line, explanation, and fix.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterator, List, Optional, Tuple

SEVERITIES = ("low", "medium", "high", "critical")
_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Duplicated from mod_audit.__init__ to avoid a circular import at module load.
__version__ = "0.2.0"

TS_EXTS = (".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx")
CONFIG_FILES = ("plugin.json", "hooks.json", "package.json")
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "__pycache__"}


@dataclass
class Finding:
    rule_id: str
    severity: str  # low | medium | high | critical
    file: str
    line: int
    message: str
    fix: str

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# 1. Lifecycle hook scanning
# ---------------------------------------------------------------------------

# Hook command patterns -----------------------------------------------------
_PIPED_DOWNLOAD = re.compile(
    r"\b(curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(sh|bash|zsh|dash|fish)\b", re.I
)
_B64_DECODE_EXEC = re.compile(
    r"base64\s+(?:-d|--decode)\b|\bb64decode\b|"
    r"\$\(\s*echo\s+[A-Za-z0-9+/=]{16,}\s*\|\s*base64",
    re.I,
)
_CURL_DATA_EXFIL = re.compile(
    r"\bcurl\b[^\n;]*?(?:-d\b|--data(?:-binary|-urlencode)?\b)", re.I
)
_SUDO = re.compile(r"(?:^|[\s;&|])sudo(?:\s|$)", re.I)
_REVERSE_SHELL = re.compile(r"\b(nc|netcat|ncat|socat)\b[^|;&\n]*-e\b|/dev/tcp/", re.I)
_CHMOD_EXEC = re.compile(r"\bchmod\s+\+x\b", re.I)
_RM_RF = re.compile(r"\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-rf?\s+[/~]", re.I)
# Credential material: SSH keys, cloud credentials, key files, .env files.
# The .env alternative excludes `process.env.X` via the lookbehind.
_CRED_PATH = re.compile(
    r"~[/\\]\.(ssh|aws|gnupg)"
    r"|\$HOME[/\\]\.(ssh|aws)"
    r"|\.ssh/|id_rsa|id_ed25519"
    r"|\.aws/credentials"
    r"|\.pem\b|\.p12\b|\.pfx\b"
    r"|(?<![\w.])\.env\b"
    r"|credentials?\.json|token\.json|secrets?\.ya?ml",
    re.I,
)

# Keys whose string values are shell commands.
HOOK_CMD_KEYS = {"command", "cmd", "shell", "exec", "run", "script", "entrypoint"}
# Ancestor keys under which free-form strings are treated as hook commands.
HOOK_SECTION_KEYS = {"hooks", "lifecycle", "scripts"}
# Metadata keys under a hooks section whose string values are NOT commands
# (e.g. the {"type": "command"} discriminator in Claude Code hook configs).
HOOK_META_KEYS = {"type", "matcher", "name", "timeout", "description", "title"}


def _walk_hook_commands(node, ancestors: Tuple[str, ...] = ()) -> Iterator[Tuple[str, Tuple[str, ...]]]:
    """Yield (command_string, key_path) for every shell command in a config."""
    if isinstance(node, dict):
        in_hooks = any(a.lower() in HOOK_SECTION_KEYS for a in ancestors)
        for key, value in node.items():
            key_l = str(key).lower()
            if key_l in HOOK_CMD_KEYS and isinstance(value, str) and value.strip():
                yield value, ancestors + (str(key),)
            elif (
                in_hooks
                and key_l not in HOOK_META_KEYS
                and isinstance(value, str)
                and value.strip()
            ):
                # Free-form string directly under a hooks/lifecycle/scripts
                # section (e.g. {"hooks": {"setup": "npm install"}}).
                yield value, ancestors + (str(key),)
            else:
                yield from _walk_hook_commands(value, ancestors + (str(key),))
    elif isinstance(node, list):
        in_hooks = any(a.lower() in HOOK_SECTION_KEYS for a in ancestors)
        for idx, item in enumerate(node):
            if in_hooks and isinstance(item, str) and item.strip():
                yield item, ancestors + (str(idx),)
            else:
                yield from _walk_hook_commands(item, ancestors + (str(idx),))


def _line_of(text: str, needle: str) -> int:
    """Best-effort 1-based line number of needle inside text (0 if unknown)."""
    idx = text.find(needle)
    if idx < 0:
        return 0
    return text.count("\n", 0, idx) + 1


def audit_hook_command(command: str, relfile: str, line: int) -> List[Finding]:
    """Classify one lifecycle hook shell command into findings."""
    out: List[Finding] = []
    cmd = command.strip()

    def add(rule_id, severity, message, fix):
        out.append(Finding(rule_id, severity, relfile, line, message, fix))

    if _PIPED_DOWNLOAD.search(cmd):
        add(
            "HOOK-PIPED-DOWNLOAD", "high",
            f"Piped remote download into a shell in lifecycle hook: {cmd[:120]}",
            "Pin and vendor the script instead of piping curl/wget into sh; "
            "verify its checksum before execution.",
        )
    if _B64_DECODE_EXEC.search(cmd):
        add(
            "HOOK-B64-EXEC", "high",
            f"Base64 decode piped into execution in lifecycle hook: {cmd[:120]}",
            "Decode the payload offline, inspect it, and vendor the decoded "
            "script instead of decoding at install time.",
        )
    if _CURL_DATA_EXFIL.search(cmd):
        add(
            "HOOK-EXFIL", "high",
            f"Hook sends data over the network (curl --data): {cmd[:120]}",
            "Remove data exfiltration from lifecycle hooks; move telemetry to "
            "explicit, documented opt-in code.",
        )
    if _REVERSE_SHELL.search(cmd):
        add(
            "HOOK-REVERSE-SHELL", "critical",
            f"Possible reverse shell in lifecycle hook: {cmd[:120]}",
            "Remove immediately and treat the mod as compromised; reinstall "
            "from a trusted source.",
        )
    if _SUDO.search(cmd):
        add(
            "HOOK-SUDO", "high",
            f"Hook requests privilege escalation (sudo): {cmd[:120]}",
            "Lifecycle hooks should never need root; drop sudo and run the "
            "mod's setup steps manually with review.",
        )
    m = _CRED_PATH.search(cmd)
    if m:
        add(
            "HOOK-CRED-READ", "high",
            f"Hook touches credential material ({m.group(0)}): {cmd[:120]}",
            "Hooks must not read SSH keys, cloud credentials, or .env "
            "files; remove the read and audit where the data goes.",
        )
    if _RM_RF.search(cmd):
        add(
            "HOOK-RM-RF", "high",
            f"Destructive recursive delete in lifecycle hook: {cmd[:120]}",
            "Scope deletions to the mod's own directory and require explicit "
            "user confirmation.",
        )
    if _CHMOD_EXEC.search(cmd):
        add(
            "HOOK-CHMOD-EXEC", "medium",
            f"Hook marks a file executable (chmod +x): {cmd[:120]}",
            "Ship binaries with the executable bit already set instead of "
            "flipping it at install time.",
        )
    if not out:
        # Any remaining shell hook still runs with the user's privileges.
        add(
            "HOOK-SHELL-EXEC", "medium",
            f"Shell command in lifecycle hook: {cmd[:120]}",
            "Review the command; prefer declarative setup steps over shell "
            "hooks where the platform allows it.",
        )
    return out


def scan_hook_commands(config_text: str, relfile: str) -> List[Finding]:
    """Parse a JSON config and audit every lifecycle hook command in it."""
    findings: List[Finding] = []
    try:
        config = json.loads(config_text)
    except (json.JSONDecodeError, ValueError):
        return findings
    for command, _key_path in _walk_hook_commands(config):
        line = _line_of(config_text, command[:60])
        findings.extend(audit_hook_command(command, relfile, line))
    return findings


# ---------------------------------------------------------------------------
# 2. TypeScript / JavaScript source scanning
# ---------------------------------------------------------------------------

_CHILD_PROC_IMPORT = re.compile(
    r"""require\s*\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]""",
)
_EXEC_CALL = re.compile(r"\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
_SHELL_TRUE = re.compile(r"\bshell\s*:\s*true\b")
_CONCAT_ARG = re.compile(r"""['"`]\s*\+|\+\s*['"`]|\$\{""")
_EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
_DYN_REQUIRE = re.compile(r"\brequire\s*\(\s*(?![\'\"`])")
_DYN_IMPORT = re.compile(r"\bimport\s*\(\s*(?![\'\"`])")
_ENV_SECRET = re.compile(
    r"process\.env\.[A-Za-z0-9_]*?(?:API_KEY|TOKEN|SECRET|PRIVATE)[A-Za-z0-9_]*", re.I
)
_NET_SINK = re.compile(
    r"\b(fetch|axios\.(?:get|post|put|delete|request)|https?\.request|"
    r"XMLHttpRequest|\.post\s*\()\s*\(",
)
_WRITE_FILE = re.compile(r"\bwriteFile(?:Sync)?\s*\(")
_CRON_PERSIST = re.compile(r"crontab|launchd|LaunchAgents|/etc/cron", re.I)


def scan_ts_source(source: str, relfile: str) -> List[Finding]:
    """Heuristic scan of one TypeScript/JavaScript file."""
    findings: List[Finding] = []
    lines = source.splitlines()

    def add(rule_id, severity, lineno, message, fix):
        findings.append(Finding(rule_id, severity, relfile, lineno, message, fix))

    uses_child_process = bool(_CHILD_PROC_IMPORT.search(source))

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        m = _EXEC_CALL.search(stripped)
        if m:
            window = "\n".join(lines[i - 1 : i + 4])
            fn = m.group(1)
            if _SHELL_TRUE.search(window):
                add(
                    "TS-SHELL-TRUE", "high", i,
                    f"{fn}() invoked with shell:true — full shell parsing of the argument",
                    "Use execFile/spawn with an argv array and shell:false; "
                    "never pass interpolated strings to a shell.",
                )
            elif _CONCAT_ARG.search(stripped) or "`" in stripped and "${" in stripped:
                add(
                    "TS-EXEC-CONCAT", "high", i,
                    f"{fn}() called with a concatenated/interpolated command string",
                    "Build the command from a fixed argv array; validate or "
                    "allow-list any dynamic part.",
                )
            elif uses_child_process or fn in ("exec", "execSync"):
                add(
                    "TS-EXEC", "medium", i,
                    f"child_process.{fn}() usage — verify the argument is not attacker-controlled",
                    "Prefer execFile with argv arrays; audit where the "
                    "command string comes from.",
                )

        if _EVAL.search(stripped):
            add(
                "TS-EVAL", "high", i,
                "eval() / new Function() — dynamic code execution",
                "Replace with static code paths; if a template is needed, use "
                "a sandboxed expression evaluator.",
            )
        if _DYN_REQUIRE.search(stripped) or _DYN_IMPORT.search(stripped):
            add(
                "TS-DYN-IMPORT", "medium", i,
                "Dynamic require()/import() with a non-literal specifier",
                "Pin imports to string literals or an allow-list of module "
                "names; resolve paths against the mod directory.",
            )
        if _CRON_PERSIST.search(stripped):
            add(
                "TS-PERSISTENCE", "high", i,
                "Persistence mechanism referenced (cron/launchd)",
                "A mod has no business installing persistence; remove it.",
            )
        if _WRITE_FILE.search(stripped) and re.search(r"process\.env\.(HOME|PATH)", stripped):
            add(
                "TS-DOTFILE-WRITE", "medium", i,
                "Writes a file derived from $HOME/$PATH — possible dotfile tampering",
                "Confine writes to the mod's own directory.",
            )

        m = _CRED_PATH.search(stripped)
        if m:
            add(
                "TS-CRED-PATH", "high", i,
                f"Credential material referenced ({m.group(0)}) — SSH key, cloud credential, or .env read",
                "A mod has no legitimate reason to read your SSH keys or "
                "cloud credentials; remove the read.",
            )

    # Env/API-key exfiltration: secret env var within a few lines of a network sink.
    for i, line in enumerate(lines, start=1):
        if _ENV_SECRET.search(line):
            secret = _ENV_SECRET.search(line).group(0)
            window = "\n".join(lines[max(0, i - 2) : i + 3])
            if _NET_SINK.search(window):
                sink = _NET_SINK.search(window).group(1)
                add(
                    "ENV-EXFIL", "high", i,
                    f"{secret} appears near a network sink ({sink}) — possible key exfiltration",
                    "Keep secrets out of request bodies/URLs; route network "
                    "calls through an allow-listed host set.",
                )

    return findings


# ---------------------------------------------------------------------------
# 3. Permissions manifest review
# ---------------------------------------------------------------------------

def scan_permissions(config: dict, relfile: str) -> List[Finding]:
    """Flag over-broad permissions in a mod manifest."""
    findings: List[Finding] = []
    perms = config.get("permissions")
    if perms is None:
        return findings

    def add(rule_id, severity, message, fix):
        findings.append(Finding(rule_id, severity, relfile, 0, message, fix))

    if isinstance(perms, dict):
        shell = perms.get("shell")
        if shell in (True, "always", "allow"):
            add(
                "PERM-SHELL-OVERGRANT", "high",
                "Manifest grants shell execution without per-action confirmation",
                "Narrow to specific allow-listed commands or require explicit "
                "user confirmation per invocation.",
            )
        network = perms.get("network")
        if network in (True, "always", "allow", "*"):
            add(
                "PERM-NETWORK-OVERGRANT", "medium",
                "Manifest grants unrestricted network access",
                "Restrict to the documented host allow-list the mod actually needs.",
            )
        fs = perms.get("filesystem") or perms.get("fs")
        if fs in (True, "write", "read-write", "/") or (
            isinstance(fs, str) and fs.strip().startswith("/")
        ):
            add(
                "PERM-FS-OVERGRANT", "medium",
                "Manifest grants broad filesystem write access",
                "Scope filesystem access to the mod's own directory.",
            )
        tools = perms.get("tools")
        if isinstance(tools, list) and any(
            str(t).lower() in ("bash", "shell", "exec", "*") for t in tools
        ):
            add(
                "PERM-TOOL-SHELL", "high",
                "Manifest grants a shell-capable tool without constraints",
                "Remove the shell tool or bind it to an allow-listed command set.",
            )
    elif isinstance(perms, list):
        lowered = [str(p).lower() for p in perms]
        if any(p in ("shell", "bash", "exec", "*") for p in lowered):
            add(
                "PERM-SHELL-OVERGRANT", "high",
                "Manifest grants shell execution permission",
                "Narrow to specific allow-listed commands or require explicit "
                "user confirmation per invocation.",
            )
        if any(p in ("network", "internet", "*") for p in lowered):
            add(
                "PERM-NETWORK-OVERGRANT", "medium",
                "Manifest grants unrestricted network access",
                "Restrict to the documented host allow-list the mod actually needs.",
            )
    return findings


# ---------------------------------------------------------------------------
# 4. Mod-level orchestration + snapshots + delta risk report
# ---------------------------------------------------------------------------

_RISKY_CAP_HINTS = ("shell", "exec", "bash", "network", "internet", "fs", "filesystem")


def _perm_capabilities(perms) -> set:
    """Normalize a permissions value (dict or list) into capability strings."""
    caps = set()
    if isinstance(perms, dict):
        for key, value in perms.items():
            k = str(key).lower()
            if value is True or str(value).lower() in (
                "always", "allow", "true", "*", "write", "read-write", "/",
            ):
                caps.add(f"{k}=*")
            elif isinstance(value, list):
                for item in value:
                    caps.add(f"{k}:{str(item).lower()}")
            elif value:
                caps.add(f"{k}={str(value).lower()}")
    elif isinstance(perms, list):
        for item in perms:
            caps.add(str(item).lower())
    return caps


def diff_permissions(old_perms: Dict[str, object], new_perms: Dict[str, object]) -> List[Finding]:
    """Flag permission grants that appeared or widened since the snapshot."""
    findings: List[Finding] = []
    for rel in sorted(set(new_perms) | set(old_perms)):
        old_caps = _perm_capabilities(old_perms.get(rel))
        new_caps = _perm_capabilities(new_perms.get(rel))
        if rel not in old_perms and new_perms.get(rel) is not None:
            findings.append(Finding(
                "DIFF-PERM-ADDED", "medium", rel, 0,
                f"Permissions manifest appeared in update: {rel}",
                "Review the granted capabilities; an update should not "
                "silently introduce a permissions block.",
            ))
            continue
        for cap in sorted(new_caps - old_caps):
            severity = (
                "high"
                if any(h in cap for h in _RISKY_CAP_HINTS)
                else "medium"
            )
            findings.append(Finding(
                "DIFF-PERM-WIDENED", severity, rel, 0,
                f"Permission widened since snapshot ({cap}) in {rel}",
                "Permission escalation in an update is a classic trojanized-"
                "update signal; confirm it is documented and necessary.",
            ))
        for cap in sorted(old_caps - new_caps):
            findings.append(Finding(
                "DIFF-PERM-NARROWED", "low", rel, 0,
                f"Permission removed since snapshot ({cap}) in {rel}",
                "Confirm the removal is part of the documented update.",
            ))
    return findings


def diff_verdict(findings: List[Finding]) -> str:
    """One-line delta risk verdict from a diff finding list."""
    if not findings:
        return "VERDICT: LOW RISK — update delta is clean, no findings."
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    worst = max(counts, key=lambda s: _SEV_ORDER.get(s, 0))
    breakdown = ", ".join(
        f"{counts[s]} {s}" for s in SEVERITIES if s in counts
    )
    word = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}[worst]
    return f"VERDICT: {word} RISK — {breakdown} finding(s) in the update delta."


# Section assignment for the delta risk report, by rule-id prefix.
_REPORT_SECTIONS = (
    ("New network exfiltration", ("ENV-EXFIL", "HOOK-EXFIL")),
    ("Credential-path reads", ("TS-CRED-PATH", "HOOK-CRED-READ")),
    ("New or swapped hooks", ("DIFF-HOOK-CHANGED", "DIFF-HOOK-REMOVED") + tuple(
        r for r in ("HOOK-PIPED-DOWNLOAD", "HOOK-B64-EXEC", "HOOK-REVERSE-SHELL",
                    "HOOK-SUDO", "HOOK-RM-RF", "HOOK-CHMOD-EXEC", "HOOK-SHELL-EXEC"))),
    ("Permission changes", ("DIFF-PERM-WIDENED", "DIFF-PERM-ADDED",
                             "DIFF-PERM-NARROWED", "PERM-")),
    ("File inventory changes", ("DIFF-NEW-FILE", "DIFF-CHANGED-FILE",
                                "DIFF-REMOVED-FILE")),
)


def _report_section(rule_id: str) -> str:
    for title, prefixes in _REPORT_SECTIONS:
        if any(rule_id == p or rule_id.startswith(p) for p in prefixes):
            return title
    return "Other delta findings"


def format_diff_report(findings: List[Finding], root: str, snapshot: Dict) -> str:
    """Render the delta risk report: grouped findings + verdict."""
    lines = [
        "mod-audit DELTA RISK REPORT",
        f"Target:   {root}",
        f"Snapshot: {snapshot.get('generated_at', 'unknown time')} "
        f"({len(snapshot.get('files', {}))} files hashed)",
        "",
    ]
    if not findings:
        lines.append("No delta found. The installed mod matches the trusted baseline.")
        lines.append("")
        lines.append(diff_verdict(findings))
        return "\n".join(lines) + "\n"
    grouped: Dict[str, List[Finding]] = {}
    order: List[str] = []
    for f in findings:
        section = _report_section(f.rule_id)
        if section not in grouped:
            grouped[section] = []
            order.append(section)
        grouped[section].append(f)
    for section in order:
        items = sorted(
            grouped[section],
            key=lambda f: (-_SEV_ORDER.get(f.severity, 0), f.file, f.line),
        )
        lines.append(f"[{section}] ({len(items)})")
        for f in items:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"  [{f.severity.upper():8}] {f.rule_id}  {loc}")
            lines.append(f"             {f.message}")
        lines.append("")
    lines.append(diff_verdict(findings))
    return "\n".join(lines) + "\n"

def _iter_mod_files(root: str) -> Iterator[Tuple[str, str]]:
    """Yield (abspath, relpath) for auditable files, skipping vendored dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            yield os.path.join(dirpath, name), rel


def scan_mod(root: str) -> List[Finding]:
    """Run every rule over a mod directory."""
    findings: List[Finding] = []
    for abspath, rel in _iter_mod_files(root):
        base = os.path.basename(rel)
        if base in CONFIG_FILES:
            try:
                with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            findings.extend(scan_hook_commands(text, rel))
            try:
                config = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                config = {}
            if isinstance(config, dict):
                findings.extend(scan_permissions(config, rel))
        elif rel.lower().endswith(TS_EXTS):
            try:
                with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            findings.extend(scan_ts_source(text, rel))
    return findings


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_snapshot(root: str) -> Dict:
    """Capture a trusted state: file hashes + hook commands + permissions."""
    files: Dict[str, str] = {}
    hooks: List[Dict] = []
    permissions: Dict[str, object] = {}
    for abspath, rel in _iter_mod_files(root):
        try:
            files[rel] = sha256_file(abspath)
        except OSError:
            continue
        base = os.path.basename(rel)
        if base in CONFIG_FILES:
            try:
                with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                config = json.loads(text)
            except (OSError, ValueError):
                continue
            for command, _ in _walk_hook_commands(config):
                hooks.append({"file": rel, "command": command})
            if isinstance(config, dict) and config.get("permissions") is not None:
                permissions[rel] = config["permissions"]
    return {
        "tool": "mod-audit",
        "version": __version__,
        "files": files,
        "hooks": hooks,
        "permissions": permissions,
    }


def diff_against_snapshot(root: str, snapshot: Dict) -> List[Finding]:
    """Compare an installed mod against a trusted snapshot.

    Reports new/removed/changed files, hook changes, and re-runs content
    rules on anything new or changed — the trojanized-update audit.
    """
    findings: List[Finding] = []
    old_files: Dict[str, str] = snapshot.get("files", {})
    new_files: Dict[str, str] = {}
    for abspath, rel in _iter_mod_files(root):
        try:
            new_files[rel] = sha256_file(abspath)
        except OSError:
            continue

    def add(rule_id, severity, rel, message, fix):
        findings.append(Finding(rule_id, severity, rel, 0, message, fix))

    for rel in sorted(set(new_files) - set(old_files)):
        add(
            "DIFF-NEW-FILE", "medium", rel,
            f"New file appeared since snapshot: {rel}",
            "Verify the file is expected in this update; re-scan flagged it "
            "below if it contains suspicious patterns.",
        )
    for rel in sorted(set(old_files) - set(new_files)):
        add(
            "DIFF-REMOVED-FILE", "low", rel,
            f"File removed since snapshot: {rel}",
            "Confirm the removal is part of the documented update.",
        )
    changed = sorted(r for r in new_files if r in old_files and new_files[r] != old_files[r])
    for rel in changed:
        add(
            "DIFF-CHANGED-FILE", "medium", rel,
            f"File changed since snapshot: {rel}",
            "Review the change; content rules were re-run on it below.",
        )

    # Re-run content rules on new + changed files.
    for rel in sorted(set(changed) | (set(new_files) - set(old_files))):
        abspath = os.path.join(root, rel)
        base = os.path.basename(rel)
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if base in CONFIG_FILES:
            findings.extend(scan_hook_commands(text, rel))
            try:
                config = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                config = {}
            if isinstance(config, dict):
                findings.extend(scan_permissions(config, rel))
        elif rel.lower().endswith(TS_EXTS):
            findings.extend(scan_ts_source(text, rel))

    # Hook inventory comparison (catches pin-swap style hook swaps).
    old_cmds = {(h.get("file"), h.get("command")) for h in snapshot.get("hooks", [])}
    new_cmds = set()
    for abspath, rel in _iter_mod_files(root):
        if os.path.basename(rel) not in CONFIG_FILES:
            continue
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                config = json.load(fh)
        except (OSError, ValueError):
            continue
        for command, _ in _walk_hook_commands(config):
            new_cmds.add((rel, command))
    for rel, command in sorted(new_cmds - old_cmds):
        add(
            "DIFF-HOOK-CHANGED", "high", rel,
            f"Hook command added/changed since snapshot: {command[:120]}",
            "Treat unexpected hook changes as a compromise indicator; "
            "reinstall from the trusted source.",
        )
    for rel, command in sorted(old_cmds - new_cmds):
        add(
            "DIFF-HOOK-REMOVED", "low", rel,
            f"Hook command removed since snapshot: {command[:120]}",
            "Confirm the removal is part of the documented update.",
        )

    # Permission delta: grants that appeared, widened, or narrowed.
    old_perms: Dict[str, object] = snapshot.get("permissions", {})
    new_perms: Dict[str, object] = {}
    for abspath, rel in _iter_mod_files(root):
        if os.path.basename(rel) not in CONFIG_FILES:
            continue
        try:
            with open(abspath, "r", encoding="utf-8", errors="replace") as fh:
                config = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(config, dict) and config.get("permissions") is not None:
            new_perms[rel] = config["permissions"]
    findings.extend(diff_permissions(old_perms, new_perms))
    return findings


def severity_at_least(sev: str, threshold: str) -> bool:
    return _SEV_ORDER.get(sev, 0) >= _SEV_ORDER.get(threshold, 0)
