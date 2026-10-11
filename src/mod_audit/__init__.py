"""mod-audit: static supply-chain auditor for Claude Code Mods.

Local, offline, stdlib-only. Scans lifecycle hooks, TypeScript/JavaScript
source, env/API-key exfiltration patterns, and permissions manifests;
snapshots a trusted state and diffs installed mods against it to catch
trojanized updates.
"""

__version__ = "0.1.0"

from .rules import Finding, scan_mod, scan_ts_source, scan_hook_commands, scan_permissions

__all__ = [
    "__version__",
    "Finding",
    "scan_mod",
    "scan_ts_source",
    "scan_hook_commands",
    "scan_permissions",
]
