"""mod-audit: static supply-chain auditor for Claude Code Mods.

Local, offline, stdlib-only. Scans lifecycle hooks, TypeScript/JavaScript
source, env/API-key exfiltration patterns, and permissions manifests;
baselines a trusted state and diffs installed mods against it to catch
trojanized updates, emitting a delta risk report.
"""

__version__ = "0.2.0"

from .rules import (
    Finding,
    build_snapshot,
    diff_against_snapshot,
    diff_permissions,
    diff_verdict,
    format_diff_report,
    scan_mod,
    scan_ts_source,
    scan_hook_commands,
    scan_permissions,
)

__all__ = [
    "__version__",
    "Finding",
    "build_snapshot",
    "diff_against_snapshot",
    "diff_permissions",
    "diff_verdict",
    "format_diff_report",
    "scan_mod",
    "scan_ts_source",
    "scan_hook_commands",
    "scan_permissions",
]
