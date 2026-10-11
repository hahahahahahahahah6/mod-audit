"""mod-audit CLI: scan, snapshot, diff for Claude Code Mods."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

from . import __version__
from .rules import (
    SEVERITIES,
    build_snapshot,
    diff_against_snapshot,
    scan_mod,
    severity_at_least,
)


def _format_text(findings) -> str:
    if not findings:
        return "mod-audit: no findings. Mod looks clean.\n"
    lines = []
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"[{f.severity.upper():8}] {f.rule_id}  {loc}")
        lines.append(f"           {f.message}")
        lines.append(f"           Fix: {f.fix}")
    summary = {}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    lines.append("")
    lines.append(
        "Findings: %d (%s)"
        % (len(findings), ", ".join(f"{k}={v}" for k, v in sorted(summary.items())))
    )
    return "\n".join(lines) + "\n"


def _emit(findings, fmt: str) -> int:
    if fmt == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        sys.stdout.write(_format_text(findings))
    return 0


def cmd_scan(args) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"mod-audit: not a directory: {args.path}", file=sys.stderr)
        return 2
    findings = scan_mod(root)
    _emit(findings, args.format)
    if any(severity_at_least(f.severity, args.fail_on) for f in findings):
        return 1
    return 0


def cmd_snapshot(args) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"mod-audit: not a directory: {args.path}", file=sys.stderr)
        return 2
    manifest = build_snapshot(root)
    manifest["generated_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    manifest["root"] = root

    out = args.out or os.path.join(
        os.getcwd(), os.path.basename(root.rstrip(os.sep)) + ".snapshot"
    )
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "manifest.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    print(f"mod-audit: snapshot written to {path}")
    print(f"  files: {len(manifest['files'])}, hooks: {len(manifest['hooks'])}")
    print("Keep this snapshot somewhere the mod updater cannot modify.")
    return 0


def cmd_diff(args) -> int:
    root = os.path.abspath(args.installed_dir)
    snap_dir = os.path.abspath(args.against)
    manifest_path = (
        snap_dir
        if snap_dir.endswith(".json")
        else os.path.join(snap_dir, "manifest.json")
    )
    if not os.path.isdir(root):
        print(f"mod-audit: not a directory: {args.installed_dir}", file=sys.stderr)
        return 2
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            snapshot = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"mod-audit: cannot read snapshot {manifest_path}: {exc}", file=sys.stderr)
        return 2
    findings = diff_against_snapshot(root, snapshot)
    _emit(findings, args.format)
    if any(severity_at_least(f.severity, args.fail_on) for f in findings):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mod-audit",
        description="Static supply-chain auditor for Claude Code Mods (local, offline, stdlib-only).",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Audit a mod directory for supply-chain risks.")
    s.add_argument("path", help="Path to the mod directory (e.g. ~/.claude/plugins/foo).")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="high",
        help="Exit 1 if any finding meets this severity (default: high).",
    )
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("snapshot", help="Save a trusted snapshot of a mod.")
    s.add_argument("path", help="Path to the mod directory.")
    s.add_argument("--out", help="Snapshot directory (default: ./<mod-name>.snapshot).")
    s.set_defaults(func=cmd_snapshot)

    s = sub.add_parser("diff", help="Diff an installed mod against a trusted snapshot.")
    s.add_argument("installed_dir", help="Path to the installed mod directory.")
    s.add_argument(
        "--against", required=True, help="Snapshot directory or manifest.json from `snapshot`."
    )
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--fail-on", choices=SEVERITIES, default="high")
    s.set_defaults(func=cmd_diff)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
