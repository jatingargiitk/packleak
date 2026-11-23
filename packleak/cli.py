import argparse
import json
import os
import sys

from . import __version__
from .scan import FIX, SEVERITY_ORDER, scan
from .sources import SourceError, is_allowed, load

NPM_FIX = {
    "SOURCEMAP_CONTENT": 'add "!**/*.map" to "files" in package.json (or "*.map" to .npmignore)',
    "SOURCEMAP_FILE": 'add "!**/*.map" to "files" in package.json (or "*.map" to .npmignore)',
    "ENV_FILE": 'use a "files" allowlist in package.json instead of relying on .npmignore',
    "KEY_FILE": 'use a "files" allowlist in package.json instead of relying on .npmignore',
    "REGISTRY_TOKEN": 'use a "files" allowlist in package.json instead of relying on .npmignore',
    "VCS_DIR": 'use a "files" allowlist in package.json instead of relying on .npmignore',
}

COLORS = {"high": "\033[31m", "warn": "\033[33m", "info": "\033[36m"}


def parse_allow(values):
    out = []
    for v in values:
        v = v.strip()
        if not v or v.startswith("#"):
            continue
        if ":" in v and v.split(":", 1)[0].isupper():
            rule, glob = v.split(":", 1)
        else:
            rule, glob = "*", v
        out.append((rule, glob))
    return out


def build_parser():
    p = argparse.ArgumentParser(
        prog="packleak",
        description="List what a package or build output would leak if you shipped it: "
                    "source maps with your original source, secrets in bundles, env files, keys, .git.")
    p.add_argument("target", help="build directory, npm .tgz, wheel/sdist, zip, or (with --npm) a package dir")
    p.add_argument("--npm", action="store_true",
                   help="scan exactly the files `npm pack --dry-run` would publish from this package dir")
    p.add_argument("--fail-on", choices=["high", "warn", "info", "never"], default="high",
                   help="exit 1 if any finding is at least this severe (default: high)")
    p.add_argument("--allow", action="append", default=[], metavar="[RULE:]GLOB",
                   help="ignore findings for files matching GLOB (optionally only for RULE); repeatable")
    p.add_argument("--allow-file", metavar="PATH",
                   help="file with one [RULE:]GLOB per line (default: .packleakignore in the target dir, if present)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-q", "--quiet", action="store_true", help="only print findings at or above --fail-on")
    p.add_argument("--version", action="version", version="packleak " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        entries, desc = load(args.target, npm=args.npm)
    except SourceError as exc:
        print("packleak: %s" % exc, file=sys.stderr)
        return 2

    allow_lines = list(args.allow)
    allow_file = args.allow_file
    if not allow_file and os.path.isdir(args.target):
        cand = os.path.join(args.target, ".packleakignore")
        if os.path.isfile(cand):
            allow_file = cand
    if allow_file:
        try:
            with open(allow_file, encoding="utf-8") as fh:
                allow_lines.extend(fh.read().splitlines())
        except OSError as exc:
            print("packleak: cannot read %s: %s" % (allow_file, exc), file=sys.stderr)
            return 2
    allows = parse_allow(allow_lines)

    findings = scan(entries)
    kept, ignored = [], 0
    for f in findings:
        if is_allowed(f.rule, f.path, allows):
            ignored += 1
        else:
            kept.append(f)

    threshold = None if args.fail_on == "never" else SEVERITY_ORDER[args.fail_on]
    failing = [f for f in kept if threshold is not None and SEVERITY_ORDER[f.severity] >= threshold]
    shown = failing if args.quiet else kept
    counts = {s: sum(1 for f in kept if f.severity == s) for s in ("high", "warn", "info")}

    if args.json:
        out = {
            "target": args.target,
            "source": desc,
            "files_scanned": len(entries),
            "counts": counts,
            "ignored": ignored,
            "findings": [],
        }
        for f in shown:
            d = f.to_dict()
            if args.npm and f.rule in NPM_FIX:
                d["fix"] = NPM_FIX[f.rule]
            out["findings"].append(d)
        print(json.dumps(out, indent=2))
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        print("packleak: %d file%s from %s" % (len(entries), "" if len(entries) == 1 else "s", desc))
        fixes_seen = set()
        for f in shown:
            sev = f.severity.upper().ljust(4)
            if color:
                sev = COLORS[f.severity] + sev + "\033[0m"
            print("%s  %-18s %s" % (sev, f.rule, f.where()))
            print("      %s" % f.detail)
            fix = NPM_FIX.get(f.rule) if args.npm else None
            fix = fix or FIX[f.rule]
            if (f.rule, fix) not in fixes_seen:
                fixes_seen.add((f.rule, fix))
                print("      fix: %s" % fix)
        summary = "%d high, %d warn, %d info" % (counts["high"], counts["warn"], counts["info"])
        if ignored:
            summary += ", %d allowed" % ignored
        verdict = "exit 1" if failing else "exit 0"
        print("%s -> %s" % (summary, verdict))
    return 1 if failing else 0
