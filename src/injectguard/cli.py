"""Command-line interface for injectguard.

Usage:
    injectguard file.md file2.txt          # scan files
    cat page.html | injectguard -          # scan stdin
    injectguard --json file.md            # machine-readable output
    injectguard --fail-on low file.md     # stricter CI gating
"""

import argparse
import json
import sys

from .scanner import scan_report
from . import __version__

EXIT_OK = 0
EXIT_WARN = 1
EXIT_BLOCK = 2
EXIT_USAGE = 64

_LEVEL_RANK = {"none": 0, "low": 1, "warn": 2, "block": 3}
_VERDICT_RANK = {"PASS": 0, "LOW": 1, "WARN": 2, "BLOCK": 3}


def build_parser():
    p = argparse.ArgumentParser(
        prog="injectguard",
        description="Zero-dependency prompt-injection scanner. Scans files "
                    "or stdin for LLM jailbreaks, instruction overrides, "
                    "exfil beacons and hidden payloads before they reach "
                    "your model or agent.",
    )
    p.add_argument("paths", metavar="PATH", nargs="*",
                   help="files to scan, or '-' for stdin")
    p.add_argument("--json", action="store_true",
                   help="emit a single JSON report instead of text")
    p.add_argument("--fail-on", choices=["none", "low", "warn", "block"],
                   default="warn",
                   help="exit nonzero when any file reaches this level "
                        "(default: warn)")
    p.add_argument("--quiet", action="store_true",
                   help="only print verdicts, no finding details")
    p.add_argument("--version", action="version",
                   version=f"injectguard {__version__}")
    return p


def _exit_code(verdict, fail_on):
    if _LEVEL_RANK[fail_on] == 0:      # --fail-on none: never fail
        return EXIT_OK
    if _VERDICT_RANK[verdict] >= _LEVEL_RANK[fail_on]:
        if verdict == "BLOCK":
            return EXIT_BLOCK
        return EXIT_WARN
    return EXIT_OK


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.paths:
        build_parser().print_usage(sys.stderr)
        print("error: give at least one PATH, or '-' for stdin",
              file=sys.stderr)
        return EXIT_USAGE

    reports = {}
    overall = "PASS"
    status = EXIT_OK

    for path in args.paths:
        try:
            if path == "-":
                text = sys.stdin.read()
            else:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
        except OSError as exc:
            print(f"injectguard: cannot read {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        rep = scan_report(text)
        reports[path] = rep
        if _VERDICT_RANK[rep.verdict] > _VERDICT_RANK[overall]:
            overall = rep.verdict
        code = _exit_code(rep.verdict, args.fail_on)
        if code > status:
            status = code

    if args.json:
        print(json.dumps({
            "tool": "injectguard",
            "version": __version__,
            "overall_verdict": overall,
            "exit_code": status,
            "files": {p: r.to_dict() for p, r in reports.items()},
        }, indent=2))
        return status

    for path, rep in reports.items():
        color = {
            "PASS": "\033[32m", "LOW": "\033[33m",
            "WARN": "\033[33;1m", "BLOCK": "\033[31;1m",
        }[rep.verdict]
        reset = "\033[0m"
        use_color = sys.stdout.isatty()
        label = f"{color}{rep.verdict}{reset}" if use_color else rep.verdict
        print(f"[{label}] {path}  (risk score {rep.score}, "
              f"{len(rep.findings)} finding(s))")
        if not args.quiet:
            for f in rep.findings:
                print(f"    {f.rule_id} {f.severity:>2}  {f.category}"
                      f"  line {f.line}:{f.column}")
                print(f"           {f.description}")
                print(f"           …{f.excerpt}…")
    print(f"overall: {overall}")
    return status


def main():
    sys.exit(run())


if __name__ == "__main__":
    main()
