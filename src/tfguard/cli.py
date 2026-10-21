"""Command line: scan, fix, verify, eval, rules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .hcl import ParseError, load_files, read_dir
from .policies import RULES, scan
from .report import SEVERITY_ORDER, findings_sarif, findings_text, pr_body, run_text

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _fail_on(findings, threshold: str) -> bool:
    if threshold == "none":
        return False
    limit = SEVERITY_ORDER.index(threshold)
    return any(SEVERITY_ORDER.index(f.severity) <= limit for f in findings)


def cmd_scan(args: argparse.Namespace) -> int:
    findings = scan(load_files(read_dir(args.path)))
    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif args.format == "sarif":
        sarif = findings_sarif(findings, args.sarif_base)
        if args.output:
            Path(args.output).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        else:
            print(json.dumps(sarif, indent=2))
    else:
        print(findings_text(findings))
    return EXIT_FINDINGS if _fail_on(findings, args.fail_on) else EXIT_OK


def _make_fixer(spec: str):
    if spec.startswith("scripted:"):
        from .fixer import ScriptedFixer

        return ScriptedFixer.from_file(spec.split(":", 1)[1])
    if spec == "anthropic":
        from .fixer import AnthropicFixer

        return AnthropicFixer()
    raise SystemExit(f"unknown fixer {spec!r}; use 'anthropic' or 'scripted:<file.json>'")


def cmd_fix(args: argparse.Namespace) -> int:
    from .pipeline import run_fixes

    files = read_dir(args.path)
    run = run_fixes(files, _make_fixer(args.fixer), args.max_attempts,
                    set(args.rule) if args.rule else None)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in run.patched.items():
        # Triaged: `name` is a file that already existed in the scanned directory.
        # apply_edits() rejects any edit naming a file outside the module, so the
        # model cannot introduce a new path here.
        (out / name).write_text(text, encoding="utf-8")  # nosemgrep: tfguard-untrusted-text-to-dangerous-sink
    (out / "tfguard-fix.patch").write_text(run.unified_diff(), encoding="utf-8")
    (out / "tfguard-pr.md").write_text(pr_body(run), encoding="utf-8")
    (out / "tfguard-report.json").write_text(
        json.dumps({"kpis": run.kpis(), "results": [r.to_dict() for r in run.results],
                    "remaining": [f.to_dict() for f in run.final_findings]}, indent=2),
        encoding="utf-8",
    )
    print(run_text(run))
    print(f"\npatched module, patch, PR body and report written to {out}/")
    return EXIT_FINDINGS if _fail_on(run.final_findings, args.fail_on) else EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    from .verifier import REJECT, verify

    before_files = read_dir(args.path)
    module = load_files(before_files)
    findings = scan(module)
    after = {p.name: p.read_text(encoding="utf-8") for p in Path(args.patched).glob("*.tf")}
    targets = [f for f in findings
               if (not args.rule or f.rule_id == args.rule)
               and (not args.address or f.address == args.address)]
    v = verify(module, after, targets, findings)
    if args.format == "json":
        print(json.dumps(v.to_dict(), indent=2))
    else:
        print(f"verdict: {v.verdict}")
        for e in v.errors:
            print(f"  error   {e}")
        for r in v.reviews:
            print(f"  review  {r}")
        for c in v.changes:
            print(f"  change  {c}")
    return EXIT_FINDINGS if v.verdict == REJECT else EXIT_OK


def cmd_eval(args: argparse.Namespace) -> int:
    from .evaluate import run_gallery

    results, metrics = run_gallery(args.cases)
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        extra = f"  missing codes {r.missing_codes}" if r.missing_codes else ""
        print(f"{mark}  {r.kind:6}  {r.name:50} expected {r.expected:6} got {r.got:6} "
              f"{','.join(r.codes)}{extra}")
    print(f"\n{metrics['passed']}/{metrics['cases']} cases as expected | "
          f"cheat catch rate {metrics['cheat_catch_rate']} | "
          f"honest pass rate {metrics['honest_pass_rate']}")
    return EXIT_OK if metrics["passed"] == metrics["cases"] else EXIT_FINDINGS


def cmd_rules(args: argparse.Namespace) -> int:
    for r in RULES:
        print(f"{r.id:11} {r.severity:8} {r.title}")
        print(f"{'':20}may change: {', '.join(r.fix_paths) or '-'}")
        if r.companions:
            print(f"{'':20}may add: {', '.join(c.type for c in r.companions)}")
        if r.review_reason:
            print(f"{'':20}always reviewed: {r.review_reason}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tfguard", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sev = ["critical", "high", "medium", "low", "none"]

    s = sub.add_parser("scan", help="scan a Terraform module")
    s.add_argument("path")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--output", help="write SARIF to this file")
    s.add_argument("--sarif-base", default="", help="path prefix for SARIF file URIs")
    s.add_argument("--fail-on", choices=sev, default="high")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="propose, verify and apply fixes")
    f.add_argument("path")
    f.add_argument("--out", required=True, help="directory for the patched module and reports")
    f.add_argument("--fixer", default="anthropic", help="anthropic | scripted:<file.json>")
    f.add_argument("--max-attempts", type=int, default=3)
    f.add_argument("--rule", action="append", help="only fix this rule id (repeatable)")
    f.add_argument("--fail-on", choices=sev, default="none")
    f.set_defaults(func=cmd_fix)

    v = sub.add_parser("verify", help="verify a patched copy of a module (from any source)")
    v.add_argument("path")
    v.add_argument("--patched", required=True)
    v.add_argument("--rule")
    v.add_argument("--address")
    v.add_argument("--format", choices=["text", "json"], default="text")
    v.set_defaults(func=cmd_verify)

    e = sub.add_parser("eval", help="run the cheat gallery against the verifier")
    e.add_argument("--cases", default="examples/cases/gallery.json")
    e.set_defaults(func=cmd_eval)

    r = sub.add_parser("rules", help="list policies and their fix scope")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
