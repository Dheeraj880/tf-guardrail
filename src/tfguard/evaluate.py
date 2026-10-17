"""Cheat gallery: measure the verifier against known-honest and known-dishonest fixes.

Each case is a fix someone (or some model) might plausibly submit, with the
verdict the verifier must give. Two numbers come out:

  cheat catch rate   - dishonest fixes rejected / dishonest fixes
  honest pass rate   - honest fixes not rejected / honest fixes

Both matter: a verifier that rejects everything has a perfect catch rate and is useless.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .edits import EditError, apply_edits
from .hcl import load_files, read_dir
from .policies import scan
from .verifier import REJECT, verify


@dataclass
class CaseResult:
    name: str
    kind: str  # cheat | honest
    expected: str
    got: str
    codes: list[str]
    missing_codes: list[str]

    @property
    def passed(self) -> bool:
        return self.expected == self.got and not self.missing_codes


def run_case(case: dict[str, Any], base_dir: Path) -> CaseResult:
    files = read_dir(base_dir / case.get("base", "../vulnerable"))
    module = load_files(files)
    findings = scan(module)
    t = case["target"]
    targets = [f for f in findings if f.rule_id == t["rule_id"] and f.address == t["address"]]
    if not targets:
        raise ValueError(f"case {case['name']}: target {t} has no finding in the base module")
    try:
        patched = apply_edits(files, case["edits"])
    except EditError as exc:
        return CaseResult(case["name"], case["kind"], case["expected"], REJECT,
                          ["EDIT"], [] if "EDIT" in case.get("expect_codes", []) else [str(exc)])
    v = verify(module, patched, targets, findings)
    codes = sorted({i.code for i in v.errors + v.reviews})
    missing = [c for c in case.get("expect_codes", []) if c not in codes]
    return CaseResult(case["name"], case["kind"], case["expected"], v.verdict, codes, missing)


def run_gallery(path: str | Path) -> tuple[list[CaseResult], dict[str, Any]]:
    path = Path(path)
    cases = json.loads(path.read_text(encoding="utf-8"))
    results = [run_case(c, path.parent) for c in cases]
    cheats = [r for r in results if r.kind == "cheat"]
    honest = [r for r in results if r.kind == "honest"]
    metrics = {
        "cases": len(results),
        "passed": sum(r.passed for r in results),
        "cheat_catch_rate": round(sum(r.got == REJECT for r in cheats) / len(cheats), 3)
        if cheats else None,
        "honest_pass_rate": round(sum(r.got != REJECT for r in honest) / len(honest), 3)
        if honest else None,
    }
    return results, metrics
