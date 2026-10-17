"""Remediation loop: one finding group at a time, propose -> verify -> retry.

Fixing findings one at a time keeps every patch small and independently checked,
so one bad fix can't hide inside a large diff, and one stubborn finding doesn't
block the other fixes from shipping.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import Any

from .edits import EditError, apply_edits
from .fixer import Fixer, FixTask
from .hcl import load_files
from .policies import RULES_BY_ID, Finding, scan
from .verifier import ACCEPT, REJECT, REVIEW, verify

# Outcomes per finding group
APPLIED = (ACCEPT, REVIEW)
NOT_FIXED = ("REJECTED", "DECLINED", "ALREADY_RESOLVED", "FLAGGED")


@dataclass
class Attempt:
    number: int
    verdict: str
    errors: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class TaskResult:
    rule_id: str
    address: str
    severity: str
    messages: list[str]
    outcome: str  # ACCEPT | REVIEW | REJECTED | DECLINED | ALREADY_RESOLVED | FLAGGED
    attempts: list[Attempt] = field(default_factory=list)
    reviews: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    notes: str = ""
    diff: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "address": self.address,
            "severity": self.severity,
            "messages": self.messages,
            "outcome": self.outcome,
            "attempts": [a.__dict__ for a in self.attempts],
            "reviews": self.reviews,
            "changes": self.changes,
            "notes": self.notes,
            "diff": self.diff,
        }


@dataclass
class FixRun:
    original: dict[str, str]
    patched: dict[str, str]
    initial_findings: list[Finding]
    final_findings: list[Finding]
    results: list[TaskResult]

    def kpis(self) -> dict[str, Any]:
        tried = [r for r in self.results if r.outcome not in ("ALREADY_RESOLVED", "FLAGGED")]
        applied = [r for r in tried if r.outcome in APPLIED]
        first_try = [r for r in applied if len(r.attempts) == 1]
        attempts = sum(len(r.attempts) for r in tried)
        return {
            "findings_before": len(self.initial_findings),
            "findings_after": len(self.final_findings),
            "groups": len(self.results),
            "accepted": sum(r.outcome == ACCEPT for r in tried),
            "needs_review": sum(r.outcome == REVIEW for r in tried),
            "rejected": sum(r.outcome == "REJECTED" for r in tried),
            "declined": sum(r.outcome == "DECLINED" for r in tried),
            "flagged": sum(r.outcome == "FLAGGED" for r in self.results),
            "fix_rate": round(len(applied) / len(tried), 3) if tried else None,
            "first_try_rate": round(len(first_try) / len(applied), 3) if applied else None,
            "avg_attempts": round(attempts / len(tried), 2) if tried else None,
        }

    def unified_diff(self) -> str:
        return unified_diff(self.original, self.patched)


def unified_diff(before: dict[str, str], after: dict[str, str]) -> str:
    out = []
    for name in sorted(set(before) | set(after)):
        out.extend(
            difflib.unified_diff(
                before.get(name, "").splitlines(keepends=True),
                after.get(name, "").splitlines(keepends=True),
                fromfile=f"a/{name}",
                tofile=f"b/{name}",
            )
        )
    return "".join(out)


def group_findings(findings: list[Finding]) -> list[tuple[str, str]]:
    seen: list[tuple[str, str]] = []
    for f in findings:
        if (f.rule_id, f.address) not in seen:
            seen.append((f.rule_id, f.address))
    return seen


def run_fixes(
    files: dict[str, str],
    fixer: Fixer,
    max_attempts: int = 3,
    rule_ids: set[str] | None = None,
) -> FixRun:
    current = dict(files)
    initial = scan(load_files(files))
    groups = [g for g in group_findings(initial) if not rule_ids or g[0] in rule_ids]
    results: list[TaskResult] = []

    for rule_id, address in groups:
        module = load_files(current)
        findings = scan(module)
        targets = [f for f in findings if (f.rule_id, f.address) == (rule_id, address)]
        original = [f for f in initial if (f.rule_id, f.address) == (rule_id, address)]
        result = TaskResult(rule_id, address, original[0].severity,
                            [f.message for f in original], "REJECTED")
        results.append(result)
        if not RULES_BY_ID[rule_id].fixable:
            result.outcome = "FLAGGED"
            continue
        if not targets:
            result.outcome = "ALREADY_RESOLVED"
            continue

        task = FixTask(rule_id, address, targets, current)
        feedback: list[str] | None = None
        for n in range(1, max_attempts + 1):
            proposal = fixer.propose(task, feedback)
            if not proposal.edits:
                result.attempts.append(Attempt(n, "DECLINED", [proposal.decline_reason]))
                result.outcome = "DECLINED"
                result.notes = proposal.decline_reason
                break
            try:
                patched = apply_edits(current, proposal.edits)
            except EditError as exc:
                feedback = [f"EDIT: {exc}"]
                result.attempts.append(Attempt(n, REJECT, feedback, proposal.notes))
                continue
            v = verify(module, patched, targets, findings)
            result.attempts.append(
                Attempt(n, v.verdict, [str(e) for e in v.errors], proposal.notes)
            )
            if v.verdict == REJECT:
                feedback = [str(e) for e in v.errors]
                continue
            result.outcome = v.verdict
            result.reviews = [str(r) for r in v.reviews]
            result.changes = v.changes
            result.notes = proposal.notes
            result.diff = unified_diff(current, patched)
            current = patched
            break

    final = scan(load_files(current))
    return FixRun(dict(files), current, initial, final, results)
