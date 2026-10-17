"""Deterministic fix verifier: decides whether a proposed fix is honest.

The fixer (an AI model, or anything else) proposes a patch. This module decides,
using only parsing, re-scanning and structural diffs, whether the patch:

  * actually resolves the targeted findings, without creating new ones;
  * changes only what the targeted policy allows it to change;
  * doesn't make the scanner go quiet by deleting, renaming or disabling the
    resource, suppressing the check, or hiding the bad value in a variable.

It returns one of three verdicts:
  ACCEPT  - safe to propose as-is
  REVIEW  - legitimate, but a human must look (forces replacement, intent-dependent,
            depends on an input value the tool can't see)
  REJECT  - fails a check; the reasons go back to the fixer for another attempt

The verifier never calls a model and never reads comments for instructions.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

from .diff import Change, diff
from .hcl import Module, ParseError, load_files, references, variables_used
from .policies import RULES_BY_ID, Finding, scan

ACCEPT, REVIEW, REJECT = "ACCEPT", "REVIEW", "REJECT"

META_ARGS = {"count", "for_each", "lifecycle", "provider", "depends_on"}

SUPPRESSION = re.compile(
    r"(tfsec|trivy|checkov|kics|tfguard|terrascan|snyk|nosec)\b[\s:-]*(ignore|skip|disable)"
    r"|checkov:skip|kics-scan\s+ignore|nosec",
    re.IGNORECASE,
)
PLACEHOLDER = re.compile(r"\b(TODO|FIXME|CHANGE_?ME|REPLACE_?ME|XXX)\b|x\.x\.x\.x", re.IGNORECASE)


@dataclass
class Issue:
    code: str
    message: str
    address: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "address": self.address}

    def __str__(self) -> str:
        where = f" [{self.address}]" if self.address else ""
        return f"{self.code}{where}: {self.message}"


@dataclass
class Verification:
    verdict: str
    errors: list[Issue] = field(default_factory=list)
    reviews: list[Issue] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    remaining: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "errors": [i.to_dict() for i in self.errors],
            "reviews": [i.to_dict() for i in self.reviews],
            "changes": self.changes,
        }


# --------------------------------------------------------------------------- path scoping


def _pattern_regex(pattern: str) -> str:
    return re.escape(pattern).replace(r"\[\*\]", r"\[\d+\]")


def scope_pattern(pattern: str, finding_path: str) -> str:
    """Pin a rule's `ingress[*]...` pattern to the flagged element, e.g. `ingress[0]...`.

    Without this, a fix for the open SSH rule could also edit the HTTPS rule next
    to it and still pass.
    """
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]", finding_path)
    if m and pattern.startswith(f"{m.group(1)}[*]"):
        return f"{m.group(1)}[{m.group(2)}]" + pattern[len(m.group(1)) + 3 :]
    return pattern


def path_within(path: str, pattern: str) -> bool:
    """True if `path` is `pattern` or sits underneath it."""
    return re.fullmatch(_pattern_regex(pattern) + r"(?:[.\[].*)?", path) is not None


def path_exact(path: str, pattern: str) -> bool:
    return re.fullmatch(_pattern_regex(pattern), path) is not None


# --------------------------------------------------------------------------- text checks


def _added_lines(before: dict[str, str], after: dict[str, str]) -> list[tuple[str, str]]:
    out = []
    for name in sorted(after):
        old = before.get(name, "").splitlines()
        for line in difflib.unified_diff(old, after[name].splitlines(), lineterm="", n=0):
            if line.startswith("+") and not line.startswith("+++"):
                out.append((name, line[1:]))
    return out


# --------------------------------------------------------------------------- verify


def verify(
    before: Module,
    after_files: dict[str, str],
    targets: list[Finding],
    before_findings: list[Finding] | None = None,
) -> Verification:
    errors: list[Issue] = []
    reviews: list[Issue] = []
    changes_desc: list[str] = []

    if set(after_files) != set(before.files):
        added = sorted(set(after_files) - set(before.files))
        removed = sorted(set(before.files) - set(after_files))
        errors.append(Issue("FILES", f"files added {added} / removed {removed}; not allowed"))
        return Verification(REJECT, errors)

    # 1. It must still be valid Terraform.
    try:
        after = load_files(after_files)
    except ParseError as exc:
        return Verification(REJECT, [Issue("PARSE", str(exc))])

    # 2. Re-scan: targets resolved, nothing new introduced.
    before_findings = before_findings if before_findings is not None else scan(before)
    after_findings = scan(after)
    before_keys = {f.key for f in before_findings}
    after_keys = {f.key for f in after_findings}
    for t in targets:
        if t.key in after_keys:
            errors.append(Issue("UNRESOLVED", f"{t.rule_id} still fails: {t.message}", t.address))
    for f in after_findings:
        if f.key not in before_keys:
            errors.append(Issue("NEW_FINDING", f"{f.rule_id}: {f.message}", f.address))

    # 3. Nothing deleted or renamed.
    before_blocks, after_blocks = before.by_address(), after.by_address()
    for addr in sorted(set(before_blocks) - set(after_blocks)):
        errors.append(
            Issue("DELETED", "block was deleted or renamed; removing the resource is not a fix",
                  addr)
        )

    # 4. Changes to existing blocks must stay inside the targeted rules' fix scope.
    by_addr: dict[str, list[Finding]] = {}
    for t in targets:
        by_addr.setdefault(t.address, []).append(t)

    for addr in sorted(set(before_blocks) & set(after_blocks)):
        changes = diff(before_blocks[addr].attrs, after_blocks[addr].attrs)
        if not changes:
            continue
        changes_desc.extend(f"{addr}: {c.describe()}" for c in changes)
        flagged = by_addr.get(addr)
        if not flagged:
            for c in changes:
                errors.append(
                    Issue("OUT_OF_SCOPE", f"changed a block no targeted finding is on: "
                          f"{c.describe()}", addr)
                )
            continue
        for c in changes:
            _judge_change(addr, c, flagged, errors, reviews)
        _judge_inputs(addr, changes, after, reviews)

    # 5. New blocks: only declared companions that point at a flagged resource, or
    #    variables that the fix actually uses.
    used_vars: set[str] = set()
    for addr in by_addr:
        if addr in after_blocks:
            used_vars |= variables_used(after_blocks[addr].attrs)
    for addr in sorted(set(after_blocks) - set(before_blocks)):
        block = after_blocks[addr]
        changes_desc.append(f"{addr}: added")
        if block.kind == "variable":
            if block.name not in used_vars:
                errors.append(Issue("UNEXPECTED_BLOCK", "new variable is not used by the fix", addr))
            continue
        if not _is_companion(block, by_addr):
            errors.append(
                Issue("UNEXPECTED_BLOCK", "new block is not a companion the targeted rule allows",
                      addr)
            )
        else:
            used_vars |= variables_used(block.attrs)

    # 6. Text-level tricks the parser can't see.
    for name, line in _added_lines(before.files, after_files):
        if SUPPRESSION.search(line):
            errors.append(Issue("SUPPRESSION", f"{name}: adds a scanner suppression: "
                                f"{line.strip()[:80]}"))
        elif PLACEHOLDER.search(line):
            errors.append(Issue("PLACEHOLDER", f"{name}: adds a placeholder value: "
                                f"{line.strip()[:80]}"))

    # 7. Some rules always need a human, no matter how clean the patch is.
    for rule_id in sorted({t.rule_id for t in targets}):
        reason = RULES_BY_ID[rule_id].review_reason
        if reason:
            reviews.append(Issue("NEEDS_HUMAN", f"{rule_id}: {reason}"))

    verdict = REJECT if errors else REVIEW if reviews else ACCEPT
    return Verification(verdict, errors, reviews, changes_desc, after_findings)


def _judge_change(
    addr: str, c: Change, flagged: list[Finding], errors: list[Issue], reviews: list[Issue]
) -> None:
    root = re.split(r"[.\[]", c.path, maxsplit=1)[0]
    if root in META_ARGS:
        errors.append(
            Issue("META_ARGUMENT", f"changes {root}; that can disable or detach the resource "
                  f"instead of fixing it: {c.describe()}", addr)
        )
        return
    for f in flagged:
        rule = RULES_BY_ID[f.rule_id]
        if any(path_within(c.path, scope_pattern(p, f.path)) for p in rule.fix_paths):
            return
    for f in flagged:
        rule = RULES_BY_ID[f.rule_id]
        if c.kind in ("added", "removed") and any(
            path_exact(c.path, scope_pattern(p, f.path)) for p in rule.review_paths
        ):
            reviews.append(
                Issue("REMOVES_ACCESS" if c.kind == "removed" else "ADDS_BLOCK",
                      f"{c.describe()}; confirm nothing depends on it", addr)
            )
            return
    allowed = sorted({scope_pattern(p, f.path) for f in flagged
                      for p in RULES_BY_ID[f.rule_id].fix_paths})
    errors.append(
        Issue("OUT_OF_SCOPE", f"{c.describe()}; this fix may only change {allowed or 'nothing'} "
              "on this block", addr)
    )


def _judge_inputs(addr: str, changes: list[Change], after: Module, reviews: list[Issue]) -> None:
    """A value that comes from an input variable without a default can't be checked here."""
    blocks = after.by_address()
    for c in changes:
        for name in sorted(variables_used(c.new)):
            var = blocks.get(f"var.{name}")
            if var is None or "default" not in var.attrs:
                reviews.append(
                    Issue("INPUT_DEPENDENT", f"{c.path} now comes from var.{name}, which has no "
                          "default; confirm the value supplied at apply time", addr)
                )


def _is_companion(block: Any, by_addr: dict[str, list[Finding]]) -> bool:
    if block.kind != "resource":
        return False
    for addr, findings in by_addr.items():
        for f in findings:
            for comp in RULES_BY_ID[f.rule_id].companions:
                if block.type == comp.type and addr in references(block.attrs.get(comp.ref_attr)):
                    return True
    return False
