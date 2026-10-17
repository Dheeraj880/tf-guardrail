"""Output formats: terminal text, SARIF (GitHub code scanning) and a PR description."""

from __future__ import annotations

from typing import Any

from . import __version__
from .pipeline import FixRun
from .policies import RULES, RULES_BY_ID, Finding

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def findings_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in findings:
        show_path = f.path and not f.address.startswith("file.")
        where = f"{f.address}{' -> ' + f.path if show_path else ''}"
        lines.append(f"{f.severity.upper():8} {f.rule_id:11} {f.file}:{f.line}  {where}")
        lines.append(f"{'':21}{f.message}")
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    lines.append(f"\n{len(findings)} findings ({summary})")
    return "\n".join(lines)


def findings_sarif(findings: list[Finding], base: str = "") -> dict[str, Any]:
    prefix = f"{base.rstrip('/')}/" if base else ""
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "tf-guardrail",
                "version": __version__,
                "rules": [{
                    "id": r.id,
                    "shortDescription": {"text": r.title},
                    "help": {"text": r.guidance},
                    "properties": {"security-severity": {"critical": "9.5", "high": "7.5",
                                                         "medium": "5.0", "low": "2.0"}[r.severity]},
                } for r in RULES],
            }},
            "results": [{
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.address}: {f.message}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f"{prefix}{f.file}"},
                    "region": {"startLine": max(f.line, 1)},
                }}],
            } for f in findings],
        }],
    }


OUTCOME_LABEL = {
    "ACCEPT": "✅ fixed",
    "REVIEW": "👀 fixed, needs review",
    "REJECTED": "❌ no safe fix found",
    "DECLINED": "⏭️ needs a human",
    "ALREADY_RESOLVED": "➖ resolved by an earlier fix",
    "FLAGGED": "🚩 flagged for security team",
}


def pr_body(run: FixRun) -> str:
    k = run.kpis()
    lines = [
        "## tf-guardrail: automated security fixes",
        "",
    ]
    flagged = [r for r in run.results if r.outcome == "FLAGGED"]
    if flagged:
        lines += ["> [!WARNING]",
                  "> **Possible prompt injection in this PR.** These comments try to instruct "
                  "automated reviewers. They were not followed and were left in place for a human:"]
        lines += [f"> - `{r.address.removeprefix('file.')}`: {r.messages[0]}" for r in flagged]
        lines += [""]
    lines += [
        f"{k['findings_before']} findings before, **{k['findings_after']} after**. "
        f"Every change below passed the deterministic verifier: it resolves its finding, "
        f"stays inside the policy's allowed scope, and deletes, disables or suppresses nothing.",
        "",
        "| Finding | Resource | Result | Attempts |",
        "|---|---|---|---|",
    ]
    for r in run.results:
        if r.outcome == "FLAGGED":
            continue
        title = RULES_BY_ID[r.rule_id].title
        lines.append(f"| {r.rule_id} {title} | `{r.address}` | {OUTCOME_LABEL[r.outcome]} | "
                     f"{len(r.attempts)} |")

    review = [r for r in run.results if r.outcome == "REVIEW"]
    if review:
        lines += ["", "### Needs a reviewer's eyes", ""]
        for r in review:
            for item in r.reviews:
                lines.append(f"- `{r.address}`: {item.split(': ', 1)[-1]}")

    open_items = [r for r in run.results if r.outcome in ("REJECTED", "DECLINED")]
    if open_items:
        lines += ["", "### Not fixed automatically", ""]
        for r in open_items:
            reason = r.notes or (r.attempts[-1].errors[0] if r.attempts and r.attempts[-1].errors
                                 else "")
            lines.append(f"- `{r.address}` ({r.rule_id}): {reason}")

    notes = [r for r in run.results if r.outcome in ("ACCEPT", "REVIEW") and r.notes]
    if notes:
        lines += ["", "<details><summary>Fixer notes</summary>", ""]
        lines += [f"- `{r.address}`: {r.notes}" for r in notes]
        lines += ["", "</details>"]
    lines += ["", f"_fix rate {k['fix_rate']}, first-try rate {k['first_try_rate']}, "
              f"avg attempts {k['avg_attempts']}_"]
    return "\n".join(lines) + "\n"


def run_text(run: FixRun) -> str:
    lines = []
    for r in run.results:
        lines.append(f"{OUTCOME_LABEL[r.outcome]:28} {r.rule_id:11} {r.address}")
        if r.outcome == "FLAGGED":
            lines.append(f"{'':6}{r.messages[0]}")
        for a in r.attempts:
            lines.append(f"{'':6}attempt {a.number}: {a.verdict}")
            for e in a.errors:
                lines.append(f"{'':10}- {e}")
        for item in r.reviews:
            lines.append(f"{'':6}review: {item}")
    k = run.kpis()
    lines.append("")
    lines.append(
        f"findings {k['findings_before']} -> {k['findings_after']} | accepted {k['accepted']}, "
        f"review {k['needs_review']}, rejected {k['rejected']}, declined {k['declined']}, "
        f"flagged {k['flagged']} | "
        f"fix rate {k['fix_rate']}, first-try {k['first_try_rate']}, "
        f"avg attempts {k['avg_attempts']}"
    )
    return "\n".join(lines)
