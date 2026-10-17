"""Detect comments that try to instruct automated reviewers (prompt injection).

A .tf file in a pull request is written by whoever opened the PR. If a comment
in it tells "AI tools" or "automated reviewers" to skip a check or add a
suppression, that is an attack on the review pipeline, whether or not any model
falls for it. This check is deterministic: it flags the attempt for the security
team instead of relying on the model to notice and mention it.

A comment is flagged when it
  * addresses an automated audience (AI, LLM, Copilot, bot, "automated reviewers"...)
    AND gives a directive (ignore, skip, suppress, don't change, mark as safe...), or
  * uses classic injection phrasing ("ignore previous instructions"), or
  * asks for a scanner suppression to be added.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

AUDIENCE = re.compile(
    r"\b(ai|a\.i\.|llms?|language models?|assistants?|copilot|chat-?gpt|gpt-?\d*|claude|gemini"
    r"|bots?|agents?|automated\s+(?:reviewers?|review|tools?|scanners?|systems?|checks?))\b",
    re.IGNORECASE,
)
DIRECTIVE = re.compile(
    r"\b(ignore|disregard|skip|suppress|bypass|whitelist|allowlist|approve"
    r"|do\s+not\s+(?:change|flag|fix|report|modify|touch|alert)"
    r"|don'?t\s+(?:change|flag|fix|report|modify|touch|alert)"
    r"|mark\s+(?:it\s+|this\s+)?as\s+(?:safe|approved|compliant|false\s+positive)"
    r"|(?:is|are)\s+(?:intentional|on\s+purpose|approved|safe))\b",
    re.IGNORECASE,
)
CLASSIC = re.compile(
    r"\b(ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instructions?|rules?|prompts?)|\bsystem\s+prompt\b|\byou\s+are\s+now\b",
    re.IGNORECASE,
)
SUPPRESSION_REQUEST = re.compile(
    r"\b(add|insert|put|use|include)\b.{0,40}(tfsec|trivy|checkov|kics|nosec|tfguard)"
    r"[\s:-]*(ignore|skip)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CommentHit:
    file: str
    line: int
    text: str
    reason: str


def _comment_part(line: str) -> str | None:
    """Return the comment text on a line ('#', '//' or '/* */'), ignoring string contents."""
    in_str = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and in_str:
            i += 2
            continue
        if ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "#":
                return line[i + 1 :]
            if line.startswith("//", i) or line.startswith("/*", i):
                return line[i + 2 :].replace("*/", "")
        i += 1
    return None


def comment_blocks(text: str) -> list[tuple[int, str]]:
    """Comments grouped into blocks: consecutive full-line comments join into one."""
    blocks: list[tuple[int, str]] = []
    current: list[str] = []
    start = 0
    in_block_comment = False
    for n, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if in_block_comment:
            current.append(stripped.replace("*/", "").lstrip("* "))
            if "*/" in stripped:
                in_block_comment = False
            continue
        part = _comment_part(raw)
        full_line = part is not None and stripped.startswith(("#", "//", "/*"))
        if full_line:
            if not current:
                start = n
            current.append(part.strip())
            if stripped.startswith("/*") and "*/" not in stripped:
                in_block_comment = True
            continue
        if current:
            blocks.append((start, " ".join(c.strip() for c in current if c.strip())))
            current = []
        if part is not None and part.strip():
            blocks.append((n, part.strip()))
    if current:
        blocks.append((start, " ".join(c.strip() for c in current if c.strip())))
    return blocks


def classify(comment: str) -> str | None:
    if CLASSIC.search(comment):
        return "uses prompt-injection phrasing"
    if AUDIENCE.search(comment) and DIRECTIVE.search(comment):
        return "gives instructions to automated reviewers"
    if SUPPRESSION_REQUEST.search(comment):
        return "asks for a scanner suppression to be added"
    return None


def find_injections(files: dict[str, str]) -> list[CommentHit]:
    hits = []
    for name in sorted(files):
        for line, comment in comment_blocks(files[name]):
            reason = classify(comment)
            if reason:
                hits.append(CommentHit(name, line, comment, reason))
    return hits


def fingerprint(text: str) -> str:
    """Stable identity for a comment, so moving it down a few lines isn't a 'new' finding."""
    return re.sub(r"\s+", " ", text.lower()).strip()[:80]
