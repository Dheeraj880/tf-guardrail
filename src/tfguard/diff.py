"""Structural diff of normalized Terraform attributes.

Compares meaning, not text: whitespace, comments and attribute order don't count.
Lists of blocks (several `ingress {}` blocks, say) are aligned by content, so
removing the first block reports `ingress[0]` removed instead of every later
block "changed".
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any


@dataclass(frozen=True)
class Change:
    path: str
    kind: str  # added | removed | changed
    old: Any = None
    new: Any = None

    def describe(self) -> str:
        if self.kind == "added":
            return f"{self.path} added ({_short(self.new)})"
        if self.kind == "removed":
            return f"{self.path} removed (was {_short(self.old)})"
        return f"{self.path}: {_short(self.old)} -> {_short(self.new)}"


def _short(value: Any, limit: int = 60) -> str:
    text = json.dumps(value, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _key(path: str, k: str) -> str:
    return f"{path}.{k}" if path else k


def _blockish(value: Any) -> bool:
    return isinstance(value, list) and any(isinstance(v, dict) for v in value)


def diff(old: Any, new: Any, path: str = "") -> list[Change]:
    if isinstance(old, dict) and isinstance(new, dict):
        out: list[Change] = []
        for k in sorted(set(old) | set(new)):
            p = _key(path, k)
            if k not in old:
                out.append(Change(p, "added", new=new[k]))
            elif k not in new:
                out.append(Change(p, "removed", old=old[k]))
            else:
                out.extend(diff(old[k], new[k], p))
        return out

    if (_blockish(old) or _blockish(new)) and isinstance(old, list) and isinstance(new, list):
        a = [json.dumps(v, sort_keys=True) for v in old]
        b = [json.dumps(v, sort_keys=True) for v in new]
        out = []
        for op, i1, i2, j1, j2 in SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
            if op == "equal":
                continue
            paired = min(i2 - i1, j2 - j1) if op == "replace" else 0
            for k in range(paired):
                out.extend(diff(old[i1 + k], new[j1 + k], f"{path}[{i1 + k}]"))
            for i in range(i1 + paired, i2):
                out.append(Change(f"{path}[{i}]", "removed", old=old[i]))
            for j in range(j1 + paired, j2):
                out.append(Change(f"{path}[{j}]", "added", new=new[j]))
        return out

    if old != new:
        return [Change(path, "changed", old, new)]
    return []
