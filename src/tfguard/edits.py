"""Apply a proposed fix: a list of exact text edits to existing .tf files.

A fix is data, not code. Each edit is either
  {"file": "network.tf", "old": "<exact text>", "new": "<replacement>"}
or
  {"file": "storage.tf", "append": "<new HCL block>"}

`old` must match exactly once, and a fix may not create, rename or delete files.
"""

from __future__ import annotations

from typing import Any


class EditError(Exception):
    pass


def apply_edits(files: dict[str, str], edits: list[dict[str, Any]]) -> dict[str, str]:
    out = dict(files)
    if not isinstance(edits, list) or not edits:
        raise EditError("a fix must contain at least one edit")
    for i, edit in enumerate(edits):
        if not isinstance(edit, dict):
            raise EditError(f"edit {i}: must be an object")
        name = edit.get("file")
        if name not in out:
            raise EditError(f"edit {i}: file {name!r} is not part of the module (no new files)")
        if "append" in edit:
            text = edit["append"]
            if not isinstance(text, str) or not text.strip():
                raise EditError(f"edit {i}: append must be non-empty text")
            body = out[name]
            out[name] = body + ("" if body.endswith("\n") else "\n") + "\n" + text.strip() + "\n"
            continue
        old, new = edit.get("old"), edit.get("new")
        if not isinstance(old, str) or not isinstance(new, str) or not old:
            raise EditError(f"edit {i}: needs non-empty 'old' and a 'new' string")
        count = out[name].count(old)
        if count != 1:
            raise EditError(
                f"edit {i}: 'old' text matches {count} times in {name}; it must match exactly once"
            )
        out[name] = out[name].replace(old, new, 1)
    return out
