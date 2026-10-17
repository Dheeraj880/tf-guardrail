"""Load Terraform files into a normalized, comparable structure.

python-hcl2 returns string literals with their quotes still attached ('"web"')
and marks blocks with an "__is_block__" key. Everything downstream (policies,
the verifier's structural diff) works on the normalized form produced here, so
the same Terraform always normalizes to the same Python value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2

# Block kinds we track. Two-label kinds carry (type, name); one-label kinds carry name only.
TWO_LABEL = ("resource", "data")
ONE_LABEL = ("variable", "module", "output")


class ParseError(Exception):
    """A Terraform file could not be parsed."""


@dataclass
class Block:
    kind: str  # resource | data | variable | module | output
    type: str  # e.g. aws_s3_bucket ("" for one-label kinds)
    name: str
    attrs: dict[str, Any]
    file: str
    line: int = 0

    @property
    def address(self) -> str:
        if self.kind == "resource":
            return f"{self.type}.{self.name}"
        if self.kind == "data":
            return f"data.{self.type}.{self.name}"
        if self.kind == "variable":
            return f"var.{self.name}"
        return f"{self.kind}.{self.name}"


@dataclass
class Module:
    files: dict[str, str]  # relative path -> file text
    blocks: list[Block] = field(default_factory=list)

    def by_address(self) -> dict[str, Block]:
        return {b.address: b for b in self.blocks}

    def of_type(self, type_: str, kind: str = "resource") -> list[Block]:
        return [b for b in self.blocks if b.kind == kind and b.type == type_]


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def normalize(value: Any) -> Any:
    """Strip parser artifacts so values compare by meaning."""
    if isinstance(value, dict):
        return {
            _unquote(k): normalize(v)
            for k, v in value.items()
            # parser metadata such as __is_block__ and __comments__; comments carry no
            # meaning for Terraform (the verifier inspects added comment text separately)
            if not (k.startswith("__") and k.endswith("__"))
        }
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, str):
        return _unquote(value)
    return value


def _block_line(text: str, kind: str, labels: list[str]) -> int:
    label_re = r"\s+".join(rf'"{re.escape(lbl)}"' for lbl in labels)
    m = re.search(rf"^[ \t]*{kind}\s+{label_re}\s*{{", text, re.MULTILINE)
    return text.count("\n", 0, m.start()) + 1 if m else 0


def parse_text(text: str, file: str) -> list[Block]:
    try:
        raw = hcl2.loads(text)
    except Exception as exc:  # the parser raises several lark error types
        raise ParseError(f"{file}: {exc}".splitlines()[0]) from exc

    blocks: list[Block] = []
    for kind in TWO_LABEL:
        for entry in raw.get(kind, []):
            for type_, by_name in entry.items():
                for name, attrs in by_name.items():
                    t, n = _unquote(type_), _unquote(name)
                    blocks.append(
                        Block(kind, t, n, normalize(attrs), file, _block_line(text, kind, [t, n]))
                    )
    for kind in ONE_LABEL:
        for entry in raw.get(kind, []):
            for name, attrs in entry.items():
                n = _unquote(name)
                blocks.append(
                    Block(kind, "", n, normalize(attrs), file, _block_line(text, kind, [n]))
                )
    return blocks


def load_files(files: dict[str, str]) -> Module:
    module = Module(files=dict(files))
    for path in sorted(files):
        module.blocks.extend(parse_text(files[path], path))
    seen: dict[str, str] = {}
    for b in module.blocks:
        if b.address in seen:
            raise ParseError(f"duplicate block {b.address} in {seen[b.address]} and {b.file}")
        seen[b.address] = b.file
    return module


def read_dir(path: str | Path) -> dict[str, str]:
    """Read every .tf file directly under `path` (Terraform modules are flat)."""
    root = Path(path)
    if root.is_file():
        return {root.name: root.read_text(encoding="utf-8")}
    files = {p.name: p.read_text(encoding="utf-8") for p in sorted(root.glob("*.tf"))}
    if not files:
        raise ParseError(f"no .tf files found in {root}")
    return files


def load_dir(path: str | Path) -> Module:
    return load_files(read_dir(path))


_REF = re.compile(r"\b((?:data\.)?[a-z][a-z0-9_]*\.[A-Za-z_][A-Za-z0-9_-]*)")
_VAR = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_-]*)")


def references(value: Any) -> set[str]:
    """Addresses referenced from interpolations like "${aws_s3_bucket.b.id}"."""
    out: set[str] = set()
    if isinstance(value, dict):
        for v in value.values():
            out |= references(v)
    elif isinstance(value, list):
        for v in value:
            out |= references(v)
    elif isinstance(value, str) and "${" in value:
        for expr in re.findall(r"\$\{(.*?)\}", value):
            out.update(_REF.findall(expr))
    return out


def variables_used(value: Any) -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for v in value.values():
            out |= variables_used(v)
    elif isinstance(value, list):
        for v in value:
            out |= variables_used(v)
    elif isinstance(value, str) and "${" in value:
        out.update(_VAR.findall(value))
    return out
