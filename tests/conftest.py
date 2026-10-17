from pathlib import Path

import pytest

from tfguard.hcl import load_files, read_dir
from tfguard.policies import scan

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "vulnerable"
GALLERY = ROOT / "examples" / "cases" / "gallery.json"
DEMO_SCRIPT = ROOT / "examples" / "demo-fixer.json"


@pytest.fixture
def files():
    return read_dir(EXAMPLE)


@pytest.fixture
def module(files):
    return load_files(files)


@pytest.fixture
def findings(module):
    return scan(module)


def tf(text: str):
    """Scan a single in-memory main.tf."""
    m = load_files({"main.tf": text})
    return m, scan(m)
