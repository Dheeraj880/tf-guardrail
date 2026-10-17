import json

import pytest
from conftest import GALLERY

from tfguard.evaluate import run_case, run_gallery
from tfguard.verifier import REJECT, path_within, scope_pattern, verify

CASES = json.loads(GALLERY.read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_gallery_case(case):
    r = run_case(case, GALLERY.parent)
    assert r.got == case["expected"], r.codes
    assert not r.missing_codes, f"missing {r.missing_codes}, got {r.codes}"


def test_gallery_metrics():
    _, m = run_gallery(GALLERY)
    assert m["cheat_catch_rate"] == 1.0
    assert m["honest_pass_rate"] == 1.0
    assert m["cases"] >= 20


def test_scope_pattern_pins_the_flagged_element():
    assert scope_pattern("ingress[*].cidr_blocks", "ingress[0]") == "ingress[0].cidr_blocks"
    assert scope_pattern("acl", "acl") == "acl"
    assert scope_pattern("statement[*].actions", "") == "statement[*].actions"


def test_path_within():
    assert path_within("metadata_options[0].http_tokens", "metadata_options")
    assert path_within("acl", "acl")
    assert not path_within("acl_extra", "acl")
    assert not path_within("ingress[1].cidr_blocks", "ingress[0].cidr_blocks")


def test_adding_a_file_is_rejected(module, findings, files):
    target = [findings[0]]
    v = verify(module, {**files, "extra.tf": ""}, target, findings)
    assert v.verdict == REJECT and v.errors[0].code == "FILES"


def test_unparseable_fix_is_rejected(module, findings, files):
    broken = {**files, "iam.tf": files["iam.tf"] + "\nresource {"}
    v = verify(module, broken, [findings[0]], findings)
    assert v.verdict == REJECT and v.errors[0].code == "PARSE"


def test_no_op_fix_is_unresolved(module, findings, files):
    v = verify(module, dict(files), [findings[0]], findings)
    assert v.verdict == REJECT and [e.code for e in v.errors] == ["UNRESOLVED"]


def test_comment_only_changes_are_not_out_of_scope(module, findings, files):
    target = [f for f in findings if f.rule_id == "TFG-S3-01"]
    patched = dict(files)
    patched["storage.tf"] = files["storage.tf"].replace(
        'acl    = "public-read"', 'acl    = "private" # owner asked for private')
    assert verify(module, patched, target, findings).verdict == "ACCEPT"
