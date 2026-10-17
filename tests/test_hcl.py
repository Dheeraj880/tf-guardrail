import pytest

from tfguard.hcl import ParseError, load_files, normalize, references, variables_used


def test_normalize_strips_quotes_and_parser_metadata():
    raw = {'"x"': {"a": '"b"', "__is_block__": True, "__comments__": [{"value": "hi"}]}}
    assert normalize(raw) == {"x": {"a": "b"}}


def test_blocks_addresses_and_lines():
    m = load_files({"main.tf": 'variable "v" {}\n\nresource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
                               'data "aws_iam_policy_document" "d" {}\n'})
    by = m.by_address()
    assert set(by) == {"var.v", "aws_s3_bucket.b", "data.aws_iam_policy_document.d"}
    assert by["aws_s3_bucket.b"].line == 3


def test_duplicate_address_across_files_is_an_error():
    body = 'resource "aws_s3_bucket" "b" {}\n'
    with pytest.raises(ParseError):
        load_files({"a.tf": body, "b.tf": body})


def test_invalid_hcl_raises_parse_error():
    with pytest.raises(ParseError):
        load_files({"main.tf": 'resource "aws_s3_bucket" "b" {\n'})


def test_references_and_variables():
    assert references("${aws_s3_bucket.logs.id}") == {"aws_s3_bucket.logs"}
    assert "data.aws_iam_policy_document.p" in references("${data.aws_iam_policy_document.p.json}")
    assert variables_used(["${var.admin_cidr}", "10.0.0.0/8"]) == {"admin_cidr"}
    assert references("plain string") == set()
