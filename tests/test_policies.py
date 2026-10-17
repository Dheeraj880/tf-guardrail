import pytest
from conftest import tf

from tfguard.policies import RULES, exposed_ports, is_open_cidr


def test_example_module_findings(findings):
    got = {(f.rule_id, f.address) for f in findings}
    assert got == {
        ("TFG-IAM-01", "data.aws_iam_policy_document.reports_job"),
        ("TFG-NET-01", "aws_security_group.bastion"),
        ("TFG-NET-03", "aws_vpc_security_group_ingress_rule.db_from_anywhere"),
        ("TFG-RDS-01", "aws_db_instance.orders"),
        ("TFG-RDS-02", "aws_db_instance.orders"),
        ("TFG-EC2-01", "aws_instance.bastion"),
        ("TFG-S3-01", "aws_s3_bucket_acl.reports"),
        ("TFG-S3-02", "aws_s3_bucket.reports"),
        ("TFG-S3-03", "aws_s3_bucket_public_access_block.logs"),
        ("TFG-LOG-01", "aws_cloudtrail.main"),
        ("TFG-AI-01", "file.storage.tf"),
    }
    # HTTPS open to the world is normal for a web front end; not a finding.
    assert not any(f.path == "ingress[1]" for f in findings)
    # Findings are ordered most severe first.
    assert findings[0].severity == "critical"


@pytest.mark.parametrize("cidr,open_", [
    ("0.0.0.0/0", True),
    ("0.0.0.0/1", True),
    ("128.0.0.0/1", True),
    ("8.0.0.0/8", True),
    ("203.0.113.0/24", False),
    ("203.0.113.10/32", False),
    ("10.0.0.0/8", False),
    ("172.16.5.0/24", False),
    ("::/0", True),
    ("2001:db8::/32", True),
    ("2001:db8:1::/48", False),
    ("fd00::/8", False),
    ("${var.admin_cidr}", False),
    ("not-a-cidr", False),
])
def test_is_open_cidr(cidr, open_):
    assert is_open_cidr(cidr) is open_


def test_exposed_ports():
    assert exposed_ports(0, 65535, "tcp") != []
    assert exposed_ports(20, 25, "tcp") == ["SSH (22)"]
    assert exposed_ports(443, 443, "tcp") == []
    assert exposed_ports(0, 0, "-1") == ["all ports"]


def test_all_traffic_rule_flagged():
    _, fs = tf('resource "aws_security_group" "a" {\n ingress {\n  from_port = 0\n  to_port = 0\n'
               '  protocol = "-1"\n  cidr_blocks = ["0.0.0.0/0"]\n }\n}\n')
    assert [f.rule_id for f in fs] == ["TFG-NET-01"]


def test_ipv6_open_ssh_flagged():
    _, fs = tf('resource "aws_security_group" "a" {\n ingress {\n  from_port = 22\n  to_port = 22\n'
               '  protocol = "tcp"\n  ipv6_cidr_blocks = ["::/0"]\n }\n}\n')
    assert fs and fs[0].rule_id == "TFG-NET-01"


def test_open_cidr_hidden_in_variable_default_is_resolved():
    _, fs = tf('variable "c" {\n default = "0.0.0.0/0"\n}\n'
               'resource "aws_security_group_rule" "r" {\n type = "ingress"\n from_port = 3389\n'
               ' to_port = 3389\n protocol = "tcp"\n cidr_blocks = [var.c]\n}\n')
    assert [f.rule_id for f in fs] == ["TFG-NET-02"]


def test_variable_without_default_is_not_judged():
    _, fs = tf('variable "c" {}\nresource "aws_vpc_security_group_ingress_rule" "r" {\n'
               ' cidr_ipv4 = var.c\n from_port = 22\n to_port = 22\n ip_protocol = "tcp"\n}\n')
    assert fs == []


def test_egress_rule_not_flagged():
    _, fs = tf('resource "aws_security_group_rule" "r" {\n type = "egress"\n from_port = 22\n'
               ' to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"]\n}\n')
    assert fs == []


def test_s3_bucket_with_full_pab_is_clean():
    _, fs = tf('resource "aws_s3_bucket" "b" {}\nresource "aws_s3_bucket_public_access_block" "b" {\n'
               ' bucket = aws_s3_bucket.b.id\n block_public_acls = true\n block_public_policy = true\n'
               ' ignore_public_acls = true\n restrict_public_buckets = true\n}\n')
    assert fs == []


def test_imdsv2_and_iam_variants():
    _, fs = tf('resource "aws_instance" "i" {\n metadata_options {\n  http_tokens = "required"\n }\n}\n'
               'data "aws_iam_policy_document" "d" {\n statement {\n  effect = "Deny"\n'
               '  actions = ["*"]\n  resources = ["*"]\n }\n}\n')
    assert fs == []


def test_every_rule_has_a_bounded_fix():
    for r in RULES:
        if not r.fixable:
            continue
        assert r.fix_paths or r.companions, f"{r.id} has no allowed fix scope"
        assert r.guidance, f"{r.id} has no guidance for the fixer"
