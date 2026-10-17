"""Policy-as-code rules for AWS Terraform.

Each rule does two jobs:

1. **Detect**: `check(block, module)` returns violations as (attribute path, message).
2. **Bound the fix**: `fix_paths` lists the only attributes a fix for this rule may
   change, `review_paths` lists changes that are legitimate but need a human
   (e.g. deleting a firewall rule), and `companions` lists new resources a fix may
   add (e.g. a public access block that points at the flagged bucket).

The second job is what lets the verifier tell an honest fix from one that just
makes the scanner go quiet.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .hcl import Block, Module, references

Violation = tuple[str, str]  # (attribute path, message)


@dataclass(frozen=True)
class Companion:
    type: str
    ref_attr: str  # attribute on the new resource that must reference the flagged one


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str  # critical | high | medium | low
    kind: str  # resource | data
    types: tuple[str, ...]
    check: Callable[[Block, Module], list[Violation]]
    fix_paths: tuple[str, ...] = ()
    review_paths: tuple[str, ...] = ()
    companions: tuple[Companion, ...] = ()
    review_reason: str = ""  # set when every fix for this rule needs human sign-off
    guidance: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    address: str
    path: str
    message: str
    file: str
    line: int

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.address, self.path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "address": self.address,
            "path": self.path,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }


# --------------------------------------------------------------------------- helpers

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
    2375: "Docker API",
}

_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
]


def is_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def is_open_cidr(cidr: Any) -> bool:
    """True if a CIDR exposes a broad slice of the public internet.

    Checking only for "0.0.0.0/0" is a trap: "0.0.0.0/1" is half the internet and
    sails past a string comparison. Any public range wider than a /24 (IPv4) or
    /48 (IPv6) counts as open. Expressions like var.admin_cidr are not literals
    and are not judged here.
    """
    if not isinstance(cidr, str) or "${" in cidr:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if any(net.version == p.version and net.subnet_of(p) for p in _PRIVATE_NETS):
        return False
    return net.prefixlen < (24 if net.version == 4 else 48)


_WHOLE_VAR = re.compile(r"^\$\{var\.([A-Za-z_][A-Za-z0-9_-]*)\}$")


def resolve(value: Any, module: Module) -> Any:
    """Substitute a bare variable reference with its default, if it has one.

    Without this, a "fix" that moves "0.0.0.0/0" into a variable default would hide
    the exposure from every check.
    """
    if isinstance(value, list):
        return [resolve(v, module) for v in value]
    if isinstance(value, str):
        m = _WHOLE_VAR.match(value)
        if m:
            var = module.by_address().get(f"var.{m.group(1)}")
            if var is not None and "default" in var.attrs:
                return resolve(var.attrs["default"], module)
    return value


def cidrs_of(attrs: dict[str, Any], keys: tuple[str, ...], module: Module) -> list[Any]:
    out: list[Any] = []
    for k in keys:
        for v in as_list(resolve(attrs.get(k), module)):
            out.extend(as_list(resolve(v, module)))
    return out


def _port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def exposed_ports(from_port: Any, to_port: Any, protocol: Any) -> list[str]:
    """Sensitive services reachable through a port range."""
    if str(protocol) in ("-1", "all"):
        return ["all ports"]
    lo, hi = _port(from_port), _port(to_port)
    if lo is None or hi is None:
        return []
    return [f"{name} ({p})" for p, name in SENSITIVE_PORTS.items() if lo <= p <= hi]


# --------------------------------------------------------------------------- checks


def _check_sg_inline(block: Block, module: Module) -> list[Violation]:
    out = []
    for i, rule in enumerate(as_list(block.attrs.get("ingress"))):
        if not isinstance(rule, dict):
            continue
        cidrs = cidrs_of(rule, ("cidr_blocks", "ipv6_cidr_blocks"), module)
        open_cidrs = [c for c in cidrs if is_open_cidr(c)]
        ports = exposed_ports(rule.get("from_port"), rule.get("to_port"), rule.get("protocol"))
        if open_cidrs and ports:
            out.append(
                (f"ingress[{i}]", f"{', '.join(ports)} open to {', '.join(open_cidrs)}")
            )
    return out


def _check_sg_rule(block: Block, module: Module) -> list[Violation]:
    a = block.attrs
    if a.get("type") != "ingress":
        return []
    cidrs = cidrs_of(a, ("cidr_blocks", "ipv6_cidr_blocks"), module)
    open_cidrs = [c for c in cidrs if is_open_cidr(c)]
    ports = exposed_ports(a.get("from_port"), a.get("to_port"), a.get("protocol"))
    if open_cidrs and ports:
        return [("", f"{', '.join(ports)} open to {', '.join(open_cidrs)}")]
    return []


def _check_vpc_ingress_rule(block: Block, module: Module) -> list[Violation]:
    a = block.attrs
    open_cidrs = [c for c in cidrs_of(a, ("cidr_ipv4", "cidr_ipv6"), module) if is_open_cidr(c)]
    ports = exposed_ports(a.get("from_port"), a.get("to_port"), a.get("ip_protocol"))
    if open_cidrs and ports:
        return [("", f"{', '.join(ports)} open to {', '.join(open_cidrs)}")]
    return []


PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


def _check_s3_acl(block: Block, module: Module) -> list[Violation]:
    acl = block.attrs.get("acl")
    if acl in PUBLIC_ACLS:
        return [("acl", f'canned ACL "{acl}" grants public access')]
    return []


PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls",
             "restrict_public_buckets")


def _pab_for(bucket: Block, module: Module) -> list[Block]:
    return [
        p
        for p in module.of_type("aws_s3_bucket_public_access_block")
        if bucket.address in references(p.attrs.get("bucket"))
    ]


def _check_s3_missing_pab(block: Block, module: Module) -> list[Violation]:
    if not _pab_for(block, module):
        return [("", "no aws_s3_bucket_public_access_block references this bucket")]
    return []


def _check_pab_flags(block: Block, module: Module) -> list[Violation]:
    off = [f for f in PAB_FLAGS if not is_true(block.attrs.get(f))]
    if off:
        return [(f, f"{f} must be true") for f in off]
    return []


def _check_rds_public(block: Block, module: Module) -> list[Violation]:
    if is_true(block.attrs.get("publicly_accessible")):
        return [("publicly_accessible", "database is reachable from the internet")]
    return []


def _check_rds_encryption(block: Block, module: Module) -> list[Violation]:
    if not is_true(block.attrs.get("storage_encrypted")):
        return [("storage_encrypted", "storage encryption is not enabled")]
    return []


def _check_imdsv2(block: Block, module: Module) -> list[Violation]:
    opts = as_list(block.attrs.get("metadata_options"))
    tokens = opts[0].get("http_tokens") if opts and isinstance(opts[0], dict) else None
    if tokens != "required":
        path = "metadata_options[0].http_tokens" if opts else "metadata_options"
        return [(path, "IMDSv2 not enforced (http_tokens must be \"required\")")]
    return []


def _check_ebs_encryption(block: Block, module: Module) -> list[Violation]:
    if not is_true(block.attrs.get("encrypted")):
        return [("encrypted", "volume is not encrypted")]
    return []


def _check_iam_wildcard(block: Block, module: Module) -> list[Violation]:
    out = []
    for i, st in enumerate(as_list(block.attrs.get("statement"))):
        if not isinstance(st, dict) or st.get("effect", "Allow") != "Allow":
            continue
        actions = as_list(st.get("actions"))
        resources = as_list(st.get("resources"))
        if "*" in actions and "*" in resources:
            out.append((f"statement[{i}]", "allows every action on every resource"))
    return out


def _check_cloudtrail_validation(block: Block, module: Module) -> list[Violation]:
    if not is_true(block.attrs.get("enable_log_file_validation")):
        return [("enable_log_file_validation", "log file integrity validation is off")]
    return []


# --------------------------------------------------------------------------- registry

_SG_GUIDE = (
    "Restrict the source to a known network. Prefer a variable such as var.admin_cidr "
    "(declare it if missing) over inventing an IP. Do not change ports or protocol."
)

RULES: tuple[Rule, ...] = (
    Rule(
        "TFG-NET-01", "Sensitive port open to the internet (inline ingress)", "critical",
        "resource", ("aws_security_group",), _check_sg_inline,
        fix_paths=("ingress[*].cidr_blocks", "ingress[*].ipv6_cidr_blocks",
                   "ingress[*].security_groups", "ingress[*].prefix_list_ids"),
        review_paths=("ingress[*]",),
        guidance=_SG_GUIDE,
    ),
    Rule(
        "TFG-NET-02", "Sensitive port open to the internet (security group rule)", "critical",
        "resource", ("aws_security_group_rule",), _check_sg_rule,
        fix_paths=("cidr_blocks", "ipv6_cidr_blocks", "source_security_group_id",
                   "prefix_list_ids"),
        guidance=_SG_GUIDE,
    ),
    Rule(
        "TFG-NET-03", "Sensitive port open to the internet (VPC ingress rule)", "critical",
        "resource", ("aws_vpc_security_group_ingress_rule",), _check_vpc_ingress_rule,
        fix_paths=("cidr_ipv4", "cidr_ipv6", "referenced_security_group_id", "prefix_list_id"),
        guidance=_SG_GUIDE,
    ),
    Rule(
        "TFG-S3-01", "S3 bucket uses a public canned ACL", "high",
        "resource", ("aws_s3_bucket", "aws_s3_bucket_acl"), _check_s3_acl,
        fix_paths=("acl",),
        guidance='Set acl = "private".',
    ),
    Rule(
        "TFG-S3-02", "S3 bucket has no public access block", "high",
        "resource", ("aws_s3_bucket",), _check_s3_missing_pab,
        companions=(Companion("aws_s3_bucket_public_access_block", "bucket"),),
        guidance=(
            "Add an aws_s3_bucket_public_access_block whose bucket = <bucket>.id with all "
            "four flags set to true. Do not modify the bucket itself."
        ),
    ),
    Rule(
        "TFG-S3-03", "S3 public access block is not fully enabled", "high",
        "resource", ("aws_s3_bucket_public_access_block",), _check_pab_flags,
        fix_paths=PAB_FLAGS,
        guidance="Set all four flags to true.",
    ),
    Rule(
        "TFG-RDS-01", "RDS instance is publicly accessible", "critical",
        "resource", ("aws_db_instance",), _check_rds_public,
        fix_paths=("publicly_accessible",),
        guidance="Set publicly_accessible = false.",
    ),
    Rule(
        "TFG-RDS-02", "RDS storage is not encrypted", "high",
        "resource", ("aws_db_instance",), _check_rds_encryption,
        fix_paths=("storage_encrypted", "kms_key_id"),
        review_reason="enabling encryption on an existing RDS instance forces replacement",
        guidance="Set storage_encrypted = true.",
    ),
    Rule(
        "TFG-EC2-01", "EC2 instance does not enforce IMDSv2", "high",
        "resource", ("aws_instance", "aws_launch_template"), _check_imdsv2,
        fix_paths=("metadata_options",),
        guidance='Add or edit the metadata_options block so http_tokens = "required".',
    ),
    Rule(
        "TFG-EBS-01", "EBS volume is not encrypted", "medium",
        "resource", ("aws_ebs_volume",), _check_ebs_encryption,
        fix_paths=("encrypted", "kms_key_id"),
        review_reason="encrypting an existing EBS volume forces replacement",
        guidance="Set encrypted = true.",
    ),
    Rule(
        "TFG-IAM-01", "IAM policy allows * on *", "critical",
        "data", ("aws_iam_policy_document",), _check_iam_wildcard,
        fix_paths=("statement[*].actions", "statement[*].resources",
                   "statement[*].not_actions"),
        review_reason="least privilege depends on what the workload needs; a human must confirm",
        guidance=(
            "Narrow actions and resources to what the workload plausibly needs, based only "
            "on evidence in the files (resource names, comments). Never keep '*' for both."
        ),
    ),
    Rule(
        "TFG-LOG-01", "CloudTrail log file validation is disabled", "medium",
        "resource", ("aws_cloudtrail",), _check_cloudtrail_validation,
        fix_paths=("enable_log_file_validation",),
        guidance="Set enable_log_file_validation = true.",
    ),
)

RULES_BY_ID = {r.id: r for r in RULES}


def scan(module: Module, rules: tuple[Rule, ...] = RULES) -> list[Finding]:
    findings: list[Finding] = []
    for block in module.blocks:
        for rule in rules:
            if block.kind != rule.kind or block.type not in rule.types:
                continue
            for path, message in rule.check(block, module):
                findings.append(
                    Finding(rule.id, rule.severity, block.address, path, message,
                            block.file, block.line)
                )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.file, f.line, f.rule_id, f.path))
    return findings
