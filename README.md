# tf-guardrail

A policy-as-code gate for Terraform that blocks insecure AWS infrastructure in pull
requests, and auto-remediates it **only when a deterministic verifier can prove the
fix is honest**.

```
PR changes infra/*.tf
        │
        ▼
   ┌─────────┐   findings    ┌────────────┐   proposed patch   ┌────────────┐
   │  scan   │ ────────────▶ │   fixer    │ ─────────────────▶ │  verifier  │
   │ 12 rules│               │ (Claude or │ ◀───────────────── │  (no AI)   │
   └─────────┘               │  scripted) │  exact rejection   └─────┬──────┘
        │                    └────────────┘  reasons, ≤3 tries       │
        ▼                                                ACCEPT / REVIEW / REJECT
  SARIF → GitHub code scanning                                       │
  fail the PR on high+                                               ▼
                                                    separate PR, human approves
```

## Why the verifier exists

Auto-remediation has an obvious failure mode: the fastest way to make a scanner go
quiet is not to fix the problem. Delete the resource. Rename it. Set `count = 0`.
Add `# tfsec:ignore`. Change `0.0.0.0/0` to `0.0.0.0/1`. Move SSH to port 2222. Hide
the open CIDR in a variable default. Every one of these "passes" a naive re-scan.

The fixer is untrusted. It can be wrong, and it reads files written by whoever opened
the PR, so it can be prompt-injected (the example repo contains a comment telling AI
tools to add a suppression). The verifier is ordinary code that never calls a model
and never reads comments for instructions. A patch is accepted only if:

| Check | Catches |
|---|---|
| Still parses | broken HCL |
| Re-scan: target resolved, no new findings | no-op fixes, `0.0.0.0/1`, open CIDR moved into a variable default, half-configured companions |
| No block deleted or renamed | deleting or renaming the resource to dodge the finding |
| Every changed attribute is inside the rule's declared fix scope, pinned to the flagged element | changing ports, `skip_final_snapshot`, the HTTPS rule next to the SSH rule, `effect = "Deny"` tricks |
| No meta-argument changes | `count = 0`, `for_each = {}`, `lifecycle`, `provider` |
| New blocks are only declared companions that reference the flagged resource, or variables the fix uses | adding unrelated resources, a public access block pointed at the wrong bucket |
| No suppression comments or placeholders added | `tfsec:ignore`, `checkov:skip`, `nosec`, `TODO` |

Verdicts:

- **ACCEPT**: safe to propose as-is.
- **REVIEW**: legitimate, but a human must look. Examples: encrypting an existing RDS
  volume (forces replacement), narrowing an IAM wildcard (depends on intent), deleting a
  firewall rule, or a value that now comes from an input variable the tool can't see.
- **REJECT**: the exact reasons go back to the fixer for another attempt (max 3).

Nothing is ever merged automatically. Fixes land as a separate pull request.

## Results

**Cheat gallery** (`examples/cases/gallery.json`): 24 hand-written fixes, 8 honest and
16 dishonest, run against the verifier in CI.

```
$ tfguard eval
...
24/24 cases as expected | cheat catch rate 1.0 | honest pass rate 1.0
```

Both numbers matter: a verifier that rejects everything catches every cheat and is
useless. These cases were written alongside the verifier, so 1.0 is a regression floor,
not proof it catches everything. New bypasses get added as cases.

**Demo remediation** on `examples/vulnerable/` (10 findings), scripted fixer:

```
$ tfguard fix examples/vulnerable --fixer scripted:examples/demo-fixer.json --out out/
✅ fixed                      TFG-RDS-01  aws_db_instance.orders
👀 fixed, needs review        TFG-NET-01  aws_security_group.bastion
      attempt 1: REJECT
          - OUT_OF_SCOPE ...: ingress[0].from_port: 22 -> 2222; this fix may only change
            ['ingress[0].cidr_blocks', ...]
      attempt 2: REVIEW
⏭️ needs a human             TFG-RDS-02  aws_db_instance.orders
...
findings 10 -> 1 | accepted 6, review 3, rejected 0, declined 1 | fix rate 0.9, first-try 0.889
```

`out/` gets the patched `.tf` files, a unified diff, a PR description and a JSON
report with KPIs.

## Quick start

```bash
pip install -e ".[dev]"

tfguard rules                                   # policies and the scope each fix may touch
tfguard scan examples/vulnerable                # exit 1 on high+ findings
tfguard scan examples/vulnerable --format sarif --output r.sarif
tfguard eval                                    # cheat gallery
tfguard fix examples/vulnerable --fixer scripted:examples/demo-fixer.json --out out
tfguard verify examples/vulnerable --patched out   # verify a patch from any source
```

Live AI fixes (needs an Anthropic API key in your environment, never in a file):

```bash
export ANTHROPIC_API_KEY=...          # PowerShell: $env:ANTHROPIC_API_KEY="..."
tfguard fix examples/vulnerable --out out-live
```

`TFGUARD_MODEL` picks the model (default `claude-sonnet-5-5`).

## CI integration

`examples/github-workflow/tf-guardrail.yml` is a drop-in workflow:

- every PR touching `infra/**.tf`: scan, upload SARIF to GitHub code scanning, fail on high+
- PR labelled `tfguard-fix`: run the fixer, keep only verified changes, open a
  separate PR whose description lists what was fixed, what needs review and what
  was left for a human

## Policies

| ID | Severity | Check | Fix may change |
|---|---|---|---|
| TFG-NET-01/02/03 | critical | SSH, RDP, database and other admin ports open to a public range wider than /24 (inline ingress, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`) | source CIDRs / SG / prefix list of the flagged rule only |
| TFG-S3-01 | high | public canned ACL | `acl` |
| TFG-S3-02 | high | bucket with no public access block | add a companion `aws_s3_bucket_public_access_block` |
| TFG-S3-03 | high | public access block flag off | the four flags |
| TFG-RDS-01 | critical | `publicly_accessible = true` | `publicly_accessible` |
| TFG-RDS-02 | high | storage not encrypted | `storage_encrypted`, `kms_key_id` (always REVIEW) |
| TFG-EC2-01 | high | IMDSv2 not required | `metadata_options` |
| TFG-EBS-01 | medium | EBS volume not encrypted | `encrypted`, `kms_key_id` (always REVIEW) |
| TFG-IAM-01 | critical | policy document allows `*` on `*` | actions/resources of that statement (always REVIEW) |
| TFG-LOG-01 | medium | CloudTrail log validation off | `enable_log_file_validation` |

## Limitations

- Works on HCL source, not `terraform plan`. It doesn't expand modules, evaluate
  `locals`/functions, or see inline `jsonencode()` IAM policies. Variable defaults are
  resolved for CIDR checks; inputs without defaults go to REVIEW.
- It can't know a change forces replacement in AWS unless the rule says so; the
  replacement-sensitive rules (RDS and EBS encryption) are always REVIEW. Running
  `terraform plan` in CI and checking for replacements is the next layer.
- AWS only, 12 rules. The rule format (detect + bounded fix scope) is the part meant to
  scale; adding rules is mostly data.

See [docs/DESIGN.md](docs/DESIGN.md) for the design decisions.
