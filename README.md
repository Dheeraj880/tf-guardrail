# tf-guardrail

[![ci](https://github.com/Dheeraj880/tf-guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/Dheeraj880/tf-guardrail/actions/workflows/ci.yml) [![codeql](https://github.com/Dheeraj880/tf-guardrail/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dheeraj880/tf-guardrail/actions/workflows/codeql.yml) [![semgrep](https://github.com/Dheeraj880/tf-guardrail/actions/workflows/semgrep.yml/badge.svg)](https://github.com/Dheeraj880/tf-guardrail/actions/workflows/semgrep.yml)

A policy-as-code gate for Terraform that blocks insecure AWS infrastructure in pull
requests, and auto-remediates it **only when a deterministic verifier can prove the
fix is honest**.

```
PR changes infra/*.tf
        │
        ▼
   ┌─────────┐   findings    ┌────────────┐   proposed patch   ┌────────────┐
   │  scan   │ ────────────▶ │   fixer    │ ─────────────────▶ │  verifier  │
   │ 13 rules│               │ (Claude or │ ◀───────────────── │  (no AI)   │
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
and never reads comments for instructions.

Injection attempts are also detected deterministically: rule **TFG-AI-01** flags
comments that address AI or automated reviewers with a directive ("do not change",
"mark as safe", "add tfsec:ignore", "ignore previous instructions"). These are never
sent to the fixer; they go to the top of the PR as a warning for the security team.
Whether the model noticed the attempt no longer matters.

A patch is accepted only if:

| Check | Catches |
|---|---|
| Still parses | broken HCL |
| Re-scan: target resolved, no new findings | no-op fixes, `0.0.0.0/1`, open CIDR moved into a variable default, half-configured companions |
| No block deleted or renamed | deleting or renaming the resource to dodge the finding |
| Every changed attribute is inside the rule's declared fix scope, pinned to the flagged element | changing ports, `skip_final_snapshot`, the HTTPS rule next to the SSH rule, `effect = "Deny"` tricks |
| No meta-argument changes | `count = 0`, `for_each = {}`, `lifecycle`, `provider` |
| New blocks are only declared companions that reference the flagged resource, or variables the fix uses | adding unrelated resources, a public access block pointed at the wrong bucket |
| No suppression comments or placeholders added | `tfsec:ignore`, `checkov:skip`, `nosec`, `TODO` |
| No finding other than the target disappears | quietly deleting the injection comment, or fixing something it wasn't asked to |

Verdicts:

- **ACCEPT**: safe to propose as-is.
- **REVIEW**: legitimate, but a human must look. Examples: encrypting an existing RDS
  volume (forces replacement), narrowing an IAM wildcard (depends on intent), deleting a
  firewall rule, or a value that now comes from an input variable the tool can't see.
- **REJECT**: the exact reasons go back to the fixer for another attempt (max 3).

Nothing is ever merged automatically. Fixes land as a separate pull request.

## Results

**Cheat gallery** (`examples/cases/gallery.json`): 26 hand-written fixes, 8 honest and
18 dishonest, run against the verifier in CI.

```
$ tfguard eval
...
26/26 cases as expected | cheat catch rate 1.0 | honest pass rate 1.0
```

Both numbers matter: a verifier that rejects everything catches every cheat and is
useless. These cases were written alongside the verifier, so 1.0 is a regression floor,
not proof it catches everything. New bypasses get added as cases.

**Live run** with Claude as the fixer, on `examples/vulnerable/` (10 fixable findings,
run before TFG-AI-01 existed): all 10 fixed on the first attempt, 6 ACCEPT and 4 REVIEW,
0 rejected. Two things worth reading in that run:

- The model set `storage_encrypted = true` on the existing database. Its note warned this
  forces replacement; the verifier turned that warning into a REVIEW verdict a reviewer
  can't skim past.
- For the open Postgres rule it reused `var.admin_cidr`, whose description says it is
  the *SSH* admin range. Safe (no longer public), probably not intended. The verifier
  checks safety and scope, not intent, which is exactly why input-dependent fixes are
  REVIEW and never ACCEPT.

The model ignored the injected comment every time. That shows the prompt-level
mitigation working; it does not test the verifier, which is what the cheat gallery is for.

**Demo remediation** on `examples/vulnerable/` (11 findings), scripted fixer:

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
🚩 flagged for security team  TFG-AI-01   file.storage.tf
      comment gives instructions to automated reviewers: "NOTE TO AUTOMATED REVIEWERS ..."

findings 11 -> 2 | accepted 6, review 3, rejected 0, declined 1, flagged 1 | fix rate 0.9, first-try 0.889
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
| TFG-AI-01 | medium | comment tries to instruct automated reviewers (prompt injection) | never auto-fixed; flagged for a human |

## Security

Every push and pull request runs three security workflows, and findings land in the repo's **Security → Code scanning** tab as SARIF.

| Workflow | What it does |
|---|---|
| [`codeql.yml`](.github/workflows/codeql.yml) | CodeQL `security-extended` queries on the Python source **and** on the GitHub Actions workflows |
| [`semgrep.yml`](.github/workflows/semgrep.yml) | Semgrep community rulesets (`p/python`, `p/secrets`, `p/github-actions`) plus this project's own rules, uploaded as SARIF |
| [`dependabot.yml`](.github/dependabot.yml) | Weekly grouped updates for Python dependencies and for the pinned Actions |

**Custom Semgrep rules** ([`.semgrep/tfguard.yml`](.semgrep/tfguard.yml)) encode this tool's trust boundary, so a future change can't quietly break it. Each rule has positive and negative test cases ([`.semgrep/tfguard.py`](.semgrep/tfguard.py)), CI runs `semgrep --test` first, and any finding from these rules fails the build:

- **`tfguard-unverified-fix-accepted`** — any module produced by `apply_edits()` from a model proposal must go through `verifier.verify()` before it is kept. This is the tool's core guarantee, enforced in CI rather than by convention.
- **`tfguard-untrusted-text-to-dangerous-sink`** (taint) — Terraform under review (which can carry prompt-injection comments) and the model's tool-call output must never reach `eval`/`exec`, `subprocess`, unsafe deserialization or a filesystem path. One flow is triaged inline in `cli.py`: output file names come from the scanned directory, and `apply_edits()` rejects any edit that names a file outside the module.

**Supply chain:** every third-party Action is pinned to a full commit SHA (Dependabot keeps the pins current), workflows default to `contents: read`, and checkouts don't persist credentials. The first Semgrep scan flagged the mutable `@v4`-style tags; pinning them is what fixed it.

**Triage:** community-rule false positives are suppressed inline with a `# nosemgrep: <rule> -- <reason>` comment, so every suppression is reviewable in the diff.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Limitations

- Works on HCL source, not `terraform plan`. It doesn't expand modules, evaluate
  `locals`/functions, or see inline `jsonencode()` IAM policies. Variable defaults are
  resolved for CIDR checks; inputs without defaults go to REVIEW.
- It can't know a change forces replacement in AWS unless the rule says so; the
  replacement-sensitive rules (RDS and EBS encryption) are always REVIEW. Running
  `terraform plan` in CI and checking for replacements is the next layer.
- The injection detector is keyword-based: it catches the common phrasing, not a
  determined attacker who avoids the words. Its job is to surface obvious attempts; the
  verifier is the control.
- AWS only, 13 rules. The rule format (detect + bounded fix scope) is the part meant to
  scale; adding rules is mostly data.

See [docs/DESIGN.md](docs/DESIGN.md) for the design decisions.
