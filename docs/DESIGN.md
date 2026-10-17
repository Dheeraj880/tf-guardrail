# Design notes

## The problem

Security teams lose the shift-left argument when the gate only says "no". Developers
get a red check, a rule ID and a link, and they either fix it slowly or ask for an
exception. Auto-remediation fixes the developer experience, but it introduces a new
risk: an automated change to infrastructure that nobody fully read.

So the question this project answers is not "can an AI fix Terraform?" It can, most of
the time. The question is **"how do you accept an automated security change without
trusting the thing that made it?"**

## Decisions

### 1. The fixer proposes, the verifier decides

The fixer's output is data: a list of exact text replacements. It never writes files,
runs commands or decides its own success. The verifier is ordinary deterministic code,
so its behaviour is testable, repeatable and identical whether the patch came from
Claude, a different model, a script or a human.

### 2. Every rule declares its fix scope

A rule is two things: a detector, and the set of attributes a fix for it may change
(plus any companion resources it may add). "Open SSH" may change the source CIDR of
the flagged ingress rule and nothing else. This is what turns "did the scanner go
quiet?" into "did the patch do only what this finding requires?"

Scope is pinned to the flagged element: a fix for `ingress[0]` may not edit
`ingress[1]`, even though both are `ingress[*].cidr_blocks`.

### 3. Compare meaning, not text

Patches are compared as parsed, normalized HCL. Whitespace, attribute order and
comments don't count as changes. Lists of blocks are aligned by content, so deleting
the first `ingress` block reads as one removal rather than every block changing.
Comments are checked separately, as text, for suppressions.

### 4. Three verdicts, not two

Some correct fixes still shouldn't ship unread: encryption that forces a database
replacement, narrowing an IAM wildcard (only the owner knows what the job needs), or a
CIDR that now comes from an input variable the tool can't see. These get REVIEW, which
is surfaced at the top of the PR description. Binary pass/fail would push those either
into "auto-merge" or "can't fix", and both are worse.

### 5. One finding at a time

Each finding group is fixed and verified separately, against the module as it stands
after earlier accepted fixes. Small patches are easier to check and to review, one bad
fix can't hide inside a large diff, and one stubborn finding doesn't block the rest.

### 6. Untrusted input, assumed injected

The fixer reads `.tf` files written by the PR author. The prompt wraps them in
`<untrusted_files>` and tells the model comments are data. That is a mitigation, not a
control. The control is that the verifier ignores comments entirely, so an injection
that succeeds against the model still produces a patch that gets rejected.

Detection is deterministic too. TFG-AI-01 flags comments that address automated
reviewers with a directive, and the finding is never sent to the fixer. Two verifier
rules protect it: a fix can't delete the comment (COLLATERAL: only the target finding
may disappear) and can't plant a new one (NEW_FINDING). An earlier version left it to
the model to mention the comment in its notes; it did, on every fix, which made the PR
noisy and made detection depend on the model's goodwill.

### 7. Measure the guardrail, not just the fixer

KPIs:

- **fix rate**: finding groups fixed (ACCEPT or REVIEW) / groups attempted
- **first-try rate**: fixes accepted on attempt 1 / fixes accepted
- **average attempts**: how much the repair loop is doing
- **cheat catch rate**: dishonest patches rejected / dishonest patches in the gallery
- **honest pass rate**: honest patches not rejected / honest patches in the gallery

The last two are a pair. Over-tightening the verifier raises catch rate and kills the
honest pass rate; the gallery keeps both visible in CI.

## Bypasses the gallery covers

| Trick | Caught by |
|---|---|
| delete / rename the resource | DELETED |
| `count = 0`, `for_each = {}` | META_ARGUMENT |
| `0.0.0.0/1` + `128.0.0.0/1` | re-scan (any public range wider than /24 is open) |
| `default = "0.0.0.0/0"` on a new variable | re-scan (variable defaults resolved) |
| SSH moved to 2222 | OUT_OF_SCOPE (ports not in fix scope) |
| fix the neighbouring rule too | OUT_OF_SCOPE (scope pinned to element) |
| `# tfsec:ignore`, `# checkov:skip` | SUPPRESSION |
| fix + flip `skip_final_snapshot` | OUT_OF_SCOPE |
| `effect = "Deny"` with `*` kept | OUT_OF_SCOPE (+ always REVIEW for IAM) |
| companion pointed at another bucket | UNEXPECTED_BLOCK, UNRESOLVED |
| companion with a flag still off | NEW_FINDING |
| `TODO` values | PLACEHOLDER |
| delete the injection comment while fixing | COLLATERAL |
| plant an instruction for the next AI | NEW_FINDING (TFG-AI-01) |

## What's next

- Run `terraform plan -json` in CI and reject or REVIEW any planned replacement or
  destroy, instead of relying on per-rule flags.
- Exceptions workflow: a reviewed, expiring allowlist file instead of inline
  suppression comments.
- More providers and rules; the rule format is the part meant to scale.
