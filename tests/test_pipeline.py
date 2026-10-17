from conftest import DEMO_SCRIPT

from tfguard.fixer import Proposal, ScriptedFixer
from tfguard.pipeline import run_fixes
from tfguard.report import pr_body


def test_demo_run(files):
    run = run_fixes(files, ScriptedFixer.from_file(DEMO_SCRIPT))
    k = run.kpis()
    assert (k["findings_before"], k["findings_after"]) == (11, 2)
    assert k["accepted"] == 6 and k["needs_review"] == 3 and k["declined"] == 1
    assert k["flagged"] == 1
    assert sorted(f.rule_id for f in run.final_findings) == ["TFG-AI-01", "TFG-RDS-02"]
    ssh = next(r for r in run.results if r.rule_id == "TFG-NET-01")
    assert [a.verdict for a in ssh.attempts] == ["REJECT", "REVIEW"]
    body = pr_body(run)
    assert "needs a human" in body and "TFG-RDS-02" in body
    assert "Possible prompt injection" in body
    # The original files are untouched; the patch is separate.
    assert 'cidr_blocks = ["0.0.0.0/0"]' in run.original["network.tf"]
    assert "var.admin_cidr" in run.patched["network.tf"]


class RecordingFixer:
    """Always cheats first, then fixes; records the feedback it was given."""

    def __init__(self):
        self.feedback = []

    def propose(self, task, feedback):
        self.feedback.append(feedback)
        if feedback is None:
            return Proposal([{"file": "compute.tf", "old": "nonexistent", "new": "x"}])
        return Proposal([{"file": "compute.tf", "old": "enable_log_file_validation = false",
                          "new": "enable_log_file_validation = true"}], "fixed")


def test_rejections_are_fed_back_to_the_fixer(files):
    fixer = RecordingFixer()
    run = run_fixes(files, fixer, rule_ids={"TFG-LOG-01"})
    assert run.results[0].outcome == "ACCEPT"
    assert fixer.feedback[0] is None
    assert fixer.feedback[1][0].startswith("EDIT:")


class AlwaysCheats:
    def propose(self, task, feedback):
        return Proposal([{"file": "compute.tf", "old": 'resource "aws_cloudtrail" "main"',
                          "new": 'resource "aws_cloudtrail" "main2"'}])


def test_unfixable_after_max_attempts_leaves_files_unchanged(files):
    run = run_fixes(files, AlwaysCheats(), max_attempts=3, rule_ids={"TFG-LOG-01"})
    r = run.results[0]
    assert r.outcome == "REJECTED" and len(r.attempts) == 3
    assert run.patched == run.original


def test_companion_fix_can_resolve_a_later_group():
    from tfguard.hcl import read_dir  # noqa: F401  (kept simple: inline module below)

    files = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'
                        'resource "aws_s3_bucket_public_access_block" "b" {\n'
                        '  bucket = aws_s3_bucket.b.id\n  block_public_acls = false\n'
                        '  block_public_policy = true\n  ignore_public_acls = true\n'
                        '  restrict_public_buckets = true\n}\n'}
    script = {"TFG-S3-03 aws_s3_bucket_public_access_block.b": [[
        {"file": "main.tf", "old": "block_public_acls = false", "new": "block_public_acls = true"}]]}
    run = run_fixes(files, ScriptedFixer(script))
    assert run.results[0].outcome == "ACCEPT" and run.final_findings == []
