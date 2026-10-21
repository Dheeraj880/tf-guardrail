# Test cases for tfguard.yml. Not imported anywhere; excluded from ruff and CodeQL.
import subprocess
from pathlib import Path


def accepts_without_verifying(current, proposal):
    # ruleid: tfguard-unverified-fix-accepted
    patched = apply_edits(current, proposal.edits)
    return patched


def verifies_first(module, current, proposal, targets, findings):
    # ok: tfguard-unverified-fix-accepted
    patched = apply_edits(current, proposal.edits)
    v = verify(module, patched, targets, findings)
    return patched if v.verdict == "ACCEPT" else current


def retry_loop(module, current, fixer, task, targets, findings):
    for n in range(3):
        proposal = fixer.propose(task, None)
        try:
            # ok: tfguard-unverified-fix-accepted
            patched = apply_edits(current, proposal.edits)
        except EditError:
            continue
        v = verify(module, patched, targets, findings)
        if v.verdict != "REJECT":
            return patched
    return current


def model_output_executed(resp):
    for call in resp.content:
        data = call.input
        # ruleid: tfguard-untrusted-text-to-dangerous-sink
        subprocess.run(data["command"], shell=True)


def model_chooses_output_path(fixer, task, out):
    proposal = fixer.propose(task, None)
    # ruleid: tfguard-untrusted-text-to-dangerous-sink
    (out / proposal.edits[0]["file"]).write_text("x")


def terraform_comment_evaluated(path):
    files = read_dir(path)
    # ruleid: tfguard-untrusted-text-to-dangerous-sink
    eval(files["main.tf"])


def fixed_output_path_is_fine(out):
    # ok: tfguard-untrusted-text-to-dangerous-sink
    Path(out / "tfguard-report.json").write_text("{}")
