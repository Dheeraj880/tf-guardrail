from types import SimpleNamespace

from tfguard.fixer import AnthropicFixer, FixTask, render_task


def block(type_, **kw):
    return SimpleNamespace(type=type_, **kw)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(content=self.responses.pop(0))


def task(findings, files):
    f = next(x for x in findings if x.rule_id == "TFG-LOG-01")
    return FixTask(f.rule_id, f.address, [f], files)


EDITS = [{"file": "compute.tf", "old": "a", "new": "b"}]


def test_prompt_marks_files_untrusted_and_names_scope(findings, files):
    text = render_task(task(findings, files))
    assert "<untrusted_files>" in text and 'name="storage.tf"' in text
    assert "enable_log_file_validation" in text


def test_tool_call_is_parsed(findings, files):
    client = FakeClient([[block("tool_use", id="t1", input={"edits": EDITS, "notes": "n"})]])
    p = AnthropicFixer(client=client, model="m").propose(task(findings, files), None)
    assert p.edits == EDITS and p.notes == "n"
    call = client.calls[0]
    assert call["model"] == "m" and "tool_choice" not in call
    assert call["tools"][0]["name"] == "submit_fix"


def test_prose_answer_gets_one_nudge(findings, files):
    client = FakeClient([[block("text", text="Here is the fix...")],
                         [block("tool_use", id="t2", input={"edits": EDITS, "notes": ""})]])
    p = AnthropicFixer(client=client).propose(task(findings, files), None)
    assert p.edits == EDITS and len(client.calls) == 2


def test_rejection_goes_back_as_tool_error(findings, files):
    client = FakeClient([[block("tool_use", id="t1", input={"edits": EDITS, "notes": ""})],
                         [block("tool_use", id="t2", input={"edits": EDITS, "notes": ""})]])
    fixer = AnthropicFixer(client=client)
    t = task(findings, files)
    fixer.propose(t, None)
    fixer.propose(t, ["OUT_OF_SCOPE: nope"])
    last = client.calls[1]["messages"][-1]["content"][0]
    assert last["type"] == "tool_result" and last["is_error"] is True
    assert last["tool_use_id"] == "t1" and "OUT_OF_SCOPE" in last["content"]


def test_decline(findings, files):
    client = FakeClient([[block("tool_use", id="t1",
                                input={"edits": [], "notes": "", "decline_reason": "needs a human"})]])
    p = AnthropicFixer(client=client).propose(task(findings, files), None)
    assert p.edits == [] and p.decline_reason == "needs a human"
