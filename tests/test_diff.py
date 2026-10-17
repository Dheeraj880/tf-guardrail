from tfguard.diff import diff


def test_scalar_and_key_changes():
    changes = diff({"a": 1, "b": 2}, {"a": 1, "b": 3, "c": 4})
    assert [(c.path, c.kind) for c in changes] == [("b", "changed"), ("c", "added")]


def test_removing_first_block_does_not_shift_the_rest():
    ssh = {"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
    https = {"from_port": 443, "cidr_blocks": ["0.0.0.0/0"]}
    changes = diff({"ingress": [ssh, https]}, {"ingress": [https]})
    assert [(c.path, c.kind) for c in changes] == [("ingress[0]", "removed")]


def test_edit_inside_a_block_is_reported_at_leaf():
    old = {"ingress": [{"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}
    new = {"ingress": [{"from_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]}
    assert [c.path for c in diff(old, new)] == ["ingress[0].cidr_blocks"]


def test_identical_values_produce_no_changes():
    v = {"tags": {"Name": "x"}, "list": [1, 2]}
    assert diff(v, v) == []
