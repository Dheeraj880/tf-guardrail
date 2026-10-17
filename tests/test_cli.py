import json

from conftest import DEMO_SCRIPT, EXAMPLE, GALLERY

from tfguard.cli import main


def test_scan_fails_on_high(capsys):
    assert main(["scan", str(EXAMPLE)]) == 1
    assert "10 findings" in capsys.readouterr().out


def test_scan_fail_on_none(capsys):
    assert main(["scan", str(EXAMPLE), "--fail-on", "none"]) == 0


def test_scan_sarif(tmp_path):
    out = tmp_path / "r.sarif"
    main(["scan", str(EXAMPLE), "--format", "sarif", "--output", str(out), "--sarif-base", "infra"])
    sarif = json.loads(out.read_text())
    results = sarif["runs"][0]["results"]
    assert len(results) == 10
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("infra/")


def test_fix_writes_outputs(tmp_path, capsys):
    rc = main(["fix", str(EXAMPLE), "--fixer", f"scripted:{DEMO_SCRIPT}", "--out", str(tmp_path)])
    assert rc == 0
    for name in ("network.tf", "tfguard-fix.patch", "tfguard-pr.md", "tfguard-report.json"):
        assert (tmp_path / name).exists()
    report = json.loads((tmp_path / "tfguard-report.json").read_text())
    assert report["kpis"]["findings_after"] == 1
    # The fixed module now passes a scan at high except the declined finding.
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 0


def test_verify_command(tmp_path, capsys):
    main(["fix", str(EXAMPLE), "--fixer", f"scripted:{DEMO_SCRIPT}", "--out", str(tmp_path),
          "--rule", "TFG-LOG-01"])
    rc = main(["verify", str(EXAMPLE), "--patched", str(tmp_path), "--rule", "TFG-LOG-01"])
    assert rc == 0 and "verdict: ACCEPT" in capsys.readouterr().out


def test_eval_command(capsys):
    assert main(["eval", "--cases", str(GALLERY)]) == 0
    assert "cheat catch rate 1.0" in capsys.readouterr().out


def test_parse_error_exit_code(tmp_path, capsys):
    (tmp_path / "bad.tf").write_text('resource "x" "y" {\n')
    assert main(["scan", str(tmp_path)]) == 2
