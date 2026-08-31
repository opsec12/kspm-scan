from __future__ import annotations

import json
from pathlib import Path

import pytest

from kspm.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_manifests_json_exit_code_nonzero_on_high(capsys):
    exit_code = main(
        ["manifests", str(FIXTURES / "insecure_pod.yaml"), "-o", "json", "--fail-on", "HIGH"]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["finding_count"] > 0
    assert exit_code == 1


def test_cli_manifests_clean_exit_code_zero(capsys):
    exit_code = main(
        ["manifests", str(FIXTURES / "hardened_deployment.yaml"), "-o", "json", "--fail-on", "HIGH"]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["finding_count"] == 0
    assert payload["posture_score"] == 100
    assert exit_code == 0


def test_cli_fail_on_none_always_zero(capsys):
    exit_code = main(
        ["manifests", str(FIXTURES / "insecure_pod.yaml"), "-o", "json", "--fail-on", "NONE"]
    )
    assert exit_code == 0


def test_cli_html_output_to_file(tmp_path: Path):
    out_file = tmp_path / "report.html"
    exit_code = main(
        [
            "manifests",
            str(FIXTURES / "insecure_pod.yaml"),
            "-o",
            "html",
            "--output-file",
            str(out_file),
            "--fail-on",
            "NONE",
        ]
    )
    assert exit_code == 0
    assert out_file.exists()
    assert "KSPM Scan Report" in out_file.read_text()


def test_cli_missing_path_exits_2():
    with pytest.raises(SystemExit) as exc_info:
        main(["manifests", "/no/such/path", "--fail-on", "NONE"])
    assert exc_info.value.code == 2
