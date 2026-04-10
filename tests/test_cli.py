from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from pcap2llm.cli import app


def test_init_config_writes_file(tmp_path: Path) -> None:
    runner = CliRunner()
    config_path = tmp_path / "pcap2llm.config.yaml"
    result = runner.invoke(app, ["init-config", str(config_path)])
    assert result.exit_code == 0
    assert config_path.exists()
    assert "profile: lte-core" in config_path.read_text(encoding="utf-8")


def test_analyze_dry_run_outputs_plan(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    result = runner.invoke(
        app,
        [
            "analyze",
            str(capture),
            "--dry-run",
            "--profile",
            "lte-core",
            "--ip-mode",
            "mask",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["profile"] == "lte-core"
    assert payload["privacy_modes"]["ip"] == "mask"
    assert payload["fail_on_truncation"] is False
    assert payload["max_capture_size_mb"] == 250


def test_analyze_dry_run_includes_effective_verbatim_overrides(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    result = runner.invoke(
        app,
        [
            "analyze",
            str(capture),
            "--dry-run",
            "--profile",
            "lte-s6a",
            "--verbatim-protocol",
            "gtpv2",
            "--no-verbatim-protocol",
            "diameter",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["effective_verbatim_protocols"] == ["gtpv2"]
    assert payload["effective_profile_overrides"]["verbatim_protocols"]["profile_default"] == ["diameter"]
    assert payload["effective_profile_overrides"]["verbatim_protocols"]["added"] == ["gtpv2"]
    assert payload["effective_profile_overrides"]["verbatim_protocols"]["removed"] == ["diameter"]


def test_analyze_override_removal_wins_in_conflict(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    result = runner.invoke(
        app,
        [
            "analyze",
            str(capture),
            "--dry-run",
            "--profile",
            "lte-s6a",
            "--verbatim-protocol",
            "diameter",
            "--no-verbatim-protocol",
            "diameter",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["effective_verbatim_protocols"] == []


def test_analyze_passes_effective_verbatim_profile_to_pipeline(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"

    captured_profile = None

    def _capture_analyze(*args, **kwargs):
        nonlocal captured_profile
        captured_profile = kwargs["profile"]
        return object()

    with (
        patch("pcap2llm.cli.analyze_capture", side_effect=_capture_analyze),
        patch(
            "pcap2llm.cli.write_artifacts",
            return_value={
                "summary": out_dir / "20240406_075320_summary_V_01.json",
                "detail": out_dir / "20240406_075320_detail_V_01.json",
                "markdown": out_dir / "20240406_075320_summary_V_01.md",
            },
        ),
    ):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--profile",
                "lte-s6a",
                "--no-verbatim-protocol",
                "diameter",
                "--verbatim-protocol",
                "gtpv2",
                "--out",
                str(out_dir),
            ],
        )

    assert result.exit_code == 0
    assert captured_profile is not None
    assert captured_profile.verbatim_protocols == ["gtpv2"]


def test_analyze_outputs_artifact_prefix_and_version(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=object()),
        patch(
            "pcap2llm.cli.write_artifacts",
            return_value={
                "summary": out_dir / "20240406_075320_summary_V_01.json",
                "detail": out_dir / "20240406_075320_detail_V_01.json",
                "markdown": out_dir / "20240406_075320_summary_V_01.md",
            },
        ),
    ):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--profile",
                "lte-core",
                "--out",
                str(out_dir),
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["artifact_prefix"] == "20240406_075320"
    assert payload["artifact_version"] == 1
    assert payload["summary"].endswith("20240406_075320_summary_V_01.json")
