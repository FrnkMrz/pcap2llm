from __future__ import annotations

import json
from pathlib import Path

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
