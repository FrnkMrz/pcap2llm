from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from pcap2llm.cli import app
from pcap2llm.models import AnalyzeArtifacts


runner = CliRunner()


def _artifacts(out_dir: Path, *, mapping: bool = False, vault: bool = False, truncated: bool = False) -> AnalyzeArtifacts:
    coverage = {
        "detail_packets_included": 10 if not truncated else 10,
        "detail_packets_available": 10 if not truncated else 25,
        "detail_truncated": truncated,
        "summary_packet_count": 25 if truncated else 10,
        "truncation_note": "detail artifact contains 10 of 25 exported packets." if truncated else None,
    }
    return AnalyzeArtifacts(
        summary={
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "capture_sha256": "a" * 64,
            "profile": "lte-core",
            "artifact_role": "summary_sidecar",
            "capture_metadata": {
                "capture_file": "sample.pcapng",
                "packet_count": coverage["summary_packet_count"],
                "first_seen_epoch": "1712390000.0",
                "last_seen_epoch": "1712390001.0",
                "relevant_protocols": ["diameter"],
                "raw_protocols": ["eth", "ip", "sctp", "diameter"],
                "display_filter": None,
            },
            "relevant_protocols": ["diameter"],
            "conversations": [],
            "packet_message_counts": {"total_packets": coverage["summary_packet_count"], "top_protocols": {}, "transport": {}},
            "anomalies": [],
            "anomaly_counts_by_layer": {},
            "deterministic_findings": [],
            "probable_notable_findings": [],
            "privacy_modes": {"imsi": "pseudonymize" if mapping else "keep"},
            "privacy_policy": {},
            "coverage": coverage,
        },
        detail={
            "schema_version": "1.0",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "capture_sha256": "a" * 64,
            "profile": "lte-core",
            "artifact_role": "llm_input",
            "coverage": coverage,
            "messages": [],
            "selected_packets": [],
        },
        markdown="# summary\n",
        pseudonym_mapping={"imsi": {"001": "IMSI_12345678"}} if mapping else {},
        vault={"key_source": "env:PCAP2LLM_VAULT_KEY", "notes": ["metadata only"]} if vault else None,
    )


def test_llm_mode_dry_run_returns_machine_readable_json(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--dry-run", "--profile", "lte-core"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mode"] == "llm"
    assert payload["dry_run"] is True
    assert payload["files_would_be_written"] is True
    assert payload["capture"]["path"].endswith("sample.pcapng")


def test_llm_mode_success_returns_strict_json_and_files(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "20240406_075320_summary_V_01.json",
        "detail": out_dir / "20240406_075320_detail_V_01.json",
        "markdown": out_dir / "20240406_075320_summary_V_01.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mode"] == "llm"
    assert payload["files"]["detail"].endswith("_detail_V_01.json")
    assert payload["artifact_version"] == 1
    assert isinstance(payload["warnings"], list)


def test_llm_mode_includes_mapping_and_vault_sidecars_in_result(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "20240406_075320_summary_V_01.json",
        "detail": out_dir / "20240406_075320_detail_V_01.json",
        "markdown": out_dir / "20240406_075320_summary_V_01.md",
        "mapping": out_dir / "20240406_075320_pseudonym_mapping_V_01.json",
        "vault": out_dir / "20240406_075320_vault_V_01.json",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir, mapping=True, vault=True)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    payload = json.loads(result.stdout)
    assert payload["files"]["mapping"].endswith("pseudonym_mapping_V_01.json")
    assert payload["files"]["vault"].endswith("vault_V_01.json")
    warning_codes = {warning["code"] for warning in payload["warnings"]}
    assert "pseudonym_mapping_created" in warning_codes
    assert "encrypted_output_requires_key_handling" in warning_codes


def test_llm_mode_reports_truncation_warning(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "20240406_075320_summary_V_01.json",
        "detail": out_dir / "20240406_075320_detail_V_01.json",
        "markdown": out_dir / "20240406_075320_summary_V_01.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir, truncated=True)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    payload = json.loads(result.stdout)
    warning_codes = {warning["code"] for warning in payload["warnings"]}
    assert "detail_truncated" in warning_codes


def test_llm_mode_all_packets_with_guard_disabled_reports_limits(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "20240406_075320_summary_V_01.json",
        "detail": out_dir / "20240406_075320_detail_V_01.json",
        "markdown": out_dir / "20240406_075320_summary_V_01.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--llm-mode",
                "--all-packets",
                "--max-capture-size-mb",
                "0",
                "--profile",
                "lte-core",
                "--out",
                str(out_dir),
            ],
        )

    payload = json.loads(result.stdout)
    assert payload["limits"]["all_packets"] is True
    assert payload["limits"]["max_capture_size_mb"] == 0
    warning_codes = {warning["code"] for warning in payload["warnings"]}
    assert "capture_size_guard_disabled" in warning_codes


@pytest.mark.parametrize(
    ("side_effect", "code"),
    [
        (RuntimeError("capture file is 412.7 MiB, which exceeds --max-capture-size-mb 250"), "capture_too_large"),
        (RuntimeError("Encryption mode requires PCAP2LLM_VAULT_KEY to be set explicitly."), "missing_vault_key"),
        (RuntimeError("PCAP2LLM_VAULT_KEY is not a valid Fernet key: bad"), "invalid_vault_key"),
        (RuntimeError("detail export would be truncated at 100 of 500 packets"), "detail_truncated_and_disallowed"),
    ],
)
def test_llm_mode_maps_known_runtime_failures(tmp_path: Path, side_effect: Exception, code: str) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    with patch("pcap2llm.cli.analyze_capture", side_effect=side_effect):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["error"]["code"] == code


def test_llm_mode_maps_tshark_missing(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    with patch("pcap2llm.cli.analyze_capture", side_effect=RuntimeError("tshark was not found in PATH. Install Wireshark/TShark and retry.")):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core"])

    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "tshark_missing"


def test_llm_mode_maps_artifact_write_failure(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", side_effect=RuntimeError("Failed to write artifacts to 'artifacts': disk full")),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    payload = json.loads(result.stdout)
    assert payload["error"]["code"] == "artifact_write_failed"
