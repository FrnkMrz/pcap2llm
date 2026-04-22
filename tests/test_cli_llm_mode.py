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
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
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
    assert payload["files"]["detail"].endswith("_V_01_detail.json")
    assert payload["artifact_version"] == 1
    assert isinstance(payload["warnings"], list)


def test_llm_mode_includes_mapping_and_vault_sidecars_in_result(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
        "mapping": out_dir / "analyze_sample_start_1_V_01_pseudonym_mapping.json",
        "vault": out_dir / "analyze_sample_start_1_V_01_vault.json",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir, mapping=True, vault=True)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    payload = json.loads(result.stdout)
    assert payload["files"]["mapping"].endswith("_V_01_pseudonym_mapping.json")
    assert payload["files"]["vault"].endswith("_V_01_vault.json")
    warning_codes = {warning["code"] for warning in payload["warnings"]}
    assert "pseudonym_mapping_created" in warning_codes
    assert "encrypted_output_requires_key_handling" in warning_codes


def test_llm_mode_includes_flow_sidecars_in_result(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
        "flow_json": out_dir / "analyze_sample_start_1_V_01_flow.json",
        "flow_svg": out_dir / "analyze_sample_start_1_V_01_flow.svg",
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
                "--profile",
                "lte-core",
                "--out",
                str(out_dir),
                "--render-flow-svg",
            ],
        )

    payload = json.loads(result.stdout)
    assert payload["files"]["flow_json"].endswith("_V_01_flow.json")
    assert payload["files"]["flow_svg"].endswith("_V_01_flow.svg")


def test_llm_mode_reports_truncation_warning(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
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
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
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
        (RuntimeError("tshark output is not valid JSON: Expecting value: line 1"), "invalid_tshark_json"),
        (RuntimeError("unknown tshark error"), "tshark_failed"),
        (RuntimeError("capture exported 47,312 packets but detail limit is 1,000 (47× oversize). Narrow with -Y"), "capture_oversize"),
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


# ---------------------------------------------------------------------------
# New contract tests
# ---------------------------------------------------------------------------

def test_llm_mode_full_load_ingestion_warning_always_present(tmp_path: Path) -> None:
    """full_load_ingestion_applies must appear in every success run (two-pass: informational about pass-1 scan scope)."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    warning_codes = {w["code"] for w in payload["warnings"]}
    assert "full_load_ingestion_applies" in warning_codes


def test_llm_mode_no_relevant_protocols_warning(tmp_path: Path) -> None:
    """no_relevant_protocols_detected must appear when relevant_protocols is empty."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
    }

    # Build artifacts with no relevant protocols
    arts = _artifacts(out_dir)
    arts.summary["relevant_protocols"] = []
    arts.summary["capture_metadata"]["relevant_protocols"] = []

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=arts),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    warning_codes = {w["code"] for w in payload["warnings"]}
    assert "no_relevant_protocols_detected" in warning_codes


def test_llm_mode_success_payload_contains_required_fields(tmp_path: Path) -> None:
    """Success payload must include profile, privacy_profile, capture.sha256, schema_versions."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(
            app,
            ["analyze", str(capture), "--llm-mode", "--profile", "lte-core",
             "--privacy-profile", "share", "--out", str(out_dir)],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["profile"] == "lte-core"
    assert payload["privacy_profile"] == "share"
    assert "sha256" in payload["capture"]
    assert payload["capture"]["sha256"] is not None
    assert "schema_versions" in payload
    assert "summary" in payload["schema_versions"]
    assert "detail" in payload["schema_versions"]


def test_llm_mode_unknown_error_falls_back_to_runtime_error_code(tmp_path: Path) -> None:
    """An unrecognised RuntimeError must map to runtime_error, stdout must be valid JSON."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    with patch("pcap2llm.cli.analyze_capture", side_effect=RuntimeError("something completely unexpected")):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)   # must not raise
    assert payload["status"] == "error"
    assert payload["error"]["code"] == "runtime_error"
    assert payload["mode"] == "llm"


def test_llm_mode_dry_run_includes_profile_limits_and_command(tmp_path: Path) -> None:
    """--llm-mode --dry-run must include profile, limits block, and tshark command."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    result = runner.invoke(
        app,
        ["analyze", str(capture), "--llm-mode", "--dry-run",
         "--profile", "lte-core", "--max-packets", "500"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["dry_run"] is True
    assert payload["profile"] == "lte-core"
    assert "limits" in payload
    assert payload["limits"]["max_packets"] == 500
    assert "command" in payload
    assert isinstance(payload["command"], list)


def test_llm_mode_dry_run_includes_effective_verbatim_configuration(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    result = runner.invoke(
        app,
        [
            "analyze",
            str(capture),
            "--llm-mode",
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


def test_llm_mode_dry_run_includes_privacy_profile_when_set(tmp_path: Path) -> None:
    """--llm-mode --dry-run must echo back the --privacy-profile argument."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    result = runner.invoke(
        app,
        ["analyze", str(capture), "--llm-mode", "--dry-run",
         "--profile", "lte-core", "--privacy-profile", "share"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["privacy_profile"] == "share"


def test_llm_mode_dry_run_writes_no_artifacts(tmp_path: Path) -> None:
    """--dry-run must not write any files to the output directory."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"

    result = runner.invoke(
        app,
        ["analyze", str(capture), "--llm-mode", "--dry-run",
         "--profile", "lte-core", "--out", str(out_dir)],
    )

    assert result.exit_code == 0
    assert not out_dir.exists(), "dry-run must not create the output directory"


def test_llm_mode_success_coverage_block_has_required_keys(tmp_path: Path) -> None:
    """Coverage block must contain the required fields for machine consumers."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    cov = payload["coverage"]
    assert "detail_packets_included" in cov
    assert "detail_packets_available" in cov
    assert "detail_truncated" in cov
    assert cov["detail_truncated"] is False
    assert cov["detail_packets_included"] == 10


def test_llm_mode_success_includes_effective_verbatim_configuration(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
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
                "--profile",
                "lte-s6a",
                "--no-verbatim-protocol",
                "diameter",
                "--out",
                str(out_dir),
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["effective_verbatim_protocols"] == []
    assert payload["effective_profile_overrides"]["verbatim_protocols"]["profile_default"] == ["diameter"]
    assert payload["effective_profile_overrides"]["verbatim_protocols"]["removed"] == ["diameter"]


def test_llm_mode_oversize_guard_disabled_reports_warning(tmp_path: Path) -> None:
    """--oversize-factor 0 must appear as a warning in the success payload."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(
            app,
            ["analyze", str(capture), "--llm-mode",
             "--oversize-factor", "0", "--profile", "lte-core", "--out", str(out_dir)],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    warning_codes = {w["code"] for w in payload["warnings"]}
    assert "oversize_guard_disabled" in warning_codes
    assert payload["limits"]["oversize_factor"] == 0.0


def test_llm_mode_oversize_factor_present_in_limits(tmp_path: Path) -> None:
    """limits block must include oversize_factor in every success response."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    outputs = {
        "summary": out_dir / "analyze_sample_start_1_V_01_summary.json",
        "detail": out_dir / "analyze_sample_start_1_V_01_detail.json",
        "markdown": out_dir / "analyze_sample_start_1_V_01_summary.md",
    }

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=_artifacts(out_dir)),
        patch("pcap2llm.cli.write_artifacts", return_value=outputs),
    ):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core", "--out", str(out_dir)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "oversize_factor" in payload["limits"]
    assert payload["limits"]["oversize_factor"] == 10.0  # default


def test_llm_mode_stdout_is_pure_json_on_error(tmp_path: Path) -> None:
    """On error, stdout must be a single JSON document with nothing before or after it."""
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    with patch("pcap2llm.cli.analyze_capture", side_effect=RuntimeError("tshark was not found in PATH. Install Wireshark/TShark and retry.")):
        result = runner.invoke(app, ["analyze", str(capture), "--llm-mode", "--profile", "lte-core"])

    assert result.exit_code == 1
    stripped = result.stdout.strip()
    assert stripped.startswith("{") and stripped.endswith("}")
    payload = json.loads(stripped)  # must not raise
    assert payload["status"] == "error"
    assert payload["mode"] == "llm"
