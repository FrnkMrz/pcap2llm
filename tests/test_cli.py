from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from pcap2llm.cli import app
from pcap2llm.models import CaptureMetadata, InspectResult


_ARTIFACT_PREFIX = "analyze_sample_20240406_075320"


def test_analyze_dry_run_outputs_local_subnets_file(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    local_subnets = tmp_path / "Subnets"
    local_subnets.write_text("10.0.0.0/24 EPC_CORE\n", encoding="utf-8")

    with patch("pcap2llm.cli._LOCAL_SUBNETS_DEFAULT", local_subnets):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "lte-core",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["subnets_file"] == str(local_subnets)


def test_analyze_dry_run_outputs_local_ss7pcs_file(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    local_ss7pcs = tmp_path / "ss7pcs"
    local_ss7pcs.write_text("0-5093 VZB\n", encoding="utf-8")

    with patch("pcap2llm.cli._LOCAL_SS7PCS_DEFAULT", local_ss7pcs):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "2g3g-sccp-mtp",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ss7pcs_file"] == str(local_ss7pcs)


def test_analyze_dry_run_outputs_local_network_element_mapping_file(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    local_mapping = tmp_path / "network_element_mapping.csv"
    local_mapping.write_text(
        "type,value,network_element_type\nsubnet,10.0.0.0/24,AMF\n",
        encoding="utf-8",
    )

    with patch("pcap2llm.cli._LOCAL_NETWORK_ELEMENT_MAPPING_DEFAULT", local_mapping):
        result = runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "lte-core",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["network_element_mapping_file"] == str(local_mapping)


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
            "--render-flow-svg",
            "--flow-max-events",
            "88",
            "--flow-svg-width",
            "1400",
            "--flow-title",
            "Test Flow",
            "--no-collapse-repeats",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["profile"] == "lte-core"
    assert payload["privacy_modes"]["ip"] == "mask"
    assert payload["fail_on_truncation"] is False
    assert payload["max_capture_size_mb"] == 250
    assert payload["render_flow_svg"] is True
    assert payload["flow_max_events"] == 88
    assert payload["flow_svg_width"] == 1400
    assert payload["flow_title"] == "Test Flow"
    assert payload["collapse_repeats"] is False


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
                "summary": out_dir / f"{_ARTIFACT_PREFIX}_V_01_summary.json",
                "detail": out_dir / f"{_ARTIFACT_PREFIX}_V_01_detail.json",
                "markdown": out_dir / f"{_ARTIFACT_PREFIX}_V_01_summary.md",
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
                "summary": out_dir / f"{_ARTIFACT_PREFIX}_V_01_summary.json",
                "detail": out_dir / f"{_ARTIFACT_PREFIX}_V_01_detail.json",
                "markdown": out_dir / f"{_ARTIFACT_PREFIX}_V_01_summary.md",
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
    assert payload["artifact_prefix"] == _ARTIFACT_PREFIX
    assert payload["artifact_version"] == 1
    assert payload["summary"].endswith(f"{_ARTIFACT_PREFIX}_V_01_summary.json")


def _inspect_result(capture: Path) -> InspectResult:
    return InspectResult(
        metadata=CaptureMetadata(
            capture_file=str(capture),
            packet_count=1,
            raw_protocols=["diameter"],
            relevant_protocols=["diameter"],
            first_seen_epoch="1712390000.0",
            last_seen_epoch="1712390000.0",
            first_packet_number=1,
        ),
        protocol_counts={"diameter": 1},
        transport_counts={"sctp": 1},
        conversations=[
            {
                "key": "10.0.0.1->10.0.0.2",
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "transport": "sctp",
                "packet_count": 1,
                "top_protocol": "diameter",
            }
        ],
        anomalies=[],
    )


def test_inspect_out_directory_generates_semantic_json_filename(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample trace.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "inspect-artifacts"

    with patch("pcap2llm.cli.inspect_capture", return_value=_inspect_result(capture)):
        result = runner.invoke(
            app,
            ["inspect", str(capture), "--profile", "lte-core", "--out", str(out_dir)],
        )

    assert result.exit_code == 0
    output_path = out_dir / "inspect_sample_trace_20240406_075320_V_01.json"
    assert output_path.exists()
    assert f"Wrote inspect output to {output_path}" in result.stdout


def test_inspect_out_directory_generates_semantic_markdown_filename(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample trace.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "inspect-artifacts"

    with patch("pcap2llm.cli.inspect_capture", return_value=_inspect_result(capture)):
        result = runner.invoke(
            app,
            [
                "inspect",
                str(capture),
                "--profile",
                "lte-core",
                "--format",
                "markdown",
                "--out",
                str(out_dir),
            ],
        )

    assert result.exit_code == 0
    output_path = out_dir / "inspect_sample_trace_20240406_075320_V_01.md"
    assert output_path.exists()
    assert f"Wrote inspect output to {output_path}" in result.stdout


def test_ask_chatgpt_dry_run_outputs_plan(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    result = runner.invoke(
        app,
        [
            "ask-chatgpt",
            str(capture),
            "--dry-run",
            "--model",
            "gpt-4.1-mini",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "chatgpt"
    assert payload["profile"] == "(auto from discovery)"
    assert payload["privacy_profile"] == "llm-telecom-safe"


def test_ask_chatgpt_refuses_external_handoff_with_keep_modes(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"

    with (
        patch(
            "pcap2llm.cli.discover_capture",
            return_value=({"candidate_profiles": [{"profile": "lte-core"}]}, "# discovery"),
        ),
        patch(
            "pcap2llm.cli.write_discovery_artifacts",
            return_value={"discovery_json": out_dir / "discovery.json", "discovery_md": out_dir / "discovery.md"},
        ),
    ):
        result = runner.invoke(
            app,
            [
                "ask-chatgpt",
                str(capture),
                "--privacy-profile",
                "lab",
                "--out",
                str(out_dir),
            ],
        )

    assert result.exit_code == 1
    assert "refusing external LLM handoff" in result.stdout


def test_ask_claude_dry_run_outputs_plan(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    result = runner.invoke(
        app,
        [
            "ask-claude",
            str(capture),
            "--dry-run",
            "--model",
            "claude-3-5-sonnet-latest",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "claude"
    assert payload["profile"] == "(auto from discovery)"
    assert payload["privacy_profile"] == "llm-telecom-safe"


def test_ask_gemini_dry_run_outputs_plan(tmp_path: Path) -> None:
    runner = CliRunner()
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    result = runner.invoke(
        app,
        [
            "ask-gemini",
            str(capture),
            "--dry-run",
            "--model",
            "gemini-2.0-flash",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["mode"] == "gemini"
    assert payload["profile"] == "(auto from discovery)"
    assert payload["privacy_profile"] == "llm-telecom-safe"


def test_visualize_command_renders_svg_from_flow_json(tmp_path: Path) -> None:
    from pcap2llm.visualize import build_flow_model

    packets = [
        {
            "packet_no": 1,
            "time_rel_ms": 0.0,
            "time_epoch": "1712390001.0",
            "top_protocol": "diameter",
            "src": {"alias": "MME", "role": "mme"},
            "dst": {"alias": "HSS", "role": "hss"},
            "anomalies": [],
            "message": {"protocol": "diameter", "fields": {"message_name": "AIR"}},
        }
    ]
    flow = build_flow_model(
        packets,
        capture_file="test.pcap",
        profile="lte-core",
        privacy_profile=None,
    )
    flow_path = tmp_path / "flow.json"
    flow_path.write_text(json.dumps(flow), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(app, ["visualize", str(flow_path)])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["events"] == 1
    assert payload["nodes"] == 2
    svg_path = tmp_path / "flow.svg"
    assert svg_path.exists()
    assert "<svg" in svg_path.read_text(encoding="utf-8")


def test_visualize_command_respects_custom_out_and_width(tmp_path: Path) -> None:
    from pcap2llm.visualize import build_flow_model

    packets = [
        {
            "packet_no": 1,
            "time_rel_ms": 0.0,
            "time_epoch": "1712390001.0",
            "top_protocol": "diameter",
            "src": {"alias": "MME", "role": "mme"},
            "dst": {"alias": "HSS", "role": "hss"},
            "anomalies": [],
            "message": {"protocol": "diameter", "fields": {"message_name": "AIR"}},
        }
    ]
    flow = build_flow_model(
        packets,
        capture_file="test.pcap",
        profile="lte-core",
        privacy_profile=None,
    )
    flow_path = tmp_path / "flow.json"
    flow_path.write_text(json.dumps(flow), encoding="utf-8")
    out_path = tmp_path / "custom_output.svg"

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["visualize", str(flow_path), "--out", str(out_path), "--width", "800"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["svg"] == str(out_path)
    assert out_path.exists()
    svg = out_path.read_text(encoding="utf-8")
    assert 'width="800"' in svg
