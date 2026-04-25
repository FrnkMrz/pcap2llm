from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from pcap2llm.cli import app


runner = CliRunner()


def _discovery_payload(capture: Path) -> dict:
    return {
        "status": "ok",
        "mode": "discovery",
        "capture": {
            "path": str(capture),
            "filename": capture.name,
            "sha256": "abc123",
            "packet_count": 10,
            "first_packet_number": 1,
            "first_seen": "1.0",
            "last_seen": "2.0",
        },
        "transport_summary": {"sctp": 4, "tcp": 3},
        "name_resolution": {
            "hosts_file_used": False,
            "mapping_file_used": False,
            "resolved_peer_count": 0,
        },
        "resolved_peers": [],
        "capture_context": {
            "link_or_envelope_protocols": ["eth", "vlan"],
            "transport_support_protocols": ["sctp", "tcp"],
        },
        "protocol_summary": {
            "dominant_signaling_protocols": [{"name": "ngap", "count": 4, "strength": "strong"}],
            "top_protocols": [{"name": "ngap", "count": 4}],
            "relevant_protocols": ["ngap"],
            "raw_protocols": ["ngap", "sctp"],
        },
        "conversations": [],
        "anomalies": [],
        "suspected_domains": [{"domain": "5g-sa-core", "score": 0.9, "reason": ["ngap present"]}],
        "candidate_profiles": [{"profile": "5g-n2", "score": 0.95, "reason": ["ngap detected"]}],
        "suppressed_profiles": [],
    }


def test_discover_command_writes_discovery_artifacts(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"

    with patch(
        "pcap2llm.cli.discover_capture",
        return_value=(_discovery_payload(capture), "# Discovery Report\n"),
    ):
        result = runner.invoke(app, ["discover", str(capture), "--out", str(out_dir)])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["mode"] == "discovery"
    # artifacts written flat into out_dir — no discovery subdirectory
    assert "run_dir" not in payload
    json_path = Path(payload["discovery_json"])
    md_path = Path(payload["discovery_md"])
    assert json_path.parent == out_dir
    assert md_path.parent == out_dir
    assert json_path.name == "discover_sample_19700101_000001_V_01.json"
    assert md_path.name == "discover_sample_19700101_000001_V_01.md"
    assert json_path.exists()
    assert md_path.exists()
    # no subdirectory created
    subdirs = [p for p in out_dir.iterdir() if p.is_dir()]
    assert subdirs == [], f"unexpected subdirectories: {subdirs}"


def test_discover_command_passes_resolution_inputs_through_to_discovery(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    out_dir = tmp_path / "artifacts"
    config = tmp_path / "pcap2llm.config.yaml"
    config.write_text("display_filter: ngap\ntshark_extra_args:\n  - --foo\n", encoding="utf-8")
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("10.109.182.14 AMF-01\n", encoding="utf-8")
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text("nodes: []\n", encoding="utf-8")

    with patch(
        "pcap2llm.cli.discover_capture",
        return_value=(_discovery_payload(capture), "# Discovery Report\n"),
    ) as mocked:
        result = runner.invoke(
            app,
            [
                "discover",
                str(capture),
                "--out",
                str(out_dir),
                "--config",
                str(config),
                "--hosts-file",
                str(hosts),
                "--mapping-file",
                str(mapping),
            ],
        )

    assert result.exit_code == 0, result.stdout
    kwargs = mocked.call_args.kwargs
    assert kwargs["display_filter"] == "ngap"
    assert kwargs["hosts_file"] == hosts
    assert kwargs["mapping_file"] == mapping
    assert kwargs["extra_args"] == ["--foo"]


def test_recommend_profiles_reads_discovery_json(tmp_path: Path) -> None:
    discovery = tmp_path / "discovery.json"
    discovery.write_text(json.dumps(_discovery_payload(tmp_path / "sample.pcapng")), encoding="utf-8")

    result = runner.invoke(app, ["recommend-profiles", str(discovery)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["recommended_profiles"][0]["profile"] == "5g-n2"


def test_session_start_creates_manifest(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    result = runner.invoke(app, ["session", "start", str(capture), "--out", str(tmp_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    manifest = Path(payload["manifest"])
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["input_capture"]["path"] == str(capture)
    assert data["runs"] == []


def test_session_start_creates_unique_directories_in_same_second(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")

    first = runner.invoke(app, ["session", "start", str(capture), "--out", str(tmp_path)])
    second = runner.invoke(app, ["session", "start", str(capture), "--out", str(tmp_path)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert json.loads(first.stdout)["session"] != json.loads(second.stdout)["session"]


def test_session_run_discovery_registers_run(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    start = runner.invoke(app, ["session", "start", str(capture), "--out", str(tmp_path)])
    session_dir = Path(json.loads(start.stdout)["session"])

    with patch(
        "pcap2llm.cli.discover_capture",
        return_value=(_discovery_payload(capture), "# Discovery Report\n"),
    ):
        result = runner.invoke(app, ["session", "run-discovery", "--session", str(session_dir)])

    assert result.exit_code == 0
    manifest = json.loads((session_dir / "session_manifest.json").read_text(encoding="utf-8"))
    run = manifest["runs"][0]
    assert run["mode"] == "discovery"
    assert run["status"] == "completed"
    # outputs reference files directly in the run_dir (no nested discovery folder)
    run_dir = session_dir / run["run_id"]
    assert run_dir.is_dir()
    output_paths = list(run["outputs"].values())
    for p in output_paths:
        assert Path(p).parent == run_dir, f"{p} is not directly in run_dir {run_dir}"
    # no extra subdirectory inside the run_dir
    subdirs = [p for p in run_dir.iterdir() if p.is_dir()]
    assert subdirs == [], f"unexpected subdirectories in run_dir: {subdirs}"


def test_session_run_profile_registers_overrides_and_reason(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    start = runner.invoke(app, ["session", "start", str(capture), "--out", str(tmp_path)])
    session_dir = Path(json.loads(start.stdout)["session"])
    out_dir = session_dir / "01_lte-s6a"

    with (
        patch("pcap2llm.cli.analyze_capture", return_value=object()),
        patch(
            "pcap2llm.cli.write_artifacts",
            return_value={
                "summary": out_dir / "summary.json",
                "detail": out_dir / "detail.json",
                "markdown": out_dir / "summary.md",
            },
        ),
    ):
        result = runner.invoke(
            app,
            [
                "session",
                "run-profile",
                "--session",
                str(session_dir),
                "--profile",
                "lte-s6a",
                "--triggered-by",
                "00_discovery",
                "--reason",
                "diameter detected",
                "--no-verbatim-protocol",
                "diameter",
            ],
        )

    assert result.exit_code == 0
    manifest = json.loads((session_dir / "session_manifest.json").read_text(encoding="utf-8"))
    run = manifest["runs"][0]
    assert run["mode"] == "profile_analysis"
    assert run["triggered_by"] == "00_discovery"
    assert run["reason"] == ["diameter detected"]
    assert run["overrides"]["verbatim_protocols_removed"] == ["diameter"]


def test_session_finalize_writes_report(tmp_path: Path) -> None:
    capture = tmp_path / "sample.pcapng"
    capture.write_bytes(b"fake")
    start = runner.invoke(app, ["session", "start", str(capture), "--out", str(tmp_path)])
    session_dir = Path(json.loads(start.stdout)["session"])

    result = runner.invoke(app, ["session", "finalize", "--session", str(session_dir)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    report = Path(payload["report"])
    assert report.exists()
    assert "Session Report" in report.read_text(encoding="utf-8")
