from __future__ import annotations

from pathlib import Path

from pcap2llm.pipeline import analyze_capture
from pcap2llm.profiles import load_profile
from pcap2llm.tshark_runner import TSharkRunner
from testutils import mock_runner_two_pass


def _raw_packet() -> dict:
    return {
        "_source": {
            "layers": {
                "frame.number": "1",
                "frame.time_epoch": "1712390000.0",
                "frame.time_relative": "0.0",
                "frame.protocols": "eth:ip:sctp:diameter",
                "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                "sctp": {"sctp.srcport": "3868", "sctp.dstport": "3868", "sctp.assoc_index": "0"},
                "diameter": {"diameter.cmd.code": "316", "diameter.imsi": "001010123456789"},
            }
        }
    }


def test_public_artifacts_include_schema_metadata_and_roles(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    runner = TSharkRunner()
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"fixture")

    with mock_runner_two_pass(runner, [_raw_packet()]):
        artifacts = analyze_capture(
            capture,
            out_dir=tmp_path,
            runner=runner,
            profile=profile,
            privacy_modes={"imsi": "pseudonymize"},
        )

    assert artifacts.detail["schema_version"] == "1.0"
    assert artifacts.summary["schema_version"] == "1.0"
    assert artifacts.detail["artifact_role"] == "llm_input"
    assert artifacts.summary["artifact_role"] == "summary_sidecar"
    assert "coverage" in artifacts.detail
    assert "coverage" in artifacts.summary
    assert "messages" in artifacts.detail
    assert "deterministic_findings" in artifacts.summary


def test_fail_on_truncation_raises(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    runner = TSharkRunner()
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"fixture")

    with mock_runner_two_pass(runner, [_raw_packet(), _raw_packet()]):
        try:
            analyze_capture(
                capture,
                out_dir=tmp_path,
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=1,
                fail_on_truncation=True,
            )
        except RuntimeError as exc:
            assert "truncated" in str(exc)
        else:
            raise AssertionError("expected fail_on_truncation to raise")
