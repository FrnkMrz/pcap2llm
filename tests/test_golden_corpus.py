from __future__ import annotations

import json
from pathlib import Path

from pcap2llm.pipeline import analyze_capture
from pcap2llm.profiles import load_profile
from pcap2llm.tshark_runner import TSharkRunner
from testutils import mock_runner_two_pass


FIXTURES = Path(__file__).parent / "fixtures" / "golden"


def _canonicalize(artifact: dict) -> dict:
    payload = json.loads(json.dumps(artifact))
    payload["generated_at"] = "<generated_at>"
    payload["capture_sha256"] = "<capture_sha256>"
    if "capture" in payload:
        payload["capture"]["path"] = "<fixture>"
        payload["capture"]["filename"] = "<fixture>.pcapng"
    if "capture_metadata" in payload:
        payload["capture_metadata"]["capture_file"] = "<fixture>"
    return payload


def test_golden_corpus_matches_expected(tmp_path: Path) -> None:
    runner = TSharkRunner()

    for scenario_dir in sorted(FIXTURES.iterdir()):
        scenario = json.loads((scenario_dir / "scenario.json").read_text(encoding="utf-8"))
        raw_packets = json.loads((scenario_dir / "raw_packets.json").read_text(encoding="utf-8"))
        expected_summary = json.loads((scenario_dir / "expected_summary.json").read_text(encoding="utf-8"))
        expected_detail = json.loads((scenario_dir / "expected_detail.json").read_text(encoding="utf-8"))
        capture = tmp_path / f"{scenario_dir.name}.pcapng"
        capture.write_bytes(scenario_dir.name.encode("utf-8"))

        with mock_runner_two_pass(runner, raw_packets):
            artifacts = analyze_capture(
                capture,
                out_dir=tmp_path,
                runner=runner,
                profile=load_profile(scenario["profile"]),
                privacy_modes=scenario.get("privacy_modes", {}),
                max_packets=scenario.get("max_packets", 0),
            )

        assert _canonicalize(artifacts.summary) == expected_summary, scenario_dir.name
        assert _canonicalize(artifacts.detail) == expected_detail, scenario_dir.name


def test_golden_scenarios_record_description_and_sanitization() -> None:
    for scenario_dir in sorted(FIXTURES.iterdir()):
        scenario = json.loads((scenario_dir / "scenario.json").read_text(encoding="utf-8"))
        assert scenario.get("description"), scenario_dir.name
        assert scenario.get("sanitization"), scenario_dir.name
