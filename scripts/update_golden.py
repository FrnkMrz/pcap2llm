from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "golden"

sys.path.insert(0, str(ROOT / "src"))

from pcap2llm.pipeline import analyze_capture  # noqa: E402
from pcap2llm.profiles import load_profile  # noqa: E402
from pcap2llm.tshark_runner import TSharkRunner  # noqa: E402


def _canonicalize(artifact: dict) -> dict:
    payload = json.loads(json.dumps(artifact))
    if "generated_at" in payload:
        payload["generated_at"] = "<generated_at>"
    if "capture_sha256" in payload:
        payload["capture_sha256"] = "<capture_sha256>"
    if "capture_metadata" in payload:
        payload["capture_metadata"]["capture_file"] = "<fixture>"
    return payload


def update_fixture(path: Path, *, force: bool) -> None:
    scenario = json.loads((path / "scenario.json").read_text(encoding="utf-8"))
    raw_packets = json.loads((path / "raw_packets.json").read_text(encoding="utf-8"))
    capture = path / "fixture_capture.pcapng"
    capture.write_bytes(path.name.encode("utf-8"))

    runner = TSharkRunner()
    with patch.object(runner, "export_packets", return_value=raw_packets):
        artifacts = analyze_capture(
            capture,
            out_dir=path,
            runner=runner,
            profile=load_profile(scenario["profile"]),
            privacy_modes=scenario.get("privacy_modes", {}),
            max_packets=scenario.get("max_packets", 0),
        )

    expected_files = {
        "expected_summary.json": _canonicalize(artifacts.summary),
        "expected_detail.json": _canonicalize(artifacts.detail),
    }
    for filename, payload in expected_files.items():
        target = path / filename
        if target.exists() and not force:
            raise SystemExit(f"Refusing to overwrite {target}; rerun with --force")
        target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    force = "--force" in sys.argv
    selected = {arg for arg in sys.argv[1:] if not arg.startswith("-")}
    for scenario_dir in sorted(FIXTURES.iterdir()):
        if scenario_dir.is_dir():
            if selected and scenario_dir.name not in selected:
                continue
            update_fixture(scenario_dir, force=force)
            print(f"updated {scenario_dir.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
