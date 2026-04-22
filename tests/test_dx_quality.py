"""Tests for DX/Quality improvements:
- _flatten() cycle detection
- max_conversations profile field
- schema_version / generated_at / capture_sha256 in artifacts
- CLI exit codes
- Privacy mode help text visibility
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import patch
from typer.testing import CliRunner

from pcap2llm.cli import app
from pcap2llm.normalizer import _flatten
from pcap2llm.pipeline import analyze_capture, write_artifacts
from pcap2llm.profiles import load_profile
from pcap2llm.tshark_runner import TSharkRunner
from testutils import mock_runner_two_pass


# ---------------------------------------------------------------------------
# _flatten – cycle detection
# ---------------------------------------------------------------------------

class TestFlattenCycleDetection:
    def test_non_circular_list_unwrapped(self) -> None:
        assert _flatten(["hello"]) == "hello"

    def test_non_circular_nested_list(self) -> None:
        assert _flatten([[1, 2], [3]]) == [[1, 2], 3]

    def test_non_circular_dict_passes_through(self) -> None:
        result = _flatten({"a": ["x"]})
        assert result == {"a": "x"}

    def test_circular_list_returns_sentinel(self) -> None:
        """A list that contains itself must not recurse infinitely."""
        lst: list = [1]
        lst.append(lst)  # type: ignore[arg-type]
        result = _flatten(lst)
        # The outer list has 2 elements so it is returned as-is (no single-element
        # unwrap), but the nested self-reference becomes "<circular>".
        assert "<circular>" in result

    def test_circular_dict_returns_sentinel(self) -> None:
        """A dict that references itself must not recurse infinitely."""
        d: dict = {"key": None}
        d["self"] = d  # type: ignore[assignment]
        result = _flatten(d)
        assert result["self"] == "<circular>"

    def test_sibling_elements_not_affected_by_cycle(self) -> None:
        """Cycle detection via frozenset must not mark non-circular siblings."""
        inner = [42]
        outer = [inner, inner]  # same object used twice, but no cycle
        result = _flatten(outer)
        # Both should resolve to 42 (single-element lists unwrapped)
        assert result == [42, 42]

    def test_scalar_passthrough(self) -> None:
        for value in (0, 3.14, True, None, "text"):
            assert _flatten(value) is value or _flatten(value) == value


# ---------------------------------------------------------------------------
# max_conversations – profile field
# ---------------------------------------------------------------------------

class TestMaxConversations:
    def test_default_max_conversations(self) -> None:
        profile = load_profile("lte-core")
        # lte-core does not set max_conversations; the model default is 25
        assert profile.max_conversations == 25

    def test_max_conversations_limits_output(self) -> None:
        from pcap2llm.normalizer import inspect_raw_packets

        profile = load_profile("lte-core")
        # Force a small limit
        object.__setattr__(profile, "max_conversations", 3)

        raw_packets = [
            {
                "_source": {
                    "layers": {
                        "frame.number": str(i),
                        "frame.time_epoch": f"1712390{i:03d}.0",
                        "frame.time_relative": str(i * 0.01),
                        "frame.protocols": "eth:ip:tcp",
                        "ip": {"ip.src": f"10.0.0.{i}", "ip.dst": "10.0.0.254"},
                        "tcp": {
                            "tcp.srcport": str(1024 + i),
                            "tcp.dstport": "80",
                            "tcp.stream": str(i),
                        },
                    }
                }
            }
            for i in range(1, 20)
        ]

        result = inspect_raw_packets(
            raw_packets,
            capture_path=Path("dummy.pcap"),
            display_filter=None,
            profile=profile,
        )
        assert len(result.conversations) <= 3

    def test_yaml_max_conversations_loaded(self) -> None:
        """All built-in profiles must have max_conversations >= 1."""
        for name in (
            "lte-core",
            "lte-s1",
            "lte-s1-nas",
            "lte-s6a",
            "lte-s11",
            "lte-s10",
            "lte-sgs",
            "lte-s5",
            "lte-s8",
            "lte-dns",
            "lte-sbc-cbc",
            "2g3g-gn",
            "2g3g-gp",
            "2g3g-gr",
            "2g3g-gs",
            "2g3g-geran",
            "2g3g-dns",
            "2g3g-map-core",
            "2g3g-cap",
            "2g3g-bssap",
            "2g3g-isup",
            "2g3g-sccp-mtp",
            "5g-core",
            "2g3g-ss7-geran",
        ):
            profile = load_profile(name)
            assert profile.max_conversations >= 1, f"{name}: max_conversations must be >= 1"


# ---------------------------------------------------------------------------
# Output artifacts – schema_version, generated_at, capture_sha256
# ---------------------------------------------------------------------------

def _make_raw_packet(number: str = "1") -> dict:
    return {
        "_source": {
            "layers": {
                "frame.number": number,
                "frame.time_epoch": "1712390000.0",
                "frame.time_relative": "0.0",
                "frame.protocols": "eth:ip:sctp:diameter",
                "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                "sctp": {
                    "sctp.srcport": "3868",
                    "sctp.dstport": "3868",
                    "sctp.assoc_index": "0",
                },
                "diameter": {
                    "diameter.cmd.code": "316",
                    "diameter.imsi": "001010123456789",
                },
            }
        }
    }


class TestArtifactMetadata:
    def _run_pipeline(self, tmp_path: Path) -> object:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake pcap content")

        with mock_runner_two_pass(runner, [_make_raw_packet()]):
            return analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes=profile.default_privacy_modes,
            )

    def test_summary_has_schema_version(self, tmp_path: Path) -> None:
        artifacts = self._run_pipeline(tmp_path)
        assert artifacts.summary.get("schema_version") == "1.0"

    def test_summary_has_generated_at_iso8601(self, tmp_path: Path) -> None:
        artifacts = self._run_pipeline(tmp_path)
        generated_at = artifacts.summary.get("generated_at")
        assert generated_at is not None
        # Must parse as ISO 8601 with timezone info
        from datetime import datetime
        dt = datetime.fromisoformat(generated_at)
        assert dt.tzinfo is not None, "generated_at must include timezone"

    def test_summary_has_capture_sha256(self, tmp_path: Path) -> None:
        artifacts = self._run_pipeline(tmp_path)
        sha = artifacts.summary.get("capture_sha256")
        assert sha is not None
        assert re.fullmatch(r"[0-9a-f]{64}", sha), "capture_sha256 must be a 64-char hex string"

    def test_detail_has_schema_version(self, tmp_path: Path) -> None:
        artifacts = self._run_pipeline(tmp_path)
        assert artifacts.detail.get("schema_version") == "1.0"

    def test_capture_sha256_matches_file(self, tmp_path: Path) -> None:
        import hashlib
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake pcap content")

        profile = load_profile("lte-core")
        runner = TSharkRunner()
        with mock_runner_two_pass(runner, [_make_raw_packet()]):
            artifacts = analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
            )

        expected = hashlib.sha256(b"fake pcap content").hexdigest()
        assert artifacts.summary["capture_sha256"] == expected

    def test_schema_version_persisted_to_disk(self, tmp_path: Path) -> None:
        artifacts = self._run_pipeline(tmp_path)
        outputs = write_artifacts(artifacts, tmp_path / "out2")
        summary = json.loads(outputs["summary"].read_text())
        detail = json.loads(outputs["detail"].read_text())
        assert summary["schema_version"] == "1.0"
        assert detail["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# CLI – exit codes
# ---------------------------------------------------------------------------

class TestCliExitCodes:
    runner = CliRunner()

    def test_analyze_nonexistent_file_exits_nonzero(self, tmp_path: Path) -> None:
        result = self.runner.invoke(app, ["analyze", str(tmp_path / "does_not_exist.pcap")])
        assert result.exit_code != 0

    def test_inspect_nonexistent_file_exits_nonzero(self, tmp_path: Path) -> None:
        result = self.runner.invoke(app, ["inspect", str(tmp_path / "does_not_exist.pcap")])
        assert result.exit_code != 0

    def test_dry_run_analyze_exits_zero(self, tmp_path: Path) -> None:
        capture = tmp_path / "sample.pcap"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            ["analyze", str(capture), "--profile", "lte-core", "--dry-run"],
        )
        assert result.exit_code == 0

    def test_dry_run_inspect_exits_zero(self, tmp_path: Path) -> None:
        capture = tmp_path / "sample.pcap"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            ["inspect", str(capture), "--profile", "lte-core", "--dry-run"],
        )
        assert result.exit_code == 0

    def test_analyze_tshark_error_exits_one(self, tmp_path: Path) -> None:
        from pcap2llm.tshark_runner import TSharkError

        capture = tmp_path / "sample.pcap"
        capture.write_bytes(b"fake")

        with patch("pcap2llm.cli.analyze_capture", side_effect=TSharkError("tshark failed")):
            result = self.runner.invoke(
                app,
                ["analyze", str(capture), "--profile", "lte-core"],
            )
        assert result.exit_code == 1

    def test_inspect_tshark_error_exits_one(self, tmp_path: Path) -> None:
        from pcap2llm.tshark_runner import TSharkError

        capture = tmp_path / "sample.pcap"
        capture.write_bytes(b"fake")

        with patch("pcap2llm.cli.inspect_capture", side_effect=TSharkError("tshark failed")):
            result = self.runner.invoke(
                app,
                ["inspect", str(capture), "--profile", "lte-core"],
            )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# CLI – privacy mode help texts
# ---------------------------------------------------------------------------

class TestPrivacyModeHelp:
    runner = CliRunner()

    def _help_text(self) -> str:
        result = self.runner.invoke(app, ["analyze", "--help"])
        # Rich/Typer may emit ANSI sequences in CI; strip them before matching.
        return re.sub(r"\x1b\[[0-9;]*m", "", result.output)

    def test_all_mode_options_in_help(self) -> None:
        help_text = self._help_text()
        # Typer may truncate long option names with "…", so we check only
        # an unambiguous prefix of each option name rather than the full string.
        expected_prefixes = [
            "--ip-mode",
            "--hostname-mode",
            "--imsi-mode",
            "--imei-mode",
            "--msisdn-mode",
            "--subscriber-id-m",   # --subscriber-id-mode
            "--email-mode",
            "--dn-mode",
            "--token-mode",
            "--uri-mode",
            "--apn-dnn-mode",
            "--diameter-identit",  # --diameter-identity-mode (may be truncated)
            "--payload-text-mode",
        ]
        for prefix in expected_prefixes:
            assert prefix in help_text, f"Expected '{prefix}' in analyze --help output"

    def test_mode_help_shows_valid_values(self) -> None:
        help_text = self._help_text()
        for keyword in ("keep", "mask", "pseudonymize", "encrypt", "remove"):
            assert keyword in help_text, f"Expected '{keyword}' in privacy mode help text"

    def test_mode_help_shows_aliases(self) -> None:
        help_text = self._help_text()
        assert "off" in help_text or "alias" in help_text, (
            "Privacy mode help should mention aliases (off=keep or redact=mask)"
        )


# ---------------------------------------------------------------------------
# --max-packets / --all-packets
# ---------------------------------------------------------------------------

class TestMaxPackets:
    runner = CliRunner()

    def _make_raw_packets(self, n: int) -> list[dict]:
        return [_make_raw_packet(number=str(i)) for i in range(1, n + 1)]

    def test_default_limits_to_1000(self, tmp_path: Path) -> None:
        from pcap2llm.pipeline import _DEFAULT_MAX_PACKETS
        assert _DEFAULT_MAX_PACKETS == 1000

    def test_truncation_when_over_limit(self, tmp_path: Path) -> None:
        from pcap2llm.pipeline import analyze_capture
        from pcap2llm.tshark_runner import TSharkRunner

        profile = load_profile("lte-core")
        runner = TSharkRunner()
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        raw = self._make_raw_packets(50)

        with mock_runner_two_pass(runner, raw):
            artifacts = analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=10,
            )

        assert len(artifacts.detail["selected_packets"]) == 10
        trunc = artifacts.summary.get("detail_truncated")
        assert trunc is not None
        assert trunc["included"] == 10
        assert trunc["total_exported"] == 50

    def test_no_truncation_when_under_limit(self, tmp_path: Path) -> None:
        from pcap2llm.pipeline import analyze_capture
        from pcap2llm.tshark_runner import TSharkRunner

        profile = load_profile("lte-core")
        runner = TSharkRunner()
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        raw = self._make_raw_packets(5)

        with mock_runner_two_pass(runner, raw):
            artifacts = analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=1000,
            )

        assert len(artifacts.detail["selected_packets"]) == 5
        assert "detail_truncated" not in artifacts.summary

    def test_all_packets_zero_means_unlimited(self, tmp_path: Path) -> None:
        from pcap2llm.pipeline import analyze_capture
        from pcap2llm.tshark_runner import TSharkRunner

        profile = load_profile("lte-core")
        runner = TSharkRunner()
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        raw = self._make_raw_packets(20)

        with mock_runner_two_pass(runner, raw):
            artifacts = analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=0,  # unlimited
            )

        assert len(artifacts.detail["selected_packets"]) == 20
        assert "detail_truncated" not in artifacts.summary

    def test_inspect_uses_full_packet_count_even_when_truncated(self, tmp_path: Path) -> None:
        """summary.json must reflect ALL packets, not just the truncated set."""
        from pcap2llm.pipeline import analyze_capture
        from pcap2llm.tshark_runner import TSharkRunner

        profile = load_profile("lte-core")
        runner = TSharkRunner()
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        raw = self._make_raw_packets(30)

        with mock_runner_two_pass(runner, raw):
            artifacts = analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=5,
            )

        # The summary should know about all 30 packets
        assert artifacts.summary["capture_metadata"]["packet_count"] == 30
        # But detail only has 5
        assert len(artifacts.detail["selected_packets"]) == 5

    def test_cli_all_packets_flag(self, tmp_path: Path) -> None:
        capture = tmp_path / "sample.pcap"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            ["analyze", str(capture), "--profile", "lte-core", "--all-packets", "--dry-run"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["max_packets"] == "unlimited"

    def test_cli_custom_max_packets(self, tmp_path: Path) -> None:
        capture = tmp_path / "sample.pcap"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            ["analyze", str(capture), "--profile", "lte-core", "--max-packets", "500", "--dry-run"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["max_packets"] == 500

    def test_cli_default_max_packets_in_dry_run(self, tmp_path: Path) -> None:
        capture = tmp_path / "sample.pcap"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            ["analyze", str(capture), "--profile", "lte-core", "--dry-run"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["max_packets"] == 1000
