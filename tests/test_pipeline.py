from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from pcap2llm.pipeline import analyze_capture, write_artifacts
from pcap2llm.profiles import load_profile
from pcap2llm.protector import ProtectionError, Protector
from pcap2llm.tshark_runner import TSharkError, TSharkRunner


_TIMESTAMP_PREFIX = "20240406_075320"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_raw_packet(
    *,
    number: str = "1",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
) -> dict:
    return {
        "_source": {
            "layers": {
                "frame.number": number,
                "frame.time_epoch": "1712390000.0",
                "frame.time_relative": "0.0",
                "frame.protocols": "eth:ip:sctp:diameter",
                "ip": {"ip.src": src_ip, "ip.dst": dst_ip},
                "sctp": {"sctp.srcport": "3868", "sctp.dstport": "3868", "sctp.assoc_index": "0"},
                "diameter": {"diameter.cmd.code": "316", "diameter.imsi": "001010123456789"},
            }
        }
    }


# ---------------------------------------------------------------------------
# TShark runner – JSON error handling
# ---------------------------------------------------------------------------

class TestTSharkRunnerJsonParsing:
    """Unit tests for TSharkRunner that mock both subprocess and ensure_available."""

    def _runner_with_mocked_output(self, stdout: str, returncode: int = 0, stderr: str = ""):
        """Return a (runner, mock_run) pair with ensure_available no-op'd."""
        runner = TSharkRunner()
        runner.ensure_available = lambda: None  # skip PATH check in tests
        mock_result = type("R", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()
        return runner, mock_result

    def test_malformed_json_raises_tsharkerror(self, tmp_path: Path) -> None:
        runner, mock_result = self._runner_with_mocked_output("not-json-at-all")
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(TSharkError, match="not valid JSON"):
                runner.export_packets(tmp_path / "sample.pcapng")

    def test_non_list_json_raises_tsharkerror(self, tmp_path: Path) -> None:
        runner, mock_result = self._runner_with_mocked_output('{"key": "value"}')
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(TSharkError, match="expected a list"):
                runner.export_packets(tmp_path / "sample.pcapng")

    def test_empty_stdout_returns_empty_list(self, tmp_path: Path) -> None:
        runner, mock_result = self._runner_with_mocked_output("")
        with patch("subprocess.run", return_value=mock_result):
            result = runner.export_packets(tmp_path / "sample.pcapng")
        assert result == []

    def test_nonzero_returncode_raises_tsharkerror(self, tmp_path: Path) -> None:
        runner, mock_result = self._runner_with_mocked_output(
            "", returncode=1, stderr="tshark: The file 'missing.pcap' doesn't exist."
        )
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(TSharkError):
                runner.export_packets(tmp_path / "sample.pcapng")


# ---------------------------------------------------------------------------
# Protector – vault key validation
# ---------------------------------------------------------------------------

class TestProtectorVaultKeyValidation:
    def test_valid_key_does_not_raise(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet
        monkeypatch.setenv("PCAP2LLM_VAULT_KEY", Fernet.generate_key().decode())
        protector = Protector({"ip": "encrypt"})
        protector.validate_vault_key()  # should not raise

    def test_invalid_key_raises_protection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pytest.importorskip("cryptography")
        monkeypatch.setenv("PCAP2LLM_VAULT_KEY", "this-is-not-a-valid-fernet-key")
        protector = Protector({"ip": "encrypt"})
        with pytest.raises(ProtectionError, match="not a valid Fernet key"):
            protector.validate_vault_key()

    def test_no_encrypt_mode_skips_validation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PCAP2LLM_VAULT_KEY", "invalid-but-irrelevant")
        protector = Protector({"ip": "mask"})
        protector.validate_vault_key()  # should not raise, encrypt mode not active

    def test_missing_cryptography_raises_protection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PCAP2LLM_VAULT_KEY", raising=False)
        protector = Protector({"ip": "encrypt"})
        # Hide cryptography even if installed
        with patch.dict("sys.modules", {"cryptography": None, "cryptography.fernet": None}):
            with pytest.raises(ProtectionError, match="cryptography"):
                protector.validate_vault_key()


# ---------------------------------------------------------------------------
# Normalizer – dropped packet counter
# ---------------------------------------------------------------------------

class TestNormalizerDroppedPackets:
    def test_malformed_packet_is_counted_as_dropped(self) -> None:
        from pcap2llm.normalizer import normalize_packets
        from pcap2llm.resolver import EndpointResolver

        profile = load_profile("lte-core")
        malformed = {"_source": None}  # will cause AttributeError in _layer_dict
        good = _make_raw_packet()

        packets, dropped = normalize_packets(
            [malformed, good],
            resolver=EndpointResolver(),
            profile=profile,
            privacy_modes={},
        )
        assert dropped == 1
        assert len(packets) == 1
        assert packets[0].packet_no == 1

    def test_all_valid_packets_zero_dropped(self) -> None:
        from pcap2llm.normalizer import normalize_packets
        from pcap2llm.resolver import EndpointResolver

        profile = load_profile("lte-core")
        raw = [_make_raw_packet(number=str(i)) for i in range(5)]
        packets, dropped = normalize_packets(
            raw,
            resolver=EndpointResolver(),
            profile=profile,
            privacy_modes={},
        )
        assert dropped == 0
        assert len(packets) == 5


# ---------------------------------------------------------------------------
# pipeline.write_artifacts – I/O error handling
# ---------------------------------------------------------------------------

class TestWriteArtifactsErrorHandling:
    def _make_artifacts(self) -> object:
        from pcap2llm.models import AnalyzeArtifacts
        return AnalyzeArtifacts(
            summary={
                "profile": "lte-core",
                "capture_metadata": {
                    "capture_file": "sample.pcapng",
                    "packet_count": 0,
                    "first_seen_epoch": "1712390000.0",
                    "last_seen_epoch": "1712390000.0",
                    "relevant_protocols": [],
                    "display_filter": None,
                },
                "anomalies": [],
                "privacy_modes": {},
                "packet_message_counts": {"top_protocols": {}, "transport": {}, "total_packets": 0},
                "probable_notable_findings": [],
            },
            detail={"profile": "lte-core", "selected_packets": []},
            markdown="# Test\n",
        )

    def test_write_artifacts_succeeds(self, tmp_path: Path) -> None:
        artifacts = self._make_artifacts()
        outputs = write_artifacts(artifacts, tmp_path / "out")
        assert (tmp_path / "out" / f"{_TIMESTAMP_PREFIX}_summary.json").exists()
        assert (tmp_path / "out" / f"{_TIMESTAMP_PREFIX}_detail.json").exists()
        assert (tmp_path / "out" / f"{_TIMESTAMP_PREFIX}_summary.md").exists()
        assert "summary" in outputs and "detail" in outputs

    def test_write_artifacts_adds_version_suffix_on_collision(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / f"{_TIMESTAMP_PREFIX}_summary.json").write_text("{}", encoding="utf-8")

        outputs = write_artifacts(self._make_artifacts(), out_dir)

        assert outputs["summary"].name == f"{_TIMESTAMP_PREFIX}_summary_V1.json"
        assert outputs["detail"].name == f"{_TIMESTAMP_PREFIX}_detail_V1.json"
        assert outputs["markdown"].name == f"{_TIMESTAMP_PREFIX}_summary_V1.md"

    def test_write_artifacts_updates_markdown_file_references(self, tmp_path: Path) -> None:
        outputs = write_artifacts(self._make_artifacts(), tmp_path / "out")

        markdown = outputs["markdown"].read_text(encoding="utf-8")
        assert f"{_TIMESTAMP_PREFIX}_summary.json" in markdown
        assert f"{_TIMESTAMP_PREFIX}_detail.json" in markdown

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not reliable on Windows")
    def test_write_artifacts_raises_on_read_only_dir(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "readonly"
        out_dir.mkdir()
        out_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)  # read + execute only
        try:
            artifacts = self._make_artifacts()
            with pytest.raises(RuntimeError, match="Failed to write artifacts"):
                write_artifacts(artifacts, out_dir)
        finally:
            out_dir.chmod(stat.S_IRWXU)  # restore so tmp_path cleanup works

    def test_write_artifacts_raises_on_invalid_parent(self, tmp_path: Path) -> None:
        # Point to a location under a file (not a directory) so mkdir fails
        blocker = tmp_path / "blocker"
        blocker.write_text("I am a file")
        with pytest.raises(RuntimeError, match="Cannot create output directory"):
            write_artifacts(self._make_artifacts(), blocker / "subdir")


# ---------------------------------------------------------------------------
# Full end-to-end pipeline (mocked tshark)
# ---------------------------------------------------------------------------

class TestAnalyzeCapturePipeline:
    def test_full_pipeline_produces_artifacts(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        raw_packets = [_make_raw_packet(number=str(i), src_ip=f"10.0.0.{i}") for i in range(1, 4)]

        with patch.object(runner, "export_packets", return_value=raw_packets):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes=profile.default_privacy_modes,
            )

        assert artifacts.summary["profile"] == "lte-core"
        assert artifacts.summary["capture_metadata"]["packet_count"] == 3
        assert isinstance(artifacts.detail["selected_packets"], list)
        assert "# PCAP2LLM Summary" in artifacts.markdown

    def test_full_pipeline_empty_capture(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()

        with patch.object(runner, "export_packets", return_value=[]):
            artifacts = analyze_capture(
                tmp_path / "empty.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
            )

        assert artifacts.summary["capture_metadata"]["packet_count"] == 0
        assert artifacts.detail["selected_packets"] == []

    def test_full_pipeline_dropped_packets_in_summary(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        malformed = {"_source": None}
        good = _make_raw_packet()

        with patch.object(runner, "export_packets", return_value=[malformed, good]):
            artifacts = analyze_capture(
                tmp_path / "mixed.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
            )

        assert artifacts.summary.get("dropped_packets") == 1

    def test_full_pipeline_write_and_read_back(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        raw_packets = [_make_raw_packet()]

        with patch.object(runner, "export_packets", return_value=raw_packets):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={"ip": "mask", "imsi": "pseudonymize"},
            )
        outputs = write_artifacts(artifacts, tmp_path / "out")

        summary = json.loads(outputs["summary"].read_text())
        assert summary["profile"] == "lte-core"
        assert summary["privacy_modes"]["ip"] == "mask"

        detail = json.loads(outputs["detail"].read_text())
        assert "selected_packets" in detail

    def test_invalid_vault_key_raises_before_processing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("cryptography")
        monkeypatch.setenv("PCAP2LLM_VAULT_KEY", "not-a-valid-key")
        profile = load_profile("lte-core")
        runner = TSharkRunner()

        with patch.object(runner, "export_packets", return_value=[_make_raw_packet()]):
            with pytest.raises(ProtectionError, match="not a valid Fernet key"):
                analyze_capture(
                    tmp_path / "sample.pcapng",
                    out_dir=tmp_path / "out",
                    runner=runner,
                    profile=profile,
                    privacy_modes={"ip": "encrypt"},
                )
