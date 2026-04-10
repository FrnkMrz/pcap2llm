from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from pcap2llm.pipeline import _artifact_timestamp_prefix, _check_oversize_ratio, analyze_capture, write_artifacts
from pcap2llm.profiles import load_profile
from pcap2llm.protector import ProtectionError, Protector
from pcap2llm.tshark_runner import TSharkError, TSharkRunner
from testutils import mock_runner_two_pass


_TIMESTAMP_PREFIX = "20240406_075320"


# ---------------------------------------------------------------------------
# _artifact_timestamp_prefix — TShark epoch format compatibility
# ---------------------------------------------------------------------------

def test_timestamp_prefix_from_unix_epoch_float() -> None:
    """Standard TShark (< 4.6) output: Unix epoch as decimal string."""
    assert _artifact_timestamp_prefix("1712390000.123456") == "20240406_075320"


def test_timestamp_prefix_from_iso8601_with_nanoseconds() -> None:
    """TShark >= 4.6 output: ISO 8601 with nanoseconds and Z suffix."""
    result = _artifact_timestamp_prefix("2025-10-14T10:44:16.046652117Z")
    assert result == "20251014_104416"


def test_timestamp_prefix_none_on_invalid_input() -> None:
    assert _artifact_timestamp_prefix(None) is None
    assert _artifact_timestamp_prefix("") is None
    assert _artifact_timestamp_prefix("not-a-date") is None


# ---------------------------------------------------------------------------
# _check_oversize_ratio
# ---------------------------------------------------------------------------

def test_oversize_ratio_passes_within_factor() -> None:
    """Should not raise when total is within the allowed factor."""
    _check_oversize_ratio(9_999, 1_000, oversize_factor=10.0)  # 9.999× — just under


def test_oversize_ratio_raises_at_threshold() -> None:
    """Should raise when total exceeds max_packets × factor."""
    with pytest.raises(RuntimeError, match="oversize"):
        _check_oversize_ratio(10_001, 1_000, oversize_factor=10.0)  # 10.001× — over


def test_oversize_ratio_raises_carries_packet_counts() -> None:
    """Error message must include exported count, limit, and bypass hint."""
    with pytest.raises(RuntimeError, match="47,312") as exc_info:
        _check_oversize_ratio(47_312, 1_000, oversize_factor=10.0)
    msg = str(exc_info.value)
    assert "1,000" in msg
    assert "--oversize-factor 0" in msg


def test_oversize_ratio_disabled_at_zero() -> None:
    """oversize_factor=0 must never raise, regardless of ratio."""
    _check_oversize_ratio(1_000_000, 1_000, oversize_factor=0)


def test_oversize_ratio_disabled_when_max_packets_zero() -> None:
    """Unlimited mode (max_packets=0) must not trigger the guard."""
    _check_oversize_ratio(1_000_000, 0, oversize_factor=10.0)


def test_oversize_ratio_pipeline_integration(tmp_path: Path) -> None:
    """Pipeline must raise RuntimeError before normalization when ratio is exceeded."""
    from pcap2llm.profiles import load_profile
    from pcap2llm.tshark_runner import TSharkRunner

    profile = load_profile("lte-core")
    runner = TSharkRunner()
    packets = [_make_raw_packet(number=str(i)) for i in range(1, 12)]  # 11 packets

    with mock_runner_two_pass(runner, packets):
        with pytest.raises(RuntimeError, match="oversize"):
            analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=1,      # limit 1
                oversize_factor=10.0,  # 11 > 1×10 → should fire
            )


def test_oversize_ratio_bypassed_in_pipeline(tmp_path: Path) -> None:
    """Setting oversize_factor=0 must allow the pipeline to continue past the guard."""
    from pcap2llm.profiles import load_profile
    from pcap2llm.tshark_runner import TSharkRunner

    profile = load_profile("lte-core")
    runner = TSharkRunner()
    packets = [_make_raw_packet(number=str(i)) for i in range(1, 12)]  # 11 packets

    with mock_runner_two_pass(runner, packets):
        # Should not raise — oversize guard is disabled
        artifacts = analyze_capture(
            tmp_path / "sample.pcapng",
            out_dir=tmp_path / "out",
            runner=runner,
            profile=profile,
            privacy_modes={},
            max_packets=1,
            oversize_factor=0,  # guard disabled
        )
    assert artifacts.summary["coverage"]["detail_packets_available"] == 11


def test_early_raw_packet_release_produces_correct_artifacts(tmp_path: Path) -> None:
    """Pipeline must produce correct artifacts after raw_packets is released post-selection.

    raw_packets is now explicitly deleted after _select_packets() so the full
    TShark export does not stay in memory during normalization/protection.
    This test confirms the pipeline produces correct coverage metadata and
    detail content after that change — i.e. no data loss from early release.
    """
    from pcap2llm.profiles import load_profile
    from pcap2llm.tshark_runner import TSharkRunner

    profile = load_profile("lte-core")
    runner = TSharkRunner()
    # 5-packet export, capped at 3 — raw_packets (5 items) is released after
    # selection; normalization runs only on the 3-packet slice.
    packets = [_make_raw_packet(number=str(i)) for i in range(1, 6)]

    with mock_runner_two_pass(runner, packets):
        artifacts = analyze_capture(
            tmp_path / "sample.pcapng",
            out_dir=tmp_path / "out",
            runner=runner,
            profile=profile,
            privacy_modes={},
            max_packets=3,
            oversize_factor=0,  # disable guard — we want to test selection+release
        )

    coverage = artifacts.summary["coverage"]
    assert coverage["detail_packets_included"] == 3
    assert coverage["detail_packets_available"] == 5
    assert coverage["detail_truncated"] is True
    assert len(artifacts.detail["selected_packets"]) == 3


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
                "schema_version": "1.0",
                "generated_at": "<generated_at>",
                "capture_sha256": "<capture_sha256>",
                "profile": "lte-core",
                "artifact_role": "summary_sidecar",
                "capture_metadata": {
                    "capture_file": "sample.pcapng",
                    "packet_count": 0,
                    "first_seen_epoch": "1712390000.0",
                    "last_seen_epoch": "1712390000.0",
                    "relevant_protocols": [],
                    "display_filter": None,
                },
                "relevant_protocols": [],
                "anomalies": [],
                "anomaly_counts_by_layer": {},
                "privacy_modes": {},
                "privacy_policy": {},
                "coverage": {
                    "detail_packets_included": 0,
                    "detail_packets_available": 0,
                    "detail_truncated": False,
                    "summary_packet_count": 0,
                    "truncation_note": None,
                },
                "packet_message_counts": {"top_protocols": {}, "transport": {}, "total_packets": 0},
                "conversations": [],
                "deterministic_findings": [],
                "probable_notable_findings": [],
            },
            detail={
                "schema_version": "1.0",
                "generated_at": "<generated_at>",
                "capture_sha256": "<capture_sha256>",
                "profile": "lte-core",
                "artifact_role": "llm_input",
                "coverage": {
                    "detail_packets_included": 0,
                    "detail_packets_available": 0,
                    "detail_truncated": False,
                    "summary_packet_count": 0,
                    "truncation_note": None,
                },
                "messages": [],
                "selected_packets": [],
            },
            markdown="# Test\n",
        )

    def test_write_artifacts_succeeds(self, tmp_path: Path) -> None:
        artifacts = self._make_artifacts()
        outputs = write_artifacts(artifacts, tmp_path / "out")
        assert (tmp_path / "out" / f"{_TIMESTAMP_PREFIX}_summary_V_01.json").exists()
        assert (tmp_path / "out" / f"{_TIMESTAMP_PREFIX}_detail_V_01.json").exists()
        assert (tmp_path / "out" / f"{_TIMESTAMP_PREFIX}_summary_V_01.md").exists()
        assert "summary" in outputs and "detail" in outputs

    def test_write_artifacts_adds_version_suffix_on_collision(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / f"{_TIMESTAMP_PREFIX}_summary_V_01.json").write_text("{}", encoding="utf-8")

        outputs = write_artifacts(self._make_artifacts(), out_dir)

        assert outputs["summary"].name == f"{_TIMESTAMP_PREFIX}_summary_V_02.json"
        assert outputs["detail"].name == f"{_TIMESTAMP_PREFIX}_detail_V_02.json"
        assert outputs["markdown"].name == f"{_TIMESTAMP_PREFIX}_summary_V_02.md"

    def test_write_artifacts_updates_markdown_file_references(self, tmp_path: Path) -> None:
        outputs = write_artifacts(self._make_artifacts(), tmp_path / "out")

        markdown = outputs["markdown"].read_text(encoding="utf-8")
        assert f"{_TIMESTAMP_PREFIX}_summary_V_01.json" in markdown
        assert f"{_TIMESTAMP_PREFIX}_detail_V_01.json" in markdown

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

        with mock_runner_two_pass(runner, raw_packets):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes=profile.default_privacy_modes,
            )

        assert artifacts.summary["profile"] == "lte-core"
        assert artifacts.summary["capture_metadata"]["packet_count"] == 3
        assert isinstance(artifacts.detail["messages"], list)
        assert "# PCAP2LLM Artifact Summary" in artifacts.markdown

    def test_full_pipeline_empty_capture(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()

        with mock_runner_two_pass(runner, []):
            artifacts = analyze_capture(
                tmp_path / "empty.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
            )

        assert artifacts.summary["capture_metadata"]["packet_count"] == 0
        assert artifacts.detail["selected_packets"] == []

    def test_fail_fast_on_large_capture_size(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        capture = tmp_path / "large_sample.pcapng"
        capture.write_bytes(b"x" * (2 * 1024 * 1024))

        with pytest.raises(RuntimeError, match="max-capture-size-mb"):
            analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_capture_size_mb=1,
            )

    def test_full_pipeline_dropped_packets_in_summary(self, tmp_path: Path) -> None:
        """When normalize_packets drops a packet, summary must record dropped_packets.

        The two-pass architecture selects packets by frame number before passing
        them to the normalizer.  We mock normalize_packets directly to simulate
        a drop, testing the pipeline's handling of the drop count rather than
        the normalizer's own malformed-packet logic.
        """
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        packets = [_make_raw_packet()]

        with mock_runner_two_pass(runner, packets):
            with patch(
                "pcap2llm.pipeline.normalize_packets",
                return_value=([], 1),  # 0 normalized, 1 dropped
            ):
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

        with mock_runner_two_pass(runner, raw_packets):
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

    def test_pseudonymization_run_generates_mapping_sidecar_and_markdown_reference(
        self, tmp_path: Path
    ) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        raw_packets = [_make_raw_packet()]

        with mock_runner_two_pass(runner, raw_packets):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={"imsi": "pseudonymize"},
            )
        outputs = write_artifacts(artifacts, tmp_path / "out")

        assert "mapping" in outputs
        assert outputs["mapping"].exists()
        markdown = outputs["markdown"].read_text(encoding="utf-8")
        assert outputs["mapping"].name in markdown

    def test_non_pseudonymization_run_omits_mapping_sidecar(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()

        with mock_runner_two_pass(runner, [_make_raw_packet()]):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
            )
        outputs = write_artifacts(artifacts, tmp_path / "out")
        assert "mapping" not in outputs
        markdown = outputs["markdown"].read_text(encoding="utf-8")
        assert "pseudonym_mapping" not in markdown

    def test_encrypted_run_generates_vault_sidecar_and_markdown_reference(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("cryptography")
        from cryptography.fernet import Fernet

        monkeypatch.setenv("PCAP2LLM_VAULT_KEY", Fernet.generate_key().decode())
        profile = load_profile("lte-core")
        runner = TSharkRunner()

        with mock_runner_two_pass(runner, [_make_raw_packet()]):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={"imsi": "encrypt"},
            )
        outputs = write_artifacts(artifacts, tmp_path / "out")
        assert "vault" in outputs
        assert outputs["vault"].exists()
        markdown = outputs["markdown"].read_text(encoding="utf-8")
        assert outputs["vault"].name in markdown
        vault = json.loads(outputs["vault"].read_text(encoding="utf-8"))
        assert "PCAP2LLM_VAULT_KEY" in vault["key_source"]
        assert os.environ["PCAP2LLM_VAULT_KEY"] not in json.dumps(vault)

    def test_non_encrypted_run_omits_vault_sidecar(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()

        with mock_runner_two_pass(runner, [_make_raw_packet()]):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
            )
        outputs = write_artifacts(artifacts, tmp_path / "out")
        assert "vault" not in outputs
        markdown = outputs["markdown"].read_text(encoding="utf-8")
        assert "vault.json" not in markdown

    def test_disabling_capture_size_guard_allows_intentional_large_input(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        capture = tmp_path / "large_sample.pcapng"
        capture.write_bytes(b"x" * (2 * 1024 * 1024))

        with mock_runner_two_pass(runner, [_make_raw_packet()]):
            artifacts = analyze_capture(
                capture,
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_capture_size_mb=0,
            )
        assert artifacts.summary["capture_metadata"]["packet_count"] == 1

    def test_all_packets_mode_preserves_full_detail_without_truncation(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        raw_packets = [_make_raw_packet(number=str(i)) for i in range(1, 4)]

        with mock_runner_two_pass(runner, raw_packets):
            artifacts = analyze_capture(
                tmp_path / "sample.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=0,
            )
        assert len(artifacts.detail["messages"]) == 3
        assert artifacts.summary["coverage"]["detail_truncated"] is False

    def test_invalid_vault_key_raises_before_processing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("cryptography")
        monkeypatch.setenv("PCAP2LLM_VAULT_KEY", "not-a-valid-key")
        profile = load_profile("lte-core")
        runner = TSharkRunner()

        with mock_runner_two_pass(runner, [_make_raw_packet()]):
            with pytest.raises(ProtectionError, match="not a valid Fernet key"):
                analyze_capture(
                    tmp_path / "sample.pcapng",
                    out_dir=tmp_path / "out",
                    runner=runner,
                    profile=profile,
                    privacy_modes={"ip": "encrypt"},
                )
