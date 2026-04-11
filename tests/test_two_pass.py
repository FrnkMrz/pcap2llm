"""Tests for the two-pass extraction architecture.

Covers:
- PacketIndexRecord / parse_index_row  (index_models)
- inspect_index_records / select_frame_numbers  (index_inspector)
- export_packet_index / export_selected_packets  (tshark_runner)
- end-to-end two-pass pipeline behavior  (pipeline)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from pcap2llm.index_models import INDEX_FIELDS, INDEX_SEPARATOR, PacketIndexRecord, parse_index_row
from pcap2llm.index_inspector import inspect_index_records, select_frame_numbers
from pcap2llm.models import InspectResult
from pcap2llm.pipeline import analyze_capture
from pcap2llm.profiles import load_profile
from pcap2llm.tshark_runner import TSharkRunner
from testutils import index_record_from_raw, mock_runner_two_pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tsv_row(
    *,
    frame_no: str = "1",
    time_epoch: str = "1712390000.0",
    protocols: str = "eth:ip:sctp:diameter",
    ip_src: str = "10.0.0.1",
    ip_dst: str = "10.0.0.2",
    ipv6_src: str = "",
    ipv6_dst: str = "",
    sctp_srcport: str = "3868",
    sctp_dstport: str = "3868",
    sctp_assoc: str = "0",
    tcp_srcport: str = "",
    tcp_dstport: str = "",
    tcp_stream: str = "",
    tcp_retr: str = "",
    tcp_ooo: str = "",
    udp_srcport: str = "",
    udp_dstport: str = "",
    udp_stream: str = "",
    diam_flags: str = "0x80",
    diam_cmd: str = "316",
    diam_hbh: str = "abc123",    # diameter.hop_by_hop_id  (older TShark)
    diam_hbhid: str = "",        # diameter.hopbyhopid     (TShark 4.x)
    diam_rc: str = "",           # diameter.Result-Code    (mixed-case primary)
    diam_rc_lc: str = "",        # diameter.result_code    (lowercase alt)
    diam_resultcode: str = "",   # diameter.resultcode     (no-separator alt)
    gtpv2_msgtype: str = "",
    gtpv2_seq: str = "",         # gtpv2.seq               (TShark 4.x primary)
    gtpv2_seqno: str = "",       # gtpv2.seq_no            (older builds)
    gtpv2_seqno_alt: str = "",   # gtpv2.sequence_number   (alt spelling)
    gtpv2_cause: str = "",
    dns_qry_name: str = "",      # dns.qry.name            (telecom naming detection)
) -> str:
    values = [
        frame_no, time_epoch, protocols,
        ip_src, ip_dst, ipv6_src, ipv6_dst,
        sctp_srcport, sctp_dstport, sctp_assoc,
        tcp_srcport, tcp_dstport, tcp_stream, tcp_retr, tcp_ooo,
        udp_srcport, udp_dstport, udp_stream,
        diam_flags, diam_cmd, diam_hbh, diam_hbhid,
        diam_rc, diam_rc_lc, diam_resultcode,
        gtpv2_msgtype, gtpv2_seq, gtpv2_seqno, gtpv2_seqno_alt, gtpv2_cause,
        dns_qry_name,
    ]
    assert len(values) == len(INDEX_FIELDS), (
        f"Row has {len(values)} columns, INDEX_FIELDS has {len(INDEX_FIELDS)}"
    )
    return INDEX_SEPARATOR.join(values)


def _make_raw_packet(
    *,
    number: str = "1",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    protocols: str = "eth:ip:sctp:diameter",
) -> dict:
    return {
        "_source": {
            "layers": {
                "frame.number": number,
                "frame.time_epoch": "1712390000.0",
                "frame.time_relative": "0.0",
                "frame.protocols": protocols,
                "ip": {"ip.src": src_ip, "ip.dst": dst_ip},
                "sctp": {"sctp.srcport": "3868", "sctp.dstport": "3868", "sctp.assoc_index": "0"},
                "diameter": {"diameter.cmd.code": "316", "diameter.imsi": "001010123456789"},
            }
        }
    }


# ---------------------------------------------------------------------------
# parse_index_row
# ---------------------------------------------------------------------------

class TestParseIndexRow:

    def test_basic_sctp_diameter_row(self) -> None:
        row = _make_tsv_row()
        record = parse_index_row(row)
        assert record is not None
        assert record.frame_no == 1
        assert record.time_epoch == "1712390000.0"
        assert "diameter" in record.protocols
        assert record.src_ip == "10.0.0.1"
        assert record.dst_ip == "10.0.0.2"
        assert record.transport == "sctp"
        assert record.src_port == 3868
        assert record.dst_port == 3868
        assert record.diameter_flags == "0x80"
        assert record.diameter_cmd_code == "316"
        assert record.diameter_hop_by_hop_id == "abc123"

    def test_ipv6_addresses_used_when_no_ipv4(self) -> None:
        row = _make_tsv_row(
            ip_src="", ip_dst="",
            ipv6_src="2001:db8::1", ipv6_dst="2001:db8::2",
        )
        record = parse_index_row(row)
        assert record is not None
        assert record.src_ip == "2001:db8::1"
        assert record.dst_ip == "2001:db8::2"

    def test_ipv4_preferred_over_ipv6(self) -> None:
        row = _make_tsv_row(
            ip_src="10.0.0.1",
            ipv6_src="2001:db8::1",
        )
        record = parse_index_row(row)
        assert record is not None
        assert record.src_ip == "10.0.0.1"

    def test_tcp_transport_parsed(self) -> None:
        row = _make_tsv_row(
            protocols="eth:ip:tcp:diameter",
            sctp_srcport="", sctp_dstport="", sctp_assoc="",
            tcp_srcport="12345", tcp_dstport="3868", tcp_stream="5",
            diam_flags="", diam_cmd="",
        )
        record = parse_index_row(row)
        assert record is not None
        assert record.transport == "tcp"
        assert record.src_port == 12345
        assert record.stream == "5"

    def test_udp_transport_parsed(self) -> None:
        row = _make_tsv_row(
            protocols="eth:ip:udp:dns",
            sctp_srcport="", sctp_dstport="", sctp_assoc="",
            tcp_srcport="", tcp_dstport="", tcp_stream="",
            udp_srcport="53000", udp_dstport="53", udp_stream="7",
            diam_flags="", diam_cmd="",
        )
        record = parse_index_row(row)
        assert record is not None
        assert record.transport == "udp"
        assert record.dst_port == 53
        assert record.stream == "7"

    def test_diameter_result_code_alt_spelling(self) -> None:
        """diameter.result_code (lowercase) must map to diameter_result_code."""
        row = _make_tsv_row(diam_rc="", diam_rc_lc="5005", diam_resultcode="")
        record = parse_index_row(row)
        assert record is not None
        assert record.diameter_result_code == "5005"

    def test_diameter_resultcode_alt_spelling(self) -> None:
        """diameter.resultcode must also map to diameter_result_code."""
        row = _make_tsv_row(diam_rc="", diam_rc_lc="", diam_resultcode="3001")
        record = parse_index_row(row)
        assert record is not None
        assert record.diameter_result_code == "3001"

    def test_diameter_result_primary_wins(self) -> None:
        """When multiple spellings are non-empty, the primary wins."""
        row = _make_tsv_row(diam_rc="2001", diam_rc_lc="5005", diam_resultcode="")
        record = parse_index_row(row)
        assert record is not None
        assert record.diameter_result_code == "2001"

    def test_gtpv2_seq_primary_spelling(self) -> None:
        """gtpv2.seq (TShark 4.x primary) must populate gtpv2_seq_no."""
        row = _make_tsv_row(
            protocols="eth:ip:udp:gtpv2",
            sctp_srcport="", sctp_dstport="", sctp_assoc="",
            diam_flags="", diam_cmd="",
            gtpv2_msgtype="32", gtpv2_seq="77",
        )
        record = parse_index_row(row)
        assert record is not None
        assert record.gtpv2_seq_no == "77"

    def test_gtpv2_sequence_number_alt_spelling(self) -> None:
        """gtpv2.sequence_number alt spelling must also populate gtpv2_seq_no."""
        row = _make_tsv_row(
            protocols="eth:ip:udp:gtpv2",
            sctp_srcport="", sctp_dstport="", sctp_assoc="",
            diam_flags="", diam_cmd="",
            gtpv2_msgtype="32", gtpv2_seqno_alt="99",
        )
        record = parse_index_row(row)
        assert record is not None
        assert record.gtpv2_seq_no == "99"

    def test_gtpv2_seq_primary_wins_over_alt(self) -> None:
        """When multiple spellings are present, gtpv2.seq wins."""
        row = _make_tsv_row(
            protocols="eth:ip:udp:gtpv2",
            sctp_srcport="", sctp_dstport="", sctp_assoc="",
            diam_flags="", diam_cmd="",
            gtpv2_msgtype="32", gtpv2_seq="55", gtpv2_seqno_alt="99",
        )
        record = parse_index_row(row)
        assert record is not None
        assert record.gtpv2_seq_no == "55"

    def test_tcp_retransmission_flag(self) -> None:
        row = _make_tsv_row(tcp_srcport="1234", tcp_dstport="5678", tcp_retr="1")
        record = parse_index_row(row)
        assert record is not None
        assert record.tcp_retransmission is True

    def test_malformed_frame_number_returns_none(self) -> None:
        row = _make_tsv_row(frame_no="not-a-number")
        assert parse_index_row(row) is None

    def test_too_few_columns_returns_none(self) -> None:
        assert parse_index_row("1|2|3") is None

    def test_empty_string_returns_none(self) -> None:
        assert parse_index_row("") is None


# ---------------------------------------------------------------------------
# inspect_index_records
# ---------------------------------------------------------------------------

class TestInspectIndexRecords:

    def _make_record(
        self,
        frame_no: int = 1,
        protocols: list[str] | None = None,
        src_ip: str = "10.0.0.1",
        dst_ip: str = "10.0.0.2",
        transport: str = "sctp",
        diameter_flags: str | None = None,
        diameter_cmd_code: str | None = None,
        diameter_hop_by_hop_id: str | None = None,
        diameter_result_code: str | None = None,
        gtpv2_message_type: str | None = None,
        gtpv2_seq_no: str | None = None,
        gtpv2_cause: str | None = None,
    ) -> PacketIndexRecord:
        return PacketIndexRecord(
            frame_no=frame_no,
            time_epoch="1712390000.0",
            protocols=protocols or ["eth", "ip", "sctp", "diameter"],
            src_ip=src_ip,
            dst_ip=dst_ip,
            transport=transport,
            src_port=3868,
            dst_port=3868,
            stream="0",
            tcp_retransmission=False,
            tcp_out_of_order=False,
            diameter_flags=diameter_flags,
            diameter_cmd_code=diameter_cmd_code,
            diameter_hop_by_hop_id=diameter_hop_by_hop_id,
            diameter_result_code=diameter_result_code,
            gtpv2_message_type=gtpv2_message_type,
            gtpv2_seq_no=gtpv2_seq_no,
            gtpv2_cause=gtpv2_cause,
        )

    def test_returns_inspect_result(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        records = [self._make_record()]
        result = inspect_index_records(
            records, capture_path=tmp_path / "x.pcapng",
            display_filter=None, profile=profile,
        )
        assert isinstance(result, InspectResult)

    def test_packet_count_matches_records(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        records = [self._make_record(frame_no=i) for i in range(1, 6)]
        result = inspect_index_records(
            records, capture_path=tmp_path / "x.pcapng",
            display_filter=None, profile=profile,
        )
        assert result.metadata.packet_count == 5

    def test_empty_records_produces_zero_counts(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        result = inspect_index_records(
            [], capture_path=tmp_path / "x.pcapng",
            display_filter=None, profile=profile,
        )
        assert result.metadata.packet_count == 0
        assert result.anomalies == []

    def test_diameter_anomaly_detected_from_index(self, tmp_path: Path) -> None:
        """Diameter error result codes must be detected from pass-1 records."""
        profile = load_profile("lte-core")
        records = [
            self._make_record(
                frame_no=10,
                diameter_cmd_code="318",
                diameter_result_code="5005",  # error
            )
        ]
        result = inspect_index_records(
            records, capture_path=tmp_path / "x.pcapng",
            display_filter=None, profile=profile,
        )
        assert any("diameter" in a and "5005" in a for a in result.anomalies), result.anomalies

    def test_gtpv2_unanswered_detected_from_index(self, tmp_path: Path) -> None:
        """Unanswered GTPv2 Create Session must be detected from pass-1 records."""
        profile = load_profile("lte-core")
        records = [
            PacketIndexRecord(
                frame_no=1,
                time_epoch="1712390000.0",
                protocols=["eth", "ip", "udp", "gtpv2"],
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                transport="udp",
                src_port=2123,
                dst_port=2123,
                stream=None,
                tcp_retransmission=False,
                tcp_out_of_order=False,
                diameter_flags=None,
                diameter_cmd_code=None,
                diameter_hop_by_hop_id=None,
                diameter_result_code=None,
                gtpv2_message_type="32",  # Create Session Request
                gtpv2_seq_no="42",
                gtpv2_cause=None,
            )
        ]
        result = inspect_index_records(
            records, capture_path=tmp_path / "x.pcapng",
            display_filter=None, profile=profile,
        )
        # Unanswered Create Session should appear
        assert any("gtpv2" in a and "42" in a for a in result.anomalies), result.anomalies

    def test_tcp_transport_anomaly_detected(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        records = [
            PacketIndexRecord(
                frame_no=3,
                time_epoch="1712390001.0",
                protocols=["eth", "ip", "tcp"],
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                transport="tcp",
                src_port=12345,
                dst_port=3868,
                stream="1",
                tcp_retransmission=True,
                tcp_out_of_order=False,
                diameter_flags=None,
                diameter_cmd_code=None,
                diameter_hop_by_hop_id=None,
                diameter_result_code=None,
                gtpv2_message_type=None,
                gtpv2_seq_no=None,
                gtpv2_cause=None,
            )
        ]
        result = inspect_index_records(
            records, capture_path=tmp_path / "x.pcapng",
            display_filter=None, profile=profile,
        )
        assert any("retransmission" in a for a in result.anomalies), result.anomalies

    def test_first_and_last_seen_set(self, tmp_path: Path) -> None:
        profile = load_profile("lte-core")
        r1 = self._make_record(frame_no=1)
        r2 = PacketIndexRecord(
            **{**r1.__dict__, "frame_no": 2, "time_epoch": "1712390010.0"}
        )
        result = inspect_index_records(
            [r1, r2], capture_path=tmp_path / "x.pcapng",
            display_filter=None, profile=profile,
        )
        assert result.metadata.first_seen_epoch == "1712390000.0"
        assert result.metadata.last_seen_epoch == "1712390010.0"


# ---------------------------------------------------------------------------
# select_frame_numbers
# ---------------------------------------------------------------------------

class TestSelectFrameNumbers:

    def _records(self, n: int) -> list[PacketIndexRecord]:
        return [
            PacketIndexRecord(
                frame_no=i,
                time_epoch="1712390000.0",
                protocols=["eth", "ip", "sctp", "diameter"],
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                transport="sctp", src_port=3868, dst_port=3868, stream="0",
                tcp_retransmission=False, tcp_out_of_order=False,
                diameter_flags=None, diameter_cmd_code=None,
                diameter_hop_by_hop_id=None, diameter_result_code=None,
                gtpv2_message_type=None, gtpv2_seq_no=None, gtpv2_cause=None,
            )
            for i in range(1, n + 1)
        ]

    def test_no_truncation_when_below_limit(self) -> None:
        records = self._records(5)
        result = select_frame_numbers(records, max_packets=1000)
        assert result.truncated is False
        assert result.total_exported == 5
        assert result.frame_numbers == [1, 2, 3, 4, 5]

    def test_truncation_when_above_limit(self) -> None:
        records = self._records(10)
        result = select_frame_numbers(records, max_packets=3)
        assert result.truncated is True
        assert result.total_exported == 10
        assert result.frame_numbers == [1, 2, 3]

    def test_unlimited_selects_all(self) -> None:
        records = self._records(5)
        result = select_frame_numbers(records, max_packets=0)
        assert result.truncated is False
        assert len(result.frame_numbers) == 5

    def test_exact_limit_not_truncated(self) -> None:
        records = self._records(3)
        result = select_frame_numbers(records, max_packets=3)
        assert result.truncated is False
        assert len(result.frame_numbers) == 3

    def test_truncation_note_present_when_truncated(self) -> None:
        records = self._records(5)
        result = select_frame_numbers(records, max_packets=2)
        assert result.truncation_note is not None
        assert "2" in result.truncation_note
        assert "5" in result.truncation_note


# ---------------------------------------------------------------------------
# TSharkRunner: export_packet_index (unit)
# ---------------------------------------------------------------------------

class TestExportPacketIndex:

    def _runner_with_output(self, stdout: str, returncode: int = 0):
        runner = TSharkRunner()
        runner.ensure_available = lambda: None
        mock_result = type("R", (), {"returncode": returncode, "stdout": stdout, "stderr": ""})()
        return runner, mock_result

    def test_parses_valid_tsv_output(self, tmp_path: Path) -> None:
        row = _make_tsv_row(frame_no="5", ip_src="192.168.1.1", ip_dst="10.0.0.1")
        runner, mock_result = self._runner_with_output(row + "\n")
        with patch("subprocess.run", return_value=mock_result):
            records = runner.export_packet_index(tmp_path / "x.pcapng")
        assert len(records) == 1
        assert records[0].frame_no == 5
        assert records[0].src_ip == "192.168.1.1"

    def test_empty_output_returns_empty_list(self, tmp_path: Path) -> None:
        runner, mock_result = self._runner_with_output("")
        with patch("subprocess.run", return_value=mock_result):
            records = runner.export_packet_index(tmp_path / "x.pcapng")
        assert records == []

    def test_nonzero_returncode_raises(self, tmp_path: Path) -> None:
        runner, mock_result = self._runner_with_output("", returncode=1)
        mock_result.stderr = "file not found"
        with patch("subprocess.run", return_value=mock_result):
            from pcap2llm.tshark_runner import TSharkError
            with pytest.raises(TSharkError):
                runner.export_packet_index(tmp_path / "x.pcapng")

    def test_malformed_rows_skipped(self, tmp_path: Path) -> None:
        good = _make_tsv_row(frame_no="1")
        bad = "not|enough|cols"
        runner, mock_result = self._runner_with_output(f"{good}\n{bad}\n")
        with patch("subprocess.run", return_value=mock_result):
            records = runner.export_packet_index(tmp_path / "x.pcapng")
        assert len(records) == 1

    def test_parse_invalid_fields_extracts_names(self) -> None:
        """_parse_invalid_fields must return all field names from TShark's error message."""
        stderr = (
            "tshark: Some fields aren't valid:\n"
            "\tgtpv2.seq_no\n"
            "\tdiameter.resultcode\n"
            "\tdiameter.result_code\n"
            "\tdiameter.hop_by_hop_id\n"
        )
        invalid = TSharkRunner._parse_invalid_fields(stderr)
        assert invalid == {"gtpv2.seq_no", "diameter.resultcode", "diameter.result_code", "diameter.hop_by_hop_id"}

    def test_parse_invalid_fields_empty_on_other_error(self) -> None:
        """_parse_invalid_fields must return empty set for unrelated errors."""
        assert TSharkRunner._parse_invalid_fields("tshark: file not found") == set()

    def test_export_packet_index_retries_on_invalid_fields(self, tmp_path: Path) -> None:
        """When TShark rejects field names, export_packet_index must retry without them."""
        from pcap2llm.index_models import INDEX_FIELDS

        runner = TSharkRunner()
        runner.ensure_available = lambda: None

        # Simulate: first call fails with "fields aren't valid"; second call succeeds
        # but with a reduced field set (drop gtpv2.seq_no + diameter.hop_by_hop_id)
        bad_result = type("R", (), {
            "returncode": 1,
            "stdout": "",
            "stderr": "tshark: Some fields aren't valid:\n\tgtpv2.seq_no\n\tdiameter.hop_by_hop_id\n",
        })()

        # Build a row for the reduced field set (without the two rejected fields)
        reduced_fields = tuple(f for f in INDEX_FIELDS if f not in {"gtpv2.seq_no", "diameter.hop_by_hop_id"})
        reduced_values = {f: "" for f in reduced_fields}
        reduced_values.update({
            "frame.number": "1",
            "frame.time_epoch": "1712390000.0",
            "frame.protocols": "eth:ip:sctp:diameter",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "sctp.srcport": "3868",
            "sctp.dstport": "3868",
            "sctp.assoc_index": "0",
            "diameter.flags": "0x80",
            "diameter.cmd.code": "316",
        })
        reduced_row = "|".join(reduced_values.get(f, "") for f in reduced_fields)
        good_result = type("R", (), {
            "returncode": 0,
            "stdout": reduced_row + "\n",
            "stderr": "",
        })()

        call_count = 0
        def mock_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            return bad_result if call_count == 1 else good_result

        with patch("subprocess.run", side_effect=mock_run):
            records = runner.export_packet_index(tmp_path / "x.pcapng")

        assert call_count == 2, "Should have retried exactly once"
        assert len(records) == 1
        assert records[0].frame_no == 1
        assert records[0].diameter_flags == "0x80"


# ---------------------------------------------------------------------------
# TSharkRunner: export_selected_packets (unit)
# ---------------------------------------------------------------------------

class TestExportSelectedPackets:

    def test_empty_frame_list_returns_empty_without_tshark(self, tmp_path: Path) -> None:
        runner = TSharkRunner()
        runner.ensure_available = lambda: None
        result = runner.export_selected_packets(tmp_path / "x.pcapng", frame_numbers=[])
        assert result == []

    def test_single_chunk_correct_filter(self, tmp_path: Path) -> None:
        """Filter string must use 'frame.number in {...}' syntax."""
        runner = TSharkRunner()
        runner.ensure_available = lambda: None
        cmd = runner.build_selected_export_command(tmp_path / "x.pcapng", frame_numbers=[1, 3, 5])
        filter_arg = cmd[cmd.index("-Y") + 1]
        assert "frame.number in {1,3,5}" == filter_arg

    def test_chunking_splits_large_frame_list(self, tmp_path: Path) -> None:
        """Frame lists > _FRAME_CHUNK_SIZE must be split into multiple TShark calls."""
        from pcap2llm.tshark_runner import _FRAME_CHUNK_SIZE
        runner = TSharkRunner()
        runner.ensure_available = lambda: None
        frames = list(range(1, _FRAME_CHUNK_SIZE + 51))  # CHUNK_SIZE + 50 extra

        call_count = 0
        def mock_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            return type("R", (), {"returncode": 0, "stdout": "[]", "stderr": ""})()

        with patch("subprocess.run", side_effect=mock_run):
            runner.export_selected_packets(tmp_path / "x.pcapng", frame_numbers=frames)

        assert call_count == 2  # two chunks

    def test_frame_number_filter_syntax_with_display_filter(self, tmp_path: Path) -> None:
        """Frame-number filter must not clobber an existing display filter.

        The runner builds a combined filter 'frame.number in {N,...}'
        (display_filter is not passed to export_selected_packets — it is
        already baked into the pass-1 selection).
        """
        runner = TSharkRunner()
        runner.ensure_available = lambda: None
        cmd = runner.build_selected_export_command(tmp_path / "x.pcapng", frame_numbers=[10, 20])
        # Must contain -Y with exactly the frame.number filter
        assert "-Y" in cmd
        filter_arg = cmd[cmd.index("-Y") + 1]
        assert filter_arg == "frame.number in {10,20}"
        # Must not contain any other -Y occurrence
        assert cmd.count("-Y") == 1


# ---------------------------------------------------------------------------
# End-to-end two-pass pipeline
# ---------------------------------------------------------------------------

class TestTwoPassPipeline:

    def test_bounded_non_truncated_uses_selected_frame_export(self, tmp_path: Path) -> None:
        """Bounded run (max_packets > 0), total ≤ max_packets: export_selected_packets
        must be called with all frame numbers, not export_packets."""
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        packets = [_make_raw_packet(number=str(i)) for i in range(1, 4)]  # 3 packets

        called_with_frames: list[int] = []

        def capture_frames(capture_path, *, frame_numbers, extra_args=None, two_pass=False):
            called_with_frames.extend(frame_numbers)
            fm = {int(p["_source"]["layers"]["frame.number"]): p for p in packets}
            return [fm[n] for n in frame_numbers if n in fm]

        with mock_runner_two_pass(runner, packets):
            with patch.object(runner, "export_selected_packets", side_effect=capture_frames):
                with patch.object(runner, "export_packets") as mock_full:
                    artifacts = analyze_capture(
                        tmp_path / "x.pcapng",
                        out_dir=tmp_path / "out",
                        runner=runner,
                        profile=profile,
                        privacy_modes={},
                        max_packets=1000,  # bounded but not truncated (3 < 1000)
                    )

        # Bounded runs always use selected-frame export — full export is not called
        mock_full.assert_not_called()
        assert called_with_frames == [1, 2, 3]
        assert artifacts.summary["coverage"]["detail_truncated"] is False
        assert artifacts.summary["coverage"]["detail_packets_included"] == 3

    def test_unlimited_uses_full_export_not_selected_frame(self, tmp_path: Path) -> None:
        """Unlimited run (max_packets=0): export_packets must be used, not
        export_selected_packets (avoids building a huge frame-number filter)."""
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        packets = [_make_raw_packet(number=str(i)) for i in range(1, 4)]

        with mock_runner_two_pass(runner, packets):
            with patch.object(runner, "export_selected_packets") as mock_selected:
                artifacts = analyze_capture(
                    tmp_path / "x.pcapng",
                    out_dir=tmp_path / "out",
                    runner=runner,
                    profile=profile,
                    privacy_modes={},
                    max_packets=0,  # unlimited → must use full export
                )
        mock_selected.assert_not_called()
        assert artifacts.summary["coverage"]["detail_truncated"] is False

    def test_truncated_uses_selected_frame_export(self, tmp_path: Path) -> None:
        """When truncated, export_selected_packets must be called with bounded frame list."""
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        packets = [_make_raw_packet(number=str(i)) for i in range(1, 6)]  # 5 packets

        called_with_frames: list[int] = []

        def mock_selected(capture_path, *, frame_numbers, extra_args=None, two_pass=False):
            called_with_frames.extend(frame_numbers)
            # Return only the first N matching packets
            fm = {int(p["_source"]["layers"]["frame.number"]): p for p in packets}
            return [fm[n] for n in frame_numbers if n in fm]

        with mock_runner_two_pass(runner, packets):
            with patch.object(runner, "export_selected_packets", side_effect=mock_selected):
                artifacts = analyze_capture(
                    tmp_path / "x.pcapng",
                    out_dir=tmp_path / "out",
                    runner=runner,
                    profile=profile,
                    privacy_modes={},
                    max_packets=2,  # only 2 of 5
                    oversize_factor=0,
                )

        assert called_with_frames == [1, 2]  # only frames 1 and 2 requested
        assert artifacts.summary["coverage"]["detail_packets_included"] == 2
        assert artifacts.summary["coverage"]["detail_packets_available"] == 5
        assert artifacts.summary["coverage"]["detail_truncated"] is True

    def test_coverage_always_reflects_full_pass1_count(self, tmp_path: Path) -> None:
        """detail_packets_available must come from pass-1 total, not pass-2 slice."""
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        packets = [_make_raw_packet(number=str(i)) for i in range(1, 11)]  # 10 packets

        with mock_runner_two_pass(runner, packets):
            artifacts = analyze_capture(
                tmp_path / "x.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=5,
                oversize_factor=0,
            )

        coverage = artifacts.summary["coverage"]
        assert coverage["detail_packets_available"] == 10
        assert coverage["detail_packets_included"] == 5
        assert coverage["summary_packet_count"] == 10

    def test_all_packets_mode(self, tmp_path: Path) -> None:
        """max_packets=0 must include all packets with truncated=False."""
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        packets = [_make_raw_packet(number=str(i)) for i in range(1, 6)]

        with mock_runner_two_pass(runner, packets):
            artifacts = analyze_capture(
                tmp_path / "x.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=0,  # unlimited
            )

        coverage = artifacts.summary["coverage"]
        assert coverage["detail_truncated"] is False
        assert coverage["detail_packets_included"] == 5
        assert coverage["detail_packets_available"] == 5

    def test_total_packets_is_capture_wide_even_when_truncated(self, tmp_path: Path) -> None:
        """summary.packet_message_counts.total_packets must come from pass-1 (capture-wide)
        and must NOT be the truncated detail count."""
        profile = load_profile("lte-core")
        runner = TSharkRunner()
        packets = [_make_raw_packet(number=str(i)) for i in range(1, 11)]  # 10 packets

        with mock_runner_two_pass(runner, packets):
            artifacts = analyze_capture(
                tmp_path / "x.pcapng",
                out_dir=tmp_path / "out",
                runner=runner,
                profile=profile,
                privacy_modes={},
                max_packets=3,   # only 3 in detail
                oversize_factor=0,
            )

        # Capture-wide total from pass 1 — must be 10, not 3
        total = artifacts.summary["packet_message_counts"]["total_packets"]
        assert total == 10, (
            f"total_packets should be capture-wide (10), got {total}. "
            "This field must come from pass-1 InspectResult, not from the detail slice."
        )

    def test_index_records_from_raw_roundtrip(self) -> None:
        """index_record_from_raw must produce records consistent with the packet."""
        pkt = _make_raw_packet(number="7", src_ip="192.168.1.100", dst_ip="10.0.0.1")
        record = index_record_from_raw(pkt)
        assert record.frame_no == 7
        assert record.src_ip == "192.168.1.100"
        assert record.dst_ip == "10.0.0.1"
        assert record.transport == "sctp"
        assert "diameter" in record.protocols
