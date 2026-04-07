"""Tests for application-layer anomaly detection."""
from __future__ import annotations

from pcap2llm.app_anomaly import detect_app_anomalies, _detect_diameter, _detect_gtpv2


def _diam_packet(
    *,
    number: str = "1",
    flags: str = "0x80",  # R-bit set = request
    cmd_code: str = "272",
    hbh: str = "0x00000001",
    result_code: str | None = None,
) -> dict:
    layers: dict = {
        "frame.number": number,
        "frame.time_epoch": "1712390000.0",
        "frame.protocols": "eth:ip:sctp:diameter",
        "diameter": {
            "diameter.flags": flags,
            "diameter.cmd.code": cmd_code,
            "diameter.hop_by_hop_id": hbh,
        },
    }
    if result_code is not None:
        layers["diameter"]["diameter.Result-Code"] = result_code
    return {"_source": {"layers": layers}}


def _gtp_packet(
    *,
    number: str = "1",
    msg_type: str = "32",  # Create Session Request
    seq_no: str = "100",
    cause: str | None = None,
) -> dict:
    layers: dict = {
        "frame.number": number,
        "frame.time_epoch": "1712390000.0",
        "frame.protocols": "eth:ip:udp:gtpv2",
        "gtpv2": {
            "gtpv2.message_type": msg_type,
            "gtpv2.seq_no": seq_no,
        },
    }
    if cause is not None:
        layers["gtpv2"]["gtpv2.cause"] = cause
    return {"_source": {"layers": layers}}


# ---------------------------------------------------------------------------
# Diameter tests
# ---------------------------------------------------------------------------

class TestDiameterAnomalies:
    def test_no_anomaly_for_matched_request_response(self) -> None:
        packets = [
            _diam_packet(number="1", flags="0x80", hbh="0x00000001"),   # request
            _diam_packet(number="2", flags="0x00", hbh="0x00000001", result_code="2001"),  # answer 2001 OK
        ]
        anomalies = _detect_diameter(packets)
        assert anomalies == []

    def test_detects_unanswered_request(self) -> None:
        packets = [
            _diam_packet(number="5", flags="0x80", hbh="0xdeadbeef"),
        ]
        anomalies = _detect_diameter(packets)
        assert len(anomalies) == 1
        assert "Unanswered" in anomalies[0]
        assert "0xdeadbeef" in anomalies[0]
        assert "5" in anomalies[0]

    def test_detects_error_result_code_3xxx(self) -> None:
        packets = [
            _diam_packet(number="1", flags="0x80", hbh="0x00000001"),
            _diam_packet(number="2", flags="0x00", hbh="0x00000001", result_code="3010"),
        ]
        anomalies = _detect_diameter(packets)
        assert any("3010" in a for a in anomalies)

    def test_detects_error_result_code_5xxx(self) -> None:
        packets = [
            _diam_packet(number="3", flags="0x80", hbh="0x00000002"),
            _diam_packet(number="4", flags="0x00", hbh="0x00000002", result_code="5001"),
        ]
        anomalies = _detect_diameter(packets)
        assert any("5001" in a and "[error]" in a for a in anomalies)

    def test_detects_duplicate_hop_by_hop_id(self) -> None:
        packets = [
            _diam_packet(number="1", flags="0x80", hbh="0x00000099"),
            _diam_packet(number="2", flags="0x80", hbh="0x00000099"),  # duplicate
        ]
        anomalies = _detect_diameter(packets)
        assert any("Duplicate" in a for a in anomalies)

    def test_no_anomaly_for_non_diameter_packet(self) -> None:
        non_diam = {
            "_source": {
                "layers": {
                    "frame.number": "1",
                    "frame.protocols": "eth:ip:tcp",
                    "tcp": {"tcp.srcport": "80"},
                }
            }
        }
        assert _detect_diameter([non_diam]) == []

    def test_malformed_packet_is_skipped_gracefully(self) -> None:
        malformed = {"_source": None}
        # Should not raise
        result = _detect_diameter([malformed])
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# GTPv2 tests
# ---------------------------------------------------------------------------

class TestGtpv2Anomalies:
    def test_no_anomaly_for_accepted_create_session(self) -> None:
        packets = [
            _gtp_packet(number="1", msg_type="32", seq_no="10"),   # CSR
            _gtp_packet(number="2", msg_type="33", seq_no="10", cause="16"),  # CSRsp accepted
        ]
        assert _detect_gtpv2(packets) == []

    def test_detects_unanswered_create_session(self) -> None:
        packets = [
            _gtp_packet(number="7", msg_type="32", seq_no="42"),
        ]
        anomalies = _detect_gtpv2(packets)
        assert len(anomalies) == 1
        assert "Unanswered" in anomalies[0]
        assert "42" in anomalies[0]

    def test_detects_rejected_create_session(self) -> None:
        packets = [
            _gtp_packet(number="1", msg_type="32", seq_no="5"),
            _gtp_packet(number="2", msg_type="33", seq_no="5", cause="73"),  # 73 = rejected
        ]
        anomalies = _detect_gtpv2(packets)
        assert any("73" in a for a in anomalies)

    def test_detects_error_indication(self) -> None:
        packets = [
            _gtp_packet(number="9", msg_type="26", seq_no="1"),  # Error Indication
        ]
        anomalies = _detect_gtpv2(packets)
        assert any("[error]" in a and "Error Indication" in a for a in anomalies)

    def test_no_anomaly_for_non_gtp_packet(self) -> None:
        non_gtp = {"_source": {"layers": {"frame.number": "1", "tcp": {}}}}
        assert _detect_gtpv2([non_gtp]) == []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TestDetectAppAnomalies:
    def test_returns_list_for_empty_input(self) -> None:
        assert detect_app_anomalies([], "lte-core") == []

    def test_runs_diameter_and_gtpv2_for_lte_core(self) -> None:
        packets = [_diam_packet(number="1", flags="0x80", hbh="0xaaa")]  # unanswered Diameter
        anomalies = detect_app_anomalies(packets, "lte-core")
        assert any("diameter" in a for a in anomalies)

    def test_skips_gtpv2_for_5g_core_profile(self) -> None:
        # GTPv2 detection should not run for 5g-core
        gtp_packets = [_gtp_packet(number="1", msg_type="32", seq_no="1")]
        anomalies = detect_app_anomalies(gtp_packets, "5g-core")
        assert not any("gtpv2" in a for a in anomalies)
