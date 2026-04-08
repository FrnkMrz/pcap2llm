"""Tests for timing stats, burst detection, and anomaly classification in summarizer."""
from __future__ import annotations

import pytest

from pcap2llm.summarizer import (
    _classify_anomalies,
    _detect_bursts,
    _timing_stats,
    build_summary,
)
from pcap2llm.models import CaptureMetadata, InspectResult
from pcap2llm.profiles import load_profile


def _packets_with_times(times_ms: list[float]) -> list[dict]:
    return [{"top_protocol": "diameter", "time_rel_ms": t, "packet_no": i}
            for i, t in enumerate(times_ms)]


def _make_inspect_result(anomalies: list[str] | None = None) -> InspectResult:
    return InspectResult(
        metadata=CaptureMetadata(
            capture_file="x.pcapng",
            packet_count=10,
            relevant_protocols=["diameter"],
            raw_protocols=[],
        ),
        protocol_counts={"diameter": 10},
        transport_counts={"sctp": 10},
        conversations=[],
        anomalies=anomalies or [],
    )


# ---------------------------------------------------------------------------
# _timing_stats
# ---------------------------------------------------------------------------

class TestTimingStats:
    def test_returns_none_for_single_packet(self) -> None:
        assert _timing_stats(_packets_with_times([100.0])) is None

    def test_returns_none_for_empty_input(self) -> None:
        assert _timing_stats([]) is None

    def test_basic_stats(self) -> None:
        # Inter-packet gaps: 100, 100, 100 → min=max=mean=p95=100
        stats = _timing_stats(_packets_with_times([0.0, 100.0, 200.0, 300.0]))
        assert stats is not None
        assert stats["packet_count"] == 4
        assert stats["duration_ms"] == 300.0
        assert stats["inter_packet_ms"]["min"] == 100.0
        assert stats["inter_packet_ms"]["max"] == 100.0
        assert stats["inter_packet_ms"]["mean"] == 100.0

    def test_p95_reflects_high_latency_outlier(self) -> None:
        # 9 fast packets (gap 1ms) + 1 slow gap (1000ms)
        times = [float(i) for i in range(10)] + [1009.0]
        stats = _timing_stats(_packets_with_times(times))
        assert stats is not None
        assert stats["inter_packet_ms"]["max"] == pytest.approx(1000.0, abs=1.0)
        assert stats["inter_packet_ms"]["p95"] >= 1.0

    def test_ignores_packets_without_time(self) -> None:
        packets = [
            {"top_protocol": "diameter", "time_rel_ms": None, "packet_no": 0},
            {"top_protocol": "diameter", "time_rel_ms": 0.0, "packet_no": 1},
            {"top_protocol": "diameter", "time_rel_ms": 200.0, "packet_no": 2},
        ]
        stats = _timing_stats(packets)
        assert stats is not None
        assert stats["packet_count"] == 2


# ---------------------------------------------------------------------------
# _detect_bursts
# ---------------------------------------------------------------------------

class TestDetectBursts:
    def test_no_bursts_when_spread_out(self) -> None:
        times = [i * 5000.0 for i in range(10)]  # 5s apart
        bursts = _detect_bursts(_packets_with_times(times))
        assert bursts == []

    def test_detects_single_burst(self) -> None:
        # 10 packets in 500ms, then a gap, then 2 more
        times = [float(i * 50) for i in range(10)] + [10000.0, 10050.0]
        bursts = _detect_bursts(_packets_with_times(times))
        assert len(bursts) == 1
        assert bursts[0]["packet_count"] == 10

    def test_burst_must_meet_min_size(self) -> None:
        times = [0.0, 100.0, 200.0, 300.0]  # 4 packets — below default min_burst_size=5
        bursts = _detect_bursts(_packets_with_times(times))
        assert bursts == []

    def test_detects_multiple_bursts(self) -> None:
        burst1 = [float(i * 50) for i in range(8)]   # burst at ~0ms
        gap = [10000.0]
        burst2 = [10000.0 + i * 50 for i in range(1, 7)]  # burst at ~10s
        times = burst1 + gap + burst2
        bursts = _detect_bursts(_packets_with_times(times))
        assert len(bursts) == 2


# ---------------------------------------------------------------------------
# _classify_anomalies
# ---------------------------------------------------------------------------

class TestClassifyAnomalies:
    def test_classifies_tagged_anomalies(self) -> None:
        anomalies = [
            "[diameter][warn] Unanswered request at packet 3",
            "[diameter][error] Result-Code 5001 at packet 7",
            "[gtpv2][warn] Error Indication at packet 12",
        ]
        counts = _classify_anomalies(anomalies)
        assert counts["diameter"] == 2
        assert counts["gtpv2"] == 1

    def test_classifies_untagged_anomalies_as_transport(self) -> None:
        anomalies = ["Packet 3: retransmission"]
        counts = _classify_anomalies(anomalies)
        assert counts.get("transport", 0) == 1

    def test_empty_list(self) -> None:
        assert _classify_anomalies([]) == {}


# ---------------------------------------------------------------------------
# build_summary integration
# ---------------------------------------------------------------------------

class TestBuildSummaryExtended:
    def test_timing_stats_included_when_packets_have_times(self) -> None:
        profile = load_profile("lte-core")
        packets = _packets_with_times([0.0, 50.0, 100.0, 150.0])
        result = build_summary(_make_inspect_result(), packets, profile=profile, privacy_modes={})
        assert "timing_stats" in result
        assert result["timing_stats"]["packet_count"] == 4

    def test_burst_periods_included(self) -> None:
        profile = load_profile("lte-core")
        times = [float(i * 50) for i in range(10)]  # 10 packets in 500ms
        result = build_summary(
            _make_inspect_result(), _packets_with_times(times), profile=profile, privacy_modes={}
        )
        assert "burst_periods" in result
        assert result["burst_periods"][0]["packet_count"] == 10

    def test_anomaly_counts_by_layer_in_summary(self) -> None:
        profile = load_profile("lte-core")
        inspect = _make_inspect_result(anomalies=[
            "[diameter][warn] Unanswered at packet 1",
            "[gtpv2][error] Error at packet 2",
            "[gtpv2][warn] Another at packet 3",
        ])
        result = build_summary(inspect, [], profile=profile, privacy_modes={})
        assert result["anomaly_counts_by_layer"]["diameter"] == 1
        assert result["anomaly_counts_by_layer"]["gtpv2"] == 2

    def test_high_p95_delay_appears_in_notable_findings(self) -> None:
        profile = load_profile("lte-core")
        # 9 fast + 1 huge gap (> 500ms threshold)
        times = [float(i) for i in range(9)] + [2000.0]
        result = build_summary(
            _make_inspect_result(), _packets_with_times(times), profile=profile, privacy_modes={}
        )
        findings_text = " ".join(result["probable_notable_findings"])
        assert "p95" in findings_text or "delay" in findings_text
