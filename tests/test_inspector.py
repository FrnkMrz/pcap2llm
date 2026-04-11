from __future__ import annotations

from pathlib import Path

from pcap2llm.normalizer import inspect_raw_packets
from pcap2llm.profiles import load_profile
from pcap2llm.resolver import EndpointResolver


def _make_packet(
    *,
    number: str = "1",
    protocols: str = "eth:ip:sctp:diameter",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    time_epoch: str = "1712390000.0",
    time_relative: str = "0.0",
    extra_layers: dict | None = None,
) -> dict:
    layers: dict = {
        "frame.number": number,
        "frame.time_epoch": time_epoch,
        "frame.time_relative": time_relative,
        "frame.protocols": protocols,
        "ip": {"ip.src": src_ip, "ip.dst": dst_ip},
        "sctp": {"sctp.srcport": "3868", "sctp.dstport": "3868", "sctp.assoc_index": "0"},
        "diameter": {"diameter.cmd.code": "272"},
    }
    if extra_layers:
        layers.update(extra_layers)
    return {"_source": {"layers": layers}}


def test_inspect_empty_packet_list(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    result = inspect_raw_packets(
        [],
        capture_path=tmp_path / "empty.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert result.metadata.packet_count == 0
    assert result.protocol_counts == {}
    assert result.conversations == []
    assert result.anomalies == []
    assert result.metadata.first_seen_epoch is None
    assert result.metadata.last_seen_epoch is None


def test_inspect_single_diameter_packet(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    result = inspect_raw_packets(
        [_make_packet()],
        capture_path=tmp_path / "sample.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert result.metadata.packet_count == 1
    assert result.protocol_counts.get("diameter") == 1
    assert result.transport_counts.get("sctp") == 1
    assert result.metadata.first_seen_epoch == "1712390000.0"
    assert result.metadata.last_seen_epoch == "1712390000.0"
    assert "diameter" in result.metadata.relevant_protocols


def test_inspect_multiple_packets_tracks_first_last_seen(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    packets = [
        _make_packet(number="1", time_epoch="1712390000.0"),
        _make_packet(number="2", time_epoch="1712390001.5"),
        _make_packet(number="3", time_epoch="1712390003.0"),
    ]
    result = inspect_raw_packets(
        packets,
        capture_path=tmp_path / "multi.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert result.metadata.packet_count == 3
    assert result.metadata.first_seen_epoch == "1712390000.0"
    assert result.metadata.last_seen_epoch == "1712390003.0"


def test_inspect_anomaly_detection(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    packet_with_retransmission = {
        "_source": {
            "layers": {
                "frame.number": "5",
                "frame.time_epoch": "1712390000.0",
                "frame.time_relative": "0.0",
                "frame.protocols": "eth:ip:tcp:http",
                "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
                "tcp": {
                    "tcp.srcport": "80",
                    "tcp.dstport": "12345",
                    "tcp.stream": "0",
                    "tcp.analysis.retransmission": "1",
                },
                "http": {"http.request.method": "GET"},
            }
        }
    }
    result = inspect_raw_packets(
        [packet_with_retransmission],
        capture_path=tmp_path / "retrans.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert len(result.anomalies) == 1
    assert "5" in result.anomalies[0]
    assert "retransmission" in result.anomalies[0]


def test_inspect_conversation_grouping(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    # Two packets same direction, one reverse
    packets = [
        _make_packet(number="1", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        _make_packet(number="2", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        _make_packet(number="3", src_ip="10.0.0.2", dst_ip="10.0.0.1"),
    ]
    result = inspect_raw_packets(
        packets,
        capture_path=tmp_path / "conv.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert result.metadata.packet_count == 3
    # Two distinct conversations
    assert len(result.conversations) == 2
    counts = {(c["src"], c["dst"]): c["packet_count"] for c in result.conversations}
    assert counts[("10.0.0.1", "10.0.0.2")] == 2
    assert counts[("10.0.0.2", "10.0.0.1")] == 1


def test_inspect_display_filter_stored_in_metadata(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    result = inspect_raw_packets(
        [],
        capture_path=tmp_path / "f.pcapng",
        display_filter="diameter",
        profile=profile,
    )
    assert result.metadata.display_filter == "diameter"


def test_inspect_adds_resolution_metadata_and_conversation_names(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(
        """
nodes:
  - ip: 10.0.0.1
    alias: MME_FRA_A
  - ip: 10.0.0.2
    alias: HSS_CORE_1
""".strip(),
        encoding="utf-8",
    )
    result = inspect_raw_packets(
        [_make_packet()],
        capture_path=tmp_path / "resolved.pcapng",
        display_filter=None,
        profile=profile,
        resolver=EndpointResolver(mapping_file=mapping),
        mapping_file_used=True,
    )

    assert result.metadata.mapping_file_used is True
    assert result.metadata.hosts_file_used is False
    mappings = {(item["ip"], item["name"]) for item in result.metadata.resolved_peers}
    assert mappings == {
        ("10.0.0.1", "MME_FRA_A"),
        ("10.0.0.2", "HSS_CORE_1"),
    }
    assert result.conversations[0]["src"] == "10.0.0.1"
    assert result.conversations[0]["dst"] == "10.0.0.2"
    assert result.conversations[0]["src_name"] == "MME_FRA_A"
    assert result.conversations[0]["dst_name"] == "HSS_CORE_1"


def test_inspect_malformed_packet_is_skipped(tmp_path: Path) -> None:
    """A packet with unexpected structure must not crash inspect_raw_packets."""
    profile = load_profile("lte-core")
    malformed = {"_source": None}  # None instead of dict – causes AttributeError
    good = _make_packet()
    result = inspect_raw_packets(
        [malformed, good],
        capture_path=tmp_path / "mixed.pcapng",
        display_filter=None,
        profile=profile,
    )
    # Only the well-formed packet is counted
    assert result.metadata.packet_count == 2  # raw count includes malformed
    assert result.protocol_counts.get("diameter") == 1  # only good packet contributed
