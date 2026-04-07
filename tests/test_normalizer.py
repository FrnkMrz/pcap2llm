from pathlib import Path

from pcap2llm.normalizer import inspect_raw_packets, normalize_packets
from pcap2llm.profiles import load_profile
from pcap2llm.resolver import EndpointResolver


def _sample_packet() -> list[dict]:
    return [
        {
            "_source": {
                "layers": {
                    "frame.number": "7",
                    "frame.time_epoch": "1712390000.10",
                    "frame.time_relative": "0.321",
                    "frame.protocols": "eth:ip:sctp:diameter",
                    "ip": {"ip.src": "10.10.1.11", "ip.dst": "10.20.8.44"},
                    "sctp": {
                        "sctp.srcport": "3868",
                        "sctp.dstport": "3868",
                        "sctp.assoc_index": "3",
                        "sctp.stream_identifier": "1",
                    },
                    "diameter": {
                        "diameter.cmd.code": "316",
                        "diameter.applicationid": "16777251",
                        "diameter.origin_host": "mme.example.net",
                        "diameter.destination_host": "hss.example.net",
                        "diameter.imsi": "001010123456789",
                    },
                }
            }
        }
    ]


def _sample_5g_packet() -> list[dict]:
    return [
        {
            "_source": {
                "layers": {
                    "frame.number": "11",
                    "frame.time_epoch": "1712391000.20",
                    "frame.time_relative": "1.234",
                    "frame.protocols": "eth:ip:udp:pfcp",
                    "ip": {"ip.src": "10.30.1.10", "ip.dst": "10.40.2.20"},
                    "udp": {
                        "udp.srcport": "8805",
                        "udp.dstport": "8805",
                        "udp.stream": "4",
                    },
                    "pfcp": {
                        "pfcp.message_type": "50",
                        "pfcp.seid": "0x0000000000001001",
                        "pfcp.node_id": "upf.example.net",
                    },
                }
            }
        }
    ]


def _sample_2g3g_packet() -> list[dict]:
    return [
        {
            "_source": {
                "layers": {
                    "frame.number": "19",
                    "frame.time_epoch": "1712392000.30",
                    "frame.time_relative": "2.468",
                    "frame.protocols": "eth:ip:sctp:m3ua:sccp:tcap:gsm_map",
                    "ip": {"ip.src": "10.50.1.10", "ip.dst": "10.60.2.20"},
                    "sctp": {
                        "sctp.srcport": "2905",
                        "sctp.dstport": "2905",
                        "sctp.assoc_index": "7",
                        "sctp.stream_identifier": "2",
                    },
                    "m3ua": {
                        "m3ua.message_class": "1",
                        "m3ua.message_type": "1",
                    },
                    "sccp": {
                        "sccp.message_type": "9",
                        "sccp.called.digits": "491700000001",
                    },
                    "tcap": {
                        "tcap.tid": "0x1234",
                    },
                    "gsm_map": {
                        "gsm_map.localValue": "2",
                        "e212.imsi": "262011234567890",
                        "e164.msisdn": "491700000001",
                    },
                }
            }
        }
    ]


def test_inspect_and_normalize_sample_packet(tmp_path: Path) -> None:
    profile = load_profile("lte-core")
    inspect_result = inspect_raw_packets(
        _sample_packet(),
        capture_path=tmp_path / "sample.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert inspect_result.metadata.packet_count == 1
    assert inspect_result.protocol_counts["diameter"] == 1

    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(
        """
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
  - ip: 10.20.8.44
    alias: HSS_CORE_1
    role: hss
""".strip(),
        encoding="utf-8",
    )
    packets, dropped = normalize_packets(
        _sample_packet(),
        resolver=EndpointResolver(mapping_file=mapping),
        profile=profile,
        privacy_modes=profile.default_privacy_modes,
    )
    assert dropped == 0
    assert packets[0].top_protocol == "diameter"
    assert packets[0].src.alias == "MME_FRA_A"
    assert packets[0].transport.proto == "sctp"
    assert packets[0].message.fields["diameter.cmd.code"] == "316"


def test_inspect_and_normalize_5g_packet(tmp_path: Path) -> None:
    profile = load_profile("5g-core")
    inspect_result = inspect_raw_packets(
        _sample_5g_packet(),
        capture_path=tmp_path / "sample-5g.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert inspect_result.metadata.packet_count == 1
    assert inspect_result.protocol_counts["pfcp"] == 1

    mapping = tmp_path / "mapping-5g.yaml"
    mapping.write_text(
        """
nodes:
  - ip: 10.30.1.10
    alias: SMF_CORE_1
    role: smf
  - ip: 10.40.2.20
    alias: UPF_EDGE_1
    role: upf
""".strip(),
        encoding="utf-8",
    )
    packets, dropped = normalize_packets(
        _sample_5g_packet(),
        resolver=EndpointResolver(mapping_file=mapping),
        profile=profile,
        privacy_modes=profile.default_privacy_modes,
    )
    assert dropped == 0
    assert packets[0].top_protocol == "pfcp"
    assert packets[0].src.alias == "SMF_CORE_1"
    assert packets[0].transport.proto == "udp"
    assert packets[0].message.fields["pfcp.message_type"] == "50"


def test_inspect_and_normalize_2g3g_packet(tmp_path: Path) -> None:
    profile = load_profile("2g3g-ss7-geran")
    inspect_result = inspect_raw_packets(
        _sample_2g3g_packet(),
        capture_path=tmp_path / "sample-2g3g.pcapng",
        display_filter=None,
        profile=profile,
    )
    assert inspect_result.metadata.packet_count == 1
    assert inspect_result.protocol_counts["map"] == 1

    mapping = tmp_path / "mapping-2g3g.yaml"
    mapping.write_text(
        """
nodes:
  - ip: 10.50.1.10
    alias: MSC_LEGACY_1
    role: msc
  - ip: 10.60.2.20
    alias: HLR_CORE_1
    role: hlr
""".strip(),
        encoding="utf-8",
    )
    packets, dropped = normalize_packets(
        _sample_2g3g_packet(),
        resolver=EndpointResolver(mapping_file=mapping),
        profile=profile,
        privacy_modes=profile.default_privacy_modes,
    )
    assert dropped == 0
    assert packets[0].top_protocol == "map"
    assert packets[0].src.alias == "MSC_LEGACY_1"
    assert packets[0].transport.proto == "sctp"
    assert packets[0].message.fields["gsm_map.localValue"] == "2"
