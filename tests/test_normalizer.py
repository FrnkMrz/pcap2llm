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
    packets = normalize_packets(
        _sample_packet(),
        resolver=EndpointResolver(mapping_file=mapping),
        profile=profile,
        privacy_modes=profile.default_privacy_modes,
    )
    assert packets[0].top_protocol == "diameter"
    assert packets[0].src.alias == "MME_FRA_A"
    assert packets[0].transport.proto == "sctp"
    assert packets[0].message.fields["diameter.cmd.code"] == "316"
