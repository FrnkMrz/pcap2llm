from __future__ import annotations

from pcap2llm.models import NormalizedPacket, ProfileDefinition


def reduce_packets(packets: list[NormalizedPacket], profile: ProfileDefinition) -> list[dict]:
    reduced: list[dict] = []
    transport_keep = set(profile.reduced_transport_fields)
    for packet in packets:
        transport = {
            key: value
            for key, value in packet.transport.model_dump().items()
            if key in transport_keep and value not in (None, [], {})
        }
        reduced.append(
            {
                "packet_no": packet.packet_no,
                "time_rel_ms": packet.time_rel_ms,
                "time_epoch": packet.time_epoch,
                "top_protocol": packet.top_protocol,
                "frame_protocols": packet.frame_protocols,
                "src": packet.src.model_dump(exclude_none=True),
                "dst": packet.dst.model_dump(exclude_none=True),
                "transport": transport,
                "privacy": packet.privacy.model_dump(),
                "anomalies": packet.anomalies,
                "message": packet.message.model_dump(),
            }
        )
    return reduced
