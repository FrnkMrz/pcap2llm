from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from pcap2llm.models import CaptureMetadata, InspectResult, MessageContext, NormalizedPacket
from pcap2llm.models import PrivacySummary, ProfileDefinition, TransportContext
from pcap2llm.resolver import EndpointResolver


def _flatten(value: Any) -> Any:
    if isinstance(value, list):
        if len(value) == 1:
            return _flatten(value[0])
        return [_flatten(item) for item in value]
    if isinstance(value, dict):
        return {key: _flatten(item) for key, item in value.items()}
    return value


def _layer_dict(packet: dict[str, Any]) -> dict[str, Any]:
    return packet.get("_source", {}).get("layers", {})


def _field(layers: dict[str, Any], key: str) -> Any:
    value = layers.get(key)
    if value is None and "." in key:
        layer_name = key.split(".", 1)[0]
        nested = layers.get(layer_name)
        if isinstance(nested, dict):
            value = nested.get(key)
    return _flatten(value)


def _maybe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _maybe_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _frame_protocols(layers: dict[str, Any]) -> list[str]:
    value = _field(layers, "frame.protocols")
    if isinstance(value, str):
        return [part for part in value.split(":") if part]
    return []


def _candidate_layers(profile: ProfileDefinition, protocol: str) -> list[str]:
    return profile.protocol_aliases.get(protocol, [protocol])


def pick_top_protocol(layers: dict[str, Any], profile: ProfileDefinition) -> str:
    frame_protocols = set(_frame_protocols(layers))
    layer_names = set(layers.keys())
    for protocol in profile.top_protocol_priority:
        for candidate in _candidate_layers(profile, protocol):
            if candidate in frame_protocols or candidate in layer_names:
                return protocol
    for fallback in ("sctp", "tcp", "udp", "ip", "ipv6"):
        if fallback in frame_protocols or fallback in layer_names:
            return "ip" if fallback == "ipv6" else fallback
    return "unknown"


def _extract_ip_pair(layers: dict[str, Any]) -> tuple[str | None, str | None]:
    if "ip" in layers:
        return _field(layers, "ip.src"), _field(layers, "ip.dst")
    if "ipv6" in layers:
        return _field(layers, "ipv6.src"), _field(layers, "ipv6.dst")
    return None, None


def _extract_transport(layers: dict[str, Any]) -> TransportContext:
    if "sctp" in layers:
        notes = []
        if _field(layers, "sctp.chunk_type") is not None:
            notes.append(f"chunks={_field(layers, 'sctp.chunk_type')}")
        anomaly = "tcp.analysis" in layers or "sctp.analysis" in layers
        return TransportContext(
            proto="sctp",
            src_port=_maybe_int(_field(layers, "sctp.srcport")),
            dst_port=_maybe_int(_field(layers, "sctp.dstport")),
            stream=_field(layers, "sctp.assoc_index"),
            sctp_stream=_field(layers, "sctp.stream_identifier"),
            anomaly=anomaly,
            notes=notes,
        )
    if "tcp" in layers:
        notes = []
        if _field(layers, "tcp.analysis.retransmission"):
            notes.append("retransmission")
        if _field(layers, "tcp.analysis.out_of_order"):
            notes.append("out_of_order")
        return TransportContext(
            proto="tcp",
            src_port=_maybe_int(_field(layers, "tcp.srcport")),
            dst_port=_maybe_int(_field(layers, "tcp.dstport")),
            stream=_field(layers, "tcp.stream"),
            anomaly=bool(notes),
            notes=notes,
        )
    if "udp" in layers:
        return TransportContext(
            proto="udp",
            src_port=_maybe_int(_field(layers, "udp.srcport")),
            dst_port=_maybe_int(_field(layers, "udp.dstport")),
            stream=_field(layers, "udp.stream"),
        )
    return TransportContext(proto="ip")


def _retain_message_fields(
    layers: dict[str, Any], profile: ProfileDefinition, top_protocol: str
) -> dict[str, Any]:
    retained: dict[str, Any] = {}
    allowed = profile.full_detail_fields.get(top_protocol, [])
    for field_name in allowed:
        value = _field(layers, field_name)
        if value is not None:
            retained[field_name] = value

    for candidate in _candidate_layers(profile, top_protocol):
        if candidate in layers and isinstance(layers[candidate], dict):
            for key, value in layers[candidate].items():
                if key in retained:
                    continue
                if key.startswith("_ws."):
                    continue
                flat_value = _flatten(value)
                if isinstance(flat_value, (dict, list, str, int, float, bool)):
                    retained[key] = flat_value
    return retained


def inspect_raw_packets(
    raw_packets: list[dict[str, Any]],
    *,
    capture_path: Path,
    display_filter: str | None,
    profile: ProfileDefinition,
) -> InspectResult:
    protocol_counts: Counter[str] = Counter()
    transport_counts: Counter[str] = Counter()
    conversations: Counter[tuple[str, str, str, str]] = Counter()
    anomalies: list[str] = []
    first_seen: str | None = None
    last_seen: str | None = None
    relevant_protocols: set[str] = set()
    raw_protocols: set[str] = set()

    for packet in raw_packets:
        try:
            layers = _layer_dict(packet)
            protocols = _frame_protocols(layers)
            raw_protocols.update(protocols)
            top_protocol = pick_top_protocol(layers, profile)
            protocol_counts[top_protocol] += 1
            if top_protocol in profile.relevant_protocols:
                relevant_protocols.add(top_protocol)
            transport = _extract_transport(layers)
            transport_counts[transport.proto or "unknown"] += 1
            src_ip, dst_ip = _extract_ip_pair(layers)
            conversations[(transport.proto or "unknown", str(src_ip), str(dst_ip), top_protocol)] += 1
            frame_time = _field(layers, "frame.time_epoch")
            if first_seen is None:
                first_seen = str(frame_time) if frame_time is not None else None
            last_seen = str(frame_time) if frame_time is not None else last_seen
            if transport.anomaly:
                packet_no = _field(layers, "frame.number")
                anomalies.append(f"Packet {packet_no}: {', '.join(transport.notes) or 'transport anomaly'}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping malformed packet during inspection: %s", exc)

    conversation_rows = [
        {
            "transport": proto,
            "src": src,
            "dst": dst,
            "top_protocol": top,
            "packet_count": count,
        }
        for (proto, src, dst, top), count in conversations.most_common(25)
    ]
    metadata = CaptureMetadata(
        capture_file=str(capture_path),
        packet_count=len(raw_packets),
        first_seen_epoch=first_seen,
        last_seen_epoch=last_seen,
        relevant_protocols=sorted(relevant_protocols),
        raw_protocols=sorted(raw_protocols),
        display_filter=display_filter,
    )
    return InspectResult(
        metadata=metadata,
        protocol_counts=dict(protocol_counts),
        transport_counts=dict(transport_counts),
        conversations=conversation_rows,
        anomalies=anomalies,
    )


def normalize_packets(
    raw_packets: list[dict[str, Any]],
    *,
    resolver: EndpointResolver,
    profile: ProfileDefinition,
    privacy_modes: dict[str, str],
) -> tuple[list[NormalizedPacket], int]:
    """Normalize raw tshark packets into :class:`NormalizedPacket` objects.

    Returns a tuple of ``(normalized_packets, dropped_count)`` where
    ``dropped_count`` is the number of packets that could not be processed due
    to unexpected structure.  A warning is logged for each dropped packet.
    """
    normalized: list[NormalizedPacket] = []
    dropped = 0

    for packet in raw_packets:
        try:
            layers = _layer_dict(packet)
            top_protocol = pick_top_protocol(layers, profile)
            src_ip, dst_ip = _extract_ip_pair(layers)
            transport = _extract_transport(layers)
            normalized.append(
                NormalizedPacket(
                    packet_no=_maybe_int(_field(layers, "frame.number")) or 0,
                    time_rel_ms=_maybe_float(_field(layers, "frame.time_relative")),
                    time_epoch=str(_field(layers, "frame.time_epoch") or ""),
                    top_protocol=top_protocol,
                    frame_protocols=_frame_protocols(layers),
                    src=resolver.resolve(src_ip),
                    dst=resolver.resolve(dst_ip),
                    transport=transport,
                    privacy=PrivacySummary(modes=privacy_modes),
                    anomalies=transport.notes,
                    message=MessageContext(
                        protocol=top_protocol,
                        fields=_retain_message_fields(layers, profile, top_protocol),
                    ),
                )
            )
        except Exception as exc:  # noqa: BLE001
            dropped += 1
            try:
                src = packet.get("_source") or {}
                pkt_no = (src.get("layers") or {}).get("frame.number", "?") if isinstance(src, dict) else "?"
            except Exception:  # noqa: BLE001
                pkt_no = "?"
            logger.warning("Dropping malformed packet %s: %s", pkt_no, exc)

    return normalized, dropped
