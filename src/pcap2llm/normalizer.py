from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

from pcap2llm.app_anomaly import detect_app_anomalies
from pcap2llm.models import CaptureMetadata, InspectResult, MessageContext, NormalizedPacket
from pcap2llm.models import PrivacySummary, ProfileDefinition, TransportContext
from pcap2llm.resolver import EndpointResolver

logger = logging.getLogger(__name__)

# Fallback transport protocol order used when no profile priority matches.
# Kept as a single constant to avoid duplication across functions.
_TRANSPORT_FALLBACK: tuple[str, ...] = ("sctp", "tcp", "udp", "ip", "ipv6")


def _flatten(value: Any, _seen: frozenset[int] | None = None) -> Any:
    """Recursively unwrap single-element lists and normalise nested dicts.

    Single-item lists are collapsed to their sole element so callers can treat
    TShark fields uniformly.  A *_seen* set of object IDs prevents infinite
    recursion on circular structures.
    """
    if _seen is None:
        _seen = frozenset()
    obj_id = id(value)
    if obj_id in _seen:
        return "<circular>"
    if isinstance(value, list):
        child_seen = _seen | {obj_id}
        if len(value) == 1:
            return _flatten(value[0], child_seen)
        return [_flatten(item, child_seen) for item in value]
    if isinstance(value, dict):
        child_seen = _seen | {obj_id}
        return {key: _flatten(item, child_seen) for key, item in value.items()}
    return value


def _layer_dict(packet: dict[str, Any]) -> dict[str, Any]:
    """Extract the ``_source.layers`` dict from a raw TShark packet object."""
    return packet.get("_source", {}).get("layers", {})


def _field(layers: dict[str, Any], key: str) -> Any:
    """Look up *key* in *layers*, trying both flat and nested access patterns.

    TShark can emit fields either at the top level of the layers dict or nested
    under the protocol prefix (e.g. ``{"ip.src": "…"}`` vs
    ``{"ip": {"ip.src": "…"}}``).  Both layouts are checked.
    """
    value = layers.get(key)
    if value is None and "." in key:
        layer_name = key.split(".", 1)[0]
        nested = layers.get(layer_name)
        if isinstance(nested, dict):
            value = nested.get(key)
    return _flatten(value)


def _maybe_int(value: Any) -> int | None:
    """Convert *value* to ``int``, returning ``None`` for empty or invalid input."""
    try:
        if value in (None, ""):
            return None
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _maybe_float(value: Any) -> float | None:
    """Convert *value* to ``float``, returning ``None`` for empty or invalid input."""
    try:
        if value in (None, ""):
            return None
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _frame_protocols(layers: dict[str, Any]) -> list[str]:
    """Return the colon-separated protocol stack from ``frame.protocols``."""
    value = _field(layers, "frame.protocols")
    if isinstance(value, str):
        return [part for part in value.split(":") if part]
    return []


def _candidate_layers(profile: ProfileDefinition, protocol: str) -> list[str]:
    """Return all TShark layer names that map to *protocol* in the profile."""
    return profile.protocol_aliases.get(protocol, [protocol])


def _merge_field_value(existing: Any, new_value: Any) -> Any:
    if existing == new_value:
        return existing
    if isinstance(existing, list):
        if new_value not in existing:
            existing.append(new_value)
        return existing
    if existing == new_value:
        return existing
    return [existing, new_value]


def _collect_prefixed_fields(value: Any, prefix: str, out: dict[str, Any]) -> None:
    """Recursively collect nested TShark fields whose keys start with *prefix*."""
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str) and key.startswith(prefix):
                if key in out:
                    out[key] = _merge_field_value(out[key], nested)
                else:
                    out[key] = nested
            _collect_prefixed_fields(nested, prefix, out)
    elif isinstance(value, list):
        for item in value:
            _collect_prefixed_fields(item, prefix, out)


def _prune_diameter_raw_avps(fields: dict[str, Any]) -> dict[str, Any]:
    """Drop raw AVP dump structures once semantic Diameter fields are surfaced."""
    pruned: dict[str, Any] = {}
    for key, value in fields.items():
        if key == "diameter.avp_tree":
            continue
        if key.startswith("diameter.avp"):
            continue
        if key.endswith("_tree") and key.startswith("diameter."):
            continue
        pruned[key] = value
    return pruned


def pick_top_protocol(layers: dict[str, Any], profile: ProfileDefinition) -> str:
    """Determine the most-significant application protocol for a packet.

    Priority is resolved against :attr:`ProfileDefinition.top_protocol_priority`.
    If no profile protocol matches, the highest-layer transport protocol from
    :data:`_TRANSPORT_FALLBACK` is returned.  Falls back to ``"unknown"``.
    """
    frame_protocols = set(_frame_protocols(layers))
    layer_names = set(layers.keys())
    for protocol in profile.top_protocol_priority:
        for candidate in _candidate_layers(profile, protocol):
            if candidate in frame_protocols or candidate in layer_names:
                return protocol
    for fallback in _TRANSPORT_FALLBACK:
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
    # Verbatim mode: return raw TShark layer without field selection or _flatten
    if top_protocol in profile.verbatim_protocols:
        raw: dict[str, Any] = {}
        for candidate in _candidate_layers(profile, top_protocol):
            prefix = f"{candidate}."
            for key, value in layers.items():
                if not key.startswith(prefix):
                    continue
                if key.startswith("_ws."):
                    continue
                raw[key] = value
            if candidate in layers and isinstance(layers[candidate], dict):
                for key, value in layers[candidate].items():
                    if not key.startswith("_ws."):
                        raw[key] = value
                for value in layers[candidate].values():
                    _collect_prefixed_fields(value, prefix, raw)
        if top_protocol == "diameter" and not profile.keep_raw_avps:
            raw = _prune_diameter_raw_avps(raw)
        return raw

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

    # Application-layer anomaly detection (stateful, runs over all packets)
    anomalies.extend(detect_app_anomalies(raw_packets, profile.name))

    conversation_rows = [
        {
            "transport": proto,
            "src": src,
            "dst": dst,
            "top_protocol": top,
            "packet_count": count,
        }
        for (proto, src, dst, top), count in conversations.most_common(profile.max_conversations)
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
                    src=resolver.resolve(src_ip, service_port=transport.src_port),
                    dst=resolver.resolve(dst_ip, service_port=transport.dst_port),
                    transport=transport,
                    privacy=PrivacySummary(modes=privacy_modes or {}),
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
