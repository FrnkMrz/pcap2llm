from __future__ import annotations

from typing import Any

from pcap2llm.models import InspectResult

TRANSPORT_ONLY: frozenset[str] = frozenset({
    "ip", "ipv6", "tcp", "udp", "sctp", "eth", "frame", "data",
    "ip.options", "ipv6.hopopts", "arp",
})

RAW_SIGNAL_FACTOR = 0.85
RAW_TRANSPORT_FACTOR = 0.35
DOMINANT_SIGNAL_THRESHOLD = 0.5

PROTOCOL_EQUIVALENTS: dict[str, tuple[str, ...]] = {
    "bssap": ("bssap", "gsm_a.bssap"),
    "bssmap": ("bssmap", "gsm_a.bssmap"),
    "dtap": ("dtap", "gsm_a.dtap", "gsm_dtap"),
    "http": ("http", "http2"),
    "nas-eps": ("nas-eps", "nas_eps"),
    "nas-5gs": ("nas-5gs", "nas_5gs"),
    "ss7": ("ss7", "m3ua"),
}

_SIGNAL_PRIORITY: dict[str, int] = {
    "ngap": 120,
    "nas-5gs": 115,
    "http": 105,
    "json": 100,
    "pfcp": 98,
    "s1ap": 96,
    "sip": 94,
    "sdp": 92,
    "dns": 90,
    "nas-eps": 88,
    "diameter": 86,
    "gtpv2": 84,
    "gtpv1": 78,
    "map": 76,
    "tcap": 74,
    "sccp": 72,
    "mtp3": 70,
    "bssap": 68,
    "dtap": 64,
    "isup": 60,
}


def _freq_factor(count: int, total: int) -> float:
    if total == 0 or count == 0:
        return 0.0
    rel = count / total
    if rel < 0.005:
        return 0.2
    if rel < 0.01:
        return 0.4
    if rel < 0.05:
        return 0.7
    return 1.0


def _protocol_variants(protocol: str) -> tuple[str, ...]:
    return PROTOCOL_EQUIVALENTS.get(protocol, (protocol,))


def canonical_protocol(protocol: str) -> str:
    for canonical, variants in PROTOCOL_EQUIVALENTS.items():
        if protocol == canonical or protocol in variants:
            return canonical
    return protocol


def protocol_count(inspect_result: InspectResult, protocol: str) -> int:
    total = 0
    for variant in _protocol_variants(protocol):
        if variant in TRANSPORT_ONLY:
            count = inspect_result.protocol_counts.get(variant, 0) or inspect_result.transport_counts.get(variant, 0)
            total += count
        else:
            total += inspect_result.protocol_counts.get(variant, 0)
    return total


def protocol_presence(inspect_result: InspectResult) -> frozenset[str]:
    present: set[str] = set()

    for protocol, count in inspect_result.protocol_counts.items():
        if count > 0:
            present.add(canonical_protocol(protocol))

    for protocol, count in inspect_result.transport_counts.items():
        if count > 0:
            present.add(canonical_protocol(protocol))

    for protocol in inspect_result.metadata.raw_protocols:
        present.add(canonical_protocol(protocol))

    return frozenset(present)


def protocol_evidence(
    inspect_result: InspectResult,
    protocol: str,
    total_packets: int | None = None,
    present: frozenset[str] | None = None,
) -> tuple[float, int, str]:
    total_packets = total_packets or inspect_result.metadata.packet_count or sum(inspect_result.protocol_counts.values()) or 1
    present = present or protocol_presence(inspect_result)
    count = protocol_count(inspect_result, protocol)
    if count > 0:
        return _freq_factor(count, total_packets), count, "count"
    if protocol in present:
        factor = RAW_TRANSPORT_FACTOR if protocol in TRANSPORT_ONLY else RAW_SIGNAL_FACTOR
        return factor, 0, "raw"
    return 0.0, 0, "none"


def dominant_signaling_protocols(
    inspect_result: InspectResult,
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    total_packets = inspect_result.metadata.packet_count or sum(inspect_result.protocol_counts.values()) or 1
    present = protocol_presence(inspect_result)

    candidates: list[dict[str, Any]] = []
    for protocol in present:
        if protocol in TRANSPORT_ONLY:
            continue
        factor, count, source = protocol_evidence(inspect_result, protocol, total_packets, present)
        if factor == 0:
            continue
        candidates.append(
            {
                "name": protocol,
                "count": count,
                "strength": "strong",
                "_score": factor,
                "_priority": _SIGNAL_PRIORITY.get(protocol, 0),
                "_source": source,
            }
        )

    candidates.sort(
        key=lambda item: (
            0 if item["_source"] == "count" else 1,
            -item["count"],
            -item["_score"],
            -item["_priority"],
            item["name"],
        )
    )
    strong = [item for item in candidates if item["_score"] >= DOMINANT_SIGNAL_THRESHOLD]
    selected = strong if strong else candidates[:5]
    selected = selected[: max(0, limit - 1)]

    sctp_factor, sctp_count, _ = protocol_evidence(inspect_result, "sctp", total_packets, present)
    if selected and sctp_factor > 0 and len(selected) < limit:
        selected.append(
            {
                "name": "sctp",
                "count": sctp_count,
                "strength": "supporting",
            }
        )

    return [
        {"name": item["name"], "count": item["count"], "strength": item["strength"]}
        for item in selected[:limit]
    ]


def dominant_signaling_names(
    inspect_result: InspectResult,
    *,
    limit: int = 10,
) -> list[str]:
    return [
        item["name"]
        for item in dominant_signaling_protocols(inspect_result, limit=limit)
        if item["strength"] == "strong"
    ]
