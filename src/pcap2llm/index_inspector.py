"""Pass-1 inspection: build InspectResult and SelectedFrames from index records.

This module is the lightweight counterpart to :func:`normalizer.inspect_raw_packets`.
It operates on :class:`~pcap2llm.index_models.PacketIndexRecord` objects produced
by the pass-1 TShark ``-T fields`` export rather than on full TShark JSON dicts.

Key design points
-----------------
- All statistics (packet counts, protocol mix, conversations) come from pass-1
  records — they cover the full capture, so ``summary.json`` accuracy is preserved.
- Application-layer anomaly detection (Diameter, GTPv2-C) is retained in full.
  The required fields (``diameter.*``, ``gtpv2.*``) are included in the pass-1
  export, so stateful cross-packet analysis still works correctly.
- :func:`select_frame_numbers` derives the bounded set of frame numbers to pass
  to the pass-2 export — after this call the index records are no longer needed.
"""
from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path
from typing import Any

from pcap2llm.app_anomaly import detect_app_anomalies
from pcap2llm.index_models import PacketIndexRecord, SelectedFrames
from pcap2llm.models import CaptureMetadata, InspectResult, ProfileDefinition
from pcap2llm.normalizer import pick_top_protocol
from pcap2llm.resolver import EndpointResolver, ResolvedEndpoint

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers: convert index record → minimal packet dict
# ---------------------------------------------------------------------------

def _record_to_minimal_packet(record: PacketIndexRecord) -> dict[str, Any]:
    """Build a minimal TShark-shaped packet dict from a :class:`PacketIndexRecord`.

    The result contains only the fields needed for anomaly detection (Diameter
    and GTPv2-C) and the frame number used in anomaly messages.  It uses the
    same nested layout that :func:`app_anomaly._get` handles.
    """
    layers: dict[str, Any] = {
        "frame": {"frame.number": str(record.frame_no)},
    }
    # Only add protocol layers when the record actually has their fields.
    if record.diameter_flags is not None or record.diameter_cmd_code is not None:
        diam: dict[str, Any] = {}
        if record.diameter_flags is not None:
            diam["diameter.flags"] = record.diameter_flags
        if record.diameter_cmd_code is not None:
            diam["diameter.cmd.code"] = record.diameter_cmd_code
        if record.diameter_hop_by_hop_id is not None:
            # Emit under all known spellings so _get() fallbacks work
            diam["diameter.hop_by_hop_id"] = record.diameter_hop_by_hop_id
            diam["diameter.hopbyhopid"] = record.diameter_hop_by_hop_id
        if record.diameter_result_code is not None:
            # Emit under all known spellings so _get() fallbacks work
            diam["diameter.Result-Code"] = record.diameter_result_code
            diam["diameter.result_code"] = record.diameter_result_code
            diam["diameter.resultcode"] = record.diameter_result_code
        layers["diameter"] = diam

    if record.gtpv2_message_type is not None:
        gtpv2: dict[str, Any] = {}
        gtpv2["gtpv2.message_type"] = record.gtpv2_message_type
        if record.gtpv2_seq_no is not None:
            # Emit under both spellings
            gtpv2["gtpv2.seq_no"] = record.gtpv2_seq_no
            gtpv2["gtpv2.sequence_number"] = record.gtpv2_seq_no
        if record.gtpv2_cause is not None:
            gtpv2["gtpv2.cause"] = record.gtpv2_cause
        layers["gtpv2"] = gtpv2

    return {"_source": {"layers": layers}}


def _minimal_layers_for_protocol_pick(record: PacketIndexRecord) -> dict[str, Any]:
    """Build a minimal ``layers`` dict that lets :func:`~normalizer.pick_top_protocol`
    work on a :class:`PacketIndexRecord`.

    The function needs:
    - ``frame.protocols`` string (for ``_frame_protocols``)
    - protocol names as top-level keys (for ``layer_names`` check)
    """
    layers: dict[str, Any] = {
        "frame": {"frame.protocols": ":".join(record.protocols)},
    }
    for proto in record.protocols:
        if proto and proto not in layers:
            layers[proto] = {}
    return layers


# ---------------------------------------------------------------------------
# Main inspection function
# ---------------------------------------------------------------------------

def inspect_index_records(
    records: list[PacketIndexRecord],
    *,
    capture_path: Path,
    display_filter: str | None,
    profile: ProfileDefinition,
    resolver: EndpointResolver | None = None,
    hosts_file_used: bool = False,
    mapping_file_used: bool = False,
    subnets_file_used: bool = False,
    ss7pcs_file_used: bool = False,
) -> InspectResult:
    """Build an :class:`~models.InspectResult` from pass-1 packet-index records.

    Produces the same fields as :func:`normalizer.inspect_raw_packets`:
    - packet counts and protocol histogram
    - transport protocol counts
    - conversation table (capped by ``profile.max_conversations``)
    - application-layer anomalies (Diameter, GTPv2-C) via :func:`~app_anomaly.detect_app_anomalies`
    - first/last seen timestamps
    - relevant and raw protocol sets

    Because all records come from the full pass-1 export, these statistics
    accurately describe the entire capture — not just the detail window.
    """
    protocol_counts: Counter[str] = Counter()
    transport_counts: Counter[str] = Counter()
    conversations: Counter[tuple[str, str, str, str]] = Counter()
    anomalies: list[str] = []
    first_packet_number: int | None = None
    last_packet_number: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    relevant_protocols: set[str] = set()
    raw_protocols: set[str] = set()
    # Sampled DNS query names for telecom naming pattern detection.
    # Limited to 30 unique names — enough for pattern detection, cheap in memory.
    _dns_qry_names_seen: set[str] = set()
    _DNS_QRY_SAMPLE_LIMIT = 30

    resolver = resolver or EndpointResolver()
    resolved_peers: dict[str, dict[str, Any]] = {}

    def _remember_endpoint(endpoint: ResolvedEndpoint) -> None:
        name = endpoint.alias or endpoint.hostname
        if not endpoint.ip or not name:
            return
        row: dict[str, Any] = {"ip": endpoint.ip, "name": name}
        if endpoint.hostname and endpoint.hostname != name:
            row["hostname"] = endpoint.hostname
        if endpoint.role:
            row["role"] = endpoint.role
        for label in (
            "network_element_type",
            "network_element_confidence",
            "network_element_source",
            "network_element_warning",
            "network_element_override",
            "ss7_point_code",
            "ss7_point_code_alias",
        ):
            if endpoint.labels.get(label) is not None:
                row[label] = endpoint.labels[label]
        resolved_peers[endpoint.ip] = row

    for record in records:
        try:
            raw_protocols.update(record.protocols)
            minimal_layers = _minimal_layers_for_protocol_pick(record)
            top_protocol = pick_top_protocol(minimal_layers, profile)
            protocol_counts[top_protocol] += 1
            if top_protocol in profile.relevant_protocols:
                relevant_protocols.add(top_protocol)

            transport = record.transport or "ip"
            transport_counts[transport] += 1

            src = record.src_ip or "unknown"
            dst = record.dst_ip or "unknown"
            conversations[(transport, src, dst, top_protocol)] += 1

            if record.src_ip:
                _remember_endpoint(
                    resolver.resolve(record.src_ip, service_port=record.src_port)
                )
            if record.dst_ip:
                _remember_endpoint(
                    resolver.resolve(record.dst_ip, service_port=record.dst_port)
                )

            if first_packet_number is None:
                first_packet_number = record.frame_no
            last_packet_number = record.frame_no
            if record.time_epoch:
                if first_seen is None:
                    first_seen = record.time_epoch
                last_seen = record.time_epoch

            # Sample DNS query names (cheap — only for DNS packets, max 30)
            if (
                record.dns_qry_name
                and len(_dns_qry_names_seen) < _DNS_QRY_SAMPLE_LIMIT
            ):
                _dns_qry_names_seen.add(record.dns_qry_name.lower())

            # Transport-layer anomaly (TCP retransmission / out-of-order)
            if record.tcp_retransmission or record.tcp_out_of_order:
                notes = []
                if record.tcp_retransmission:
                    notes.append("retransmission")
                if record.tcp_out_of_order:
                    notes.append("out_of_order")
                anomalies.append(
                    f"Packet {record.frame_no}: {', '.join(notes)}"
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Skipping malformed index record frame=%s during inspection: %s",
                getattr(record, "frame_no", "?"),
                exc,
            )

    # Application-layer anomaly detection — stateful, runs over all records.
    # We convert records to minimal packet dicts that detect_app_anomalies()
    # can consume via its nested-dict _get() helper.
    minimal_packets = [_record_to_minimal_packet(r) for r in records]
    anomalies.extend(detect_app_anomalies(minimal_packets, profile.name))

    conversation_rows = [
        {
            "transport": proto,
            "src": src,
            "dst": dst,
            "top_protocol": top,
            "packet_count": count,
        }
        for (proto, src, dst, top), count in conversations.most_common(
            profile.max_conversations
        )
    ]
    metadata = CaptureMetadata(
        capture_file=str(capture_path),
        packet_count=len(records),
        first_packet_number=first_packet_number,
        last_packet_number=last_packet_number,
        first_seen_epoch=first_seen,
        last_seen_epoch=last_seen,
        relevant_protocols=sorted(relevant_protocols),
        raw_protocols=sorted(raw_protocols),
        display_filter=display_filter,
        hosts_file_used=hosts_file_used,
        mapping_file_used=mapping_file_used,
        subnets_file_used=subnets_file_used,
        ss7pcs_file_used=ss7pcs_file_used,
        resolved_peers=sorted(resolved_peers.values(), key=lambda item: (item["name"], item["ip"])),
        dns_qry_names=sorted(_dns_qry_names_seen),
    )
    return InspectResult(
        metadata=metadata,
        protocol_counts=dict(protocol_counts),
        transport_counts=dict(transport_counts),
        conversations=conversation_rows,
        anomalies=anomalies,
    )


# ---------------------------------------------------------------------------
# Frame selection
# ---------------------------------------------------------------------------

def select_frame_numbers(
    records: list[PacketIndexRecord],
    *,
    max_packets: int,
) -> SelectedFrames:
    """Derive the bounded set of frame numbers for pass-2 export.

    When *max_packets* is 0 or negative, all frames are selected (equivalent to
    ``--all-packets``).  Otherwise the first *max_packets* frames are selected.

    The returned :class:`~index_models.SelectedFrames` carries:
    - ``frame_numbers`` — ordered list for use in the pass-2 display filter
    - ``total_exported`` — total packets seen in pass 1
    - ``truncated`` — whether the selection is smaller than the full index
    """
    total = len(records)
    unlimited = max_packets <= 0
    truncated = (not unlimited) and (total > max_packets)

    if unlimited or not truncated:
        frame_numbers = [r.frame_no for r in records]
    else:
        frame_numbers = [r.frame_no for r in records[:max_packets]]

    note: str | None = None
    if truncated:
        note = (
            f"detail.json contains only the first {max_packets:,} of "
            f"{total:,} packets. Use --all-packets to include all."
        )

    return SelectedFrames(
        frame_numbers=frame_numbers,
        total_exported=total,
        truncated=truncated,
        truncation_note=note,
    )
