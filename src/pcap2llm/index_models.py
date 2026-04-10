"""Lightweight packet-index data model for two-pass extraction.

Pass 1 of the two-pass pipeline uses TShark ``-T fields`` to export only the
fields needed for inspection, anomaly detection, and frame selection.  This
produces a list of :class:`PacketIndexRecord` objects — one per packet — that
is much smaller than a full ``-T json`` export.

Pass 2 then exports full JSON *only* for the selected frame numbers, so the
expensive normalization and protection stages only process a bounded set of
packets.
"""
from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Fields exported in pass 1
# ---------------------------------------------------------------------------
#
# Order here must match INDEX_FIELDS exactly — the TSV parser uses positional
# indexing.

INDEX_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
    # Network layer — IPv4 and IPv6 addresses are separate columns
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    # SCTP (most common transport for telecom signalling)
    "sctp.srcport",
    "sctp.dstport",
    "sctp.assoc_index",
    # TCP
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.analysis.retransmission",
    "tcp.analysis.out_of_order",
    # UDP
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
    # Diameter anomaly fields — primary names and alternative spellings
    # (TShark emits different names depending on version/config;
    # _detect_diameter() uses _get() with fallbacks — we mirror those here)
    "diameter.flags",
    "diameter.cmd.code",
    "diameter.hop_by_hop_id",
    "diameter.hopbyhopid",          # alt spelling
    "diameter.Result-Code",
    "diameter.result_code",         # alt spelling
    "diameter.resultcode",          # alt spelling
    # GTPv2-C anomaly fields — primary and alternative
    "gtpv2.message_type",
    "gtpv2.seq_no",
    "gtpv2.sequence_number",        # alt spelling
    "gtpv2.cause",
)

INDEX_SEPARATOR = "|"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PacketIndexRecord:
    """Lightweight per-packet record produced by pass-1 TShark field export.

    All string fields are ``None`` when TShark did not output a value for that
    packet (e.g. ``diameter.*`` fields for non-Diameter packets).
    """
    frame_no: int
    time_epoch: str | None
    protocols: list[str]

    # Network
    src_ip: str | None          # IPv4 or IPv6 source (IPv4 preferred)
    dst_ip: str | None          # IPv4 or IPv6 destination (IPv4 preferred)

    # Transport
    transport: str | None       # "sctp", "tcp", "udp", or None
    src_port: int | None
    dst_port: int | None
    stream: str | None

    # Transport anomaly flags
    tcp_retransmission: bool
    tcp_out_of_order: bool

    # Diameter anomaly fields (None for non-Diameter packets)
    diameter_flags: str | None
    diameter_cmd_code: str | None
    diameter_hop_by_hop_id: str | None
    diameter_result_code: str | None

    # GTPv2-C anomaly fields (None for non-GTPv2 packets)
    gtpv2_message_type: str | None
    gtpv2_seq_no: str | None
    gtpv2_cause: str | None


# ---------------------------------------------------------------------------
# Selection result
# ---------------------------------------------------------------------------

@dataclass
class SelectedFrames:
    """Frame-selection result produced at the end of pass 1."""
    frame_numbers: list[int]        # ordered list of selected frame numbers
    total_exported: int             # total packets in pass-1 index
    truncated: bool                 # True when total_exported > max_packets
    truncation_note: str | None = None


# ---------------------------------------------------------------------------
# TSV row parser
# ---------------------------------------------------------------------------

def _v(raw: str) -> str | None:
    """Return ``None`` for empty TShark field output, otherwise the raw string."""
    stripped = raw.strip()
    return stripped if stripped else None


def parse_index_row(row: str) -> PacketIndexRecord | None:
    """Parse one tab-separated row from TShark ``-T fields`` output.

    Returns ``None`` and logs a warning for malformed rows.  Callers should
    skip ``None`` entries and count them as dropped.

    The separator is :data:`INDEX_SEPARATOR` (``|``) to avoid clashes with
    protocol field values that may contain tabs.
    """
    cols = row.split(INDEX_SEPARATOR)
    if len(cols) < len(INDEX_FIELDS):
        return None

    # Positional unpacking — must mirror INDEX_FIELDS order exactly.
    (
        frame_number_raw,
        time_epoch_raw,
        protocols_raw,
        ip_src_raw,
        ip_dst_raw,
        ipv6_src_raw,
        ipv6_dst_raw,
        sctp_srcport_raw,
        sctp_dstport_raw,
        sctp_assoc_raw,
        tcp_srcport_raw,
        tcp_dstport_raw,
        tcp_stream_raw,
        tcp_retr_raw,
        tcp_ooo_raw,
        udp_srcport_raw,
        udp_dstport_raw,
        udp_stream_raw,
        diam_flags_raw,
        diam_cmd_raw,
        diam_hopbyhop_raw,
        diam_hopbyhopid_raw,        # alt spelling
        diam_result_raw,
        diam_result_lc_raw,         # alt spelling diameter.result_code
        diam_resultcode_raw,        # alt spelling diameter.resultcode
        gtpv2_msgtype_raw,
        gtpv2_seqno_raw,
        gtpv2_seqno_alt_raw,        # alt spelling gtpv2.sequence_number
        gtpv2_cause_raw,
    ) = cols[:len(INDEX_FIELDS)]

    try:
        frame_no = int(frame_number_raw.strip())
    except (ValueError, AttributeError):
        return None

    # Protocol list
    proto_str = _v(protocols_raw)
    protocols = [p for p in proto_str.split(":") if p] if proto_str else []

    # Network addresses — prefer IPv4 over IPv6
    src_ip = _v(ip_src_raw) or _v(ipv6_src_raw)
    dst_ip = _v(ip_dst_raw) or _v(ipv6_dst_raw)

    # Transport resolution — prefer SCTP > TCP > UDP
    transport: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    stream: str | None = None

    if _v(sctp_srcport_raw):
        transport = "sctp"
        try:
            src_port = int(sctp_srcport_raw.strip())
            dst_port = int(sctp_dstport_raw.strip())
        except (ValueError, AttributeError):
            pass
        stream = _v(sctp_assoc_raw)
    elif _v(tcp_srcport_raw):
        transport = "tcp"
        try:
            src_port = int(tcp_srcport_raw.strip())
            dst_port = int(tcp_dstport_raw.strip())
        except (ValueError, AttributeError):
            pass
        stream = _v(tcp_stream_raw)
    elif _v(udp_srcport_raw):
        transport = "udp"
        try:
            src_port = int(udp_srcport_raw.strip())
            dst_port = int(udp_dstport_raw.strip())
        except (ValueError, AttributeError):
            pass
        stream = _v(udp_stream_raw)

    # TCP anomaly flags — TShark emits "1" when present
    tcp_retransmission = bool(_v(tcp_retr_raw))
    tcp_out_of_order = bool(_v(tcp_ooo_raw))

    # Merge field-name aliases: use first non-None value across all spellings.
    diam_hbh = _v(diam_hopbyhop_raw) or _v(diam_hopbyhopid_raw)
    diam_rc = _v(diam_result_raw) or _v(diam_result_lc_raw) or _v(diam_resultcode_raw)
    gtpv2_seq = _v(gtpv2_seqno_raw) or _v(gtpv2_seqno_alt_raw)

    return PacketIndexRecord(
        frame_no=frame_no,
        time_epoch=_v(time_epoch_raw),
        protocols=protocols,
        src_ip=src_ip,
        dst_ip=dst_ip,
        transport=transport,
        src_port=src_port,
        dst_port=dst_port,
        stream=stream,
        tcp_retransmission=tcp_retransmission,
        tcp_out_of_order=tcp_out_of_order,
        diameter_flags=_v(diam_flags_raw),
        diameter_cmd_code=_v(diam_cmd_raw),
        diameter_hop_by_hop_id=diam_hbh,
        diameter_result_code=diam_rc,
        gtpv2_message_type=_v(gtpv2_msgtype_raw),
        gtpv2_seq_no=gtpv2_seq,
        gtpv2_cause=_v(gtpv2_cause_raw),
    )
