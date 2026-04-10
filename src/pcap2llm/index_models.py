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
# INDEX_FIELDS is the *desired* full set.  TShark versions differ in which
# field names they accept — some of the alt-spelling names below may not exist
# on a given installation.  ``export_packet_index`` in tshark_runner.py
# handles this by retrying without any fields TShark rejects, and passing the
# active subset to ``parse_index_row`` via the *fields* parameter.
#
# All aliases are included so that whichever spelling a given TShark version
# exports, at least one will be present in the active field list.

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
    # Diameter anomaly fields — include multiple spellings; TShark version
    # determines which names are valid.  The parser merges aliases.
    "diameter.flags",
    "diameter.cmd.code",
    "diameter.hop_by_hop_id",        # TShark < 4.x
    "diameter.hopbyhopid",           # TShark 4.x
    "diameter.Result-Code",          # mixed-case primary
    "diameter.result_code",          # lowercase alt (some builds)
    "diameter.resultcode",           # no-separator alt (some builds)
    # GTPv2-C anomaly fields — multiple spellings across TShark versions
    "gtpv2.message_type",
    "gtpv2.seq",                     # TShark 4.x
    "gtpv2.seq_no",                  # older builds
    "gtpv2.sequence_number",         # another alt spelling
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


def parse_index_row(
    row: str,
    fields: tuple[str, ...] = INDEX_FIELDS,
) -> PacketIndexRecord | None:
    """Parse one ``|``-separated row from TShark ``-T fields`` output.

    *fields* must match the ``-e`` field sequence used when TShark was invoked.
    It defaults to :data:`INDEX_FIELDS` but callers can pass a reduced subset
    (e.g. when some field names were rejected by a particular TShark version and
    the export was retried without them).

    Returns ``None`` for malformed rows (too few columns, non-integer frame
    number).  Callers should skip ``None`` entries.
    """
    cols = row.split(INDEX_SEPARATOR)
    if len(cols) < len(fields):
        return None

    # Build a name→value mapping so the rest of the parser is position-independent.
    fv: dict[str, str | None] = {field: _v(cols[i]) for i, field in enumerate(fields)}

    # Frame number — mandatory
    fn_raw = fv.get("frame.number")
    try:
        frame_no = int((fn_raw or "").strip())
    except (ValueError, AttributeError):
        return None

    # Protocol list
    proto_str = fv.get("frame.protocols")
    protocols = [p for p in proto_str.split(":") if p] if proto_str else []

    # Network addresses — prefer IPv4 over IPv6
    src_ip = fv.get("ip.src") or fv.get("ipv6.src")
    dst_ip = fv.get("ip.dst") or fv.get("ipv6.dst")

    # Transport resolution — prefer SCTP > TCP > UDP
    transport: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    stream: str | None = None

    if fv.get("sctp.srcport"):
        transport = "sctp"
        try:
            src_port = int((fv.get("sctp.srcport") or "").strip())
            dst_port = int((fv.get("sctp.dstport") or "").strip())
        except (ValueError, AttributeError):
            pass
        stream = fv.get("sctp.assoc_index")
    elif fv.get("tcp.srcport"):
        transport = "tcp"
        try:
            src_port = int((fv.get("tcp.srcport") or "").strip())
            dst_port = int((fv.get("tcp.dstport") or "").strip())
        except (ValueError, AttributeError):
            pass
        stream = fv.get("tcp.stream")
    elif fv.get("udp.srcport"):
        transport = "udp"
        try:
            src_port = int((fv.get("udp.srcport") or "").strip())
            dst_port = int((fv.get("udp.dstport") or "").strip())
        except (ValueError, AttributeError):
            pass
        stream = fv.get("udp.stream")

    # TCP anomaly flags — TShark emits "1" when present
    tcp_retransmission = bool(fv.get("tcp.analysis.retransmission"))
    tcp_out_of_order = bool(fv.get("tcp.analysis.out_of_order"))

    # Diameter — merge all known spellings (whichever are present wins)
    diam_hbh = (
        fv.get("diameter.hop_by_hop_id")
        or fv.get("diameter.hopbyhopid")
    )
    diam_rc = (
        fv.get("diameter.Result-Code")
        or fv.get("diameter.result_code")
        or fv.get("diameter.resultcode")
    )

    # GTPv2 — merge all known spellings
    gtpv2_seq = (
        fv.get("gtpv2.seq")
        or fv.get("gtpv2.seq_no")
        or fv.get("gtpv2.sequence_number")
    )

    return PacketIndexRecord(
        frame_no=frame_no,
        time_epoch=fv.get("frame.time_epoch"),
        protocols=protocols,
        src_ip=src_ip,
        dst_ip=dst_ip,
        transport=transport,
        src_port=src_port,
        dst_port=dst_port,
        stream=stream,
        tcp_retransmission=tcp_retransmission,
        tcp_out_of_order=tcp_out_of_order,
        diameter_flags=fv.get("diameter.flags"),
        diameter_cmd_code=fv.get("diameter.cmd.code"),
        diameter_hop_by_hop_id=diam_hbh,
        diameter_result_code=diam_rc,
        gtpv2_message_type=fv.get("gtpv2.message_type"),
        gtpv2_seq_no=gtpv2_seq,
        gtpv2_cause=fv.get("gtpv2.cause"),
    )
