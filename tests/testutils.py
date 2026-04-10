"""Shared test utilities for two-pass pipeline mocking.

The pipeline now calls three TShark runner methods:
  - export_packet_index()   → list[PacketIndexRecord]  (pass 1)
  - export_packets()        → list[dict]               (pass 2, non-truncated)
  - export_selected_packets() → list[dict]             (pass 2, truncated)

Tests that previously patched only ``export_packets`` must now patch all three.
:func:`mock_runner_two_pass` does this with a single context manager, deriving
the pass-1 index records automatically from the mock raw-packet dicts so tests
do not have to build them manually.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

from pcap2llm.index_models import PacketIndexRecord
from pcap2llm.normalizer import _field


# ---------------------------------------------------------------------------
# Conversion: raw packet dict → PacketIndexRecord
# ---------------------------------------------------------------------------

def _layers(packet: dict[str, Any]) -> dict[str, Any]:
    src = packet.get("_source") if isinstance(packet, dict) else None
    if not isinstance(src, dict):
        return {}
    layers = src.get("layers")
    return layers if isinstance(layers, dict) else {}


def _safe_int(value: Any) -> int | None:
    try:
        return int(str(value)) if value is not None else None
    except (ValueError, TypeError):
        return None


def index_record_from_raw(packet: dict[str, Any]) -> PacketIndexRecord:
    """Derive a :class:`~pcap2llm.index_models.PacketIndexRecord` from a raw mock packet dict.

    Uses the same field-access helpers as the normalizer so the derived record
    is consistent with what a real ``-T fields`` pass-1 export would produce.
    """
    layers = _layers(packet)

    # Frame number — fall back to 1 for malformed mocks
    fn_raw = _field(layers, "frame.number")
    frame_no = _safe_int(fn_raw) or 1

    # Protocol list
    proto_str = _field(layers, "frame.protocols") or ""
    protocols = [p for p in str(proto_str).split(":") if p]

    # IP addresses — prefer IPv4
    src_ip = _field(layers, "ip.src") or _field(layers, "ipv6.src")
    dst_ip = _field(layers, "ip.dst") or _field(layers, "ipv6.dst")
    src_ip = str(src_ip) if src_ip is not None else None
    dst_ip = str(dst_ip) if dst_ip is not None else None

    # Transport — SCTP > TCP > UDP
    transport: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    stream: str | None = None

    if "sctp" in layers or any(k.startswith("sctp.") for k in layers):
        transport = "sctp"
        src_port = _safe_int(_field(layers, "sctp.srcport"))
        dst_port = _safe_int(_field(layers, "sctp.dstport"))
        raw_stream = _field(layers, "sctp.assoc_index")
        stream = str(raw_stream) if raw_stream is not None else None
    elif "tcp" in layers or any(k.startswith("tcp.") for k in layers):
        transport = "tcp"
        src_port = _safe_int(_field(layers, "tcp.srcport"))
        dst_port = _safe_int(_field(layers, "tcp.dstport"))
        raw_stream = _field(layers, "tcp.stream")
        stream = str(raw_stream) if raw_stream is not None else None
    elif "udp" in layers or any(k.startswith("udp.") for k in layers):
        transport = "udp"
        src_port = _safe_int(_field(layers, "udp.srcport"))
        dst_port = _safe_int(_field(layers, "udp.dstport"))
        raw_stream = _field(layers, "udp.stream")
        stream = str(raw_stream) if raw_stream is not None else None

    def _s(v: Any) -> str | None:
        return str(v) if v is not None else None

    def _first(*vals: Any) -> str | None:
        """Return the first non-None value as a string, or None."""
        for v in vals:
            if v is not None:
                return str(v)
        return None

    # Diameter anomaly fields — try all known field-name aliases
    diam_hbh = _first(
        _field(layers, "diameter.hop_by_hop_id"),
        _field(layers, "diameter.hopbyhopid"),
    )
    diam_rc = _first(
        _field(layers, "diameter.Result-Code"),
        _field(layers, "diameter.result_code"),
        _field(layers, "diameter.resultcode"),
    )
    # GTPv2 fields — try both spellings
    gtpv2_seq = _first(
        _field(layers, "gtpv2.seq_no"),
        _field(layers, "gtpv2.sequence_number"),
    )

    return PacketIndexRecord(
        frame_no=frame_no,
        time_epoch=str(_field(layers, "frame.time_epoch") or "1712390000.0"),
        protocols=protocols,
        src_ip=src_ip,
        dst_ip=dst_ip,
        transport=transport,
        src_port=src_port,
        dst_port=dst_port,
        stream=stream,
        tcp_retransmission=bool(_field(layers, "tcp.analysis.retransmission")),
        tcp_out_of_order=bool(_field(layers, "tcp.analysis.out_of_order")),
        diameter_flags=_s(_field(layers, "diameter.flags")),
        diameter_cmd_code=_s(_field(layers, "diameter.cmd.code")),
        diameter_hop_by_hop_id=diam_hbh,
        diameter_result_code=diam_rc,
        gtpv2_message_type=_s(_field(layers, "gtpv2.message_type")),
        gtpv2_seq_no=gtpv2_seq,
        gtpv2_cause=_s(_field(layers, "gtpv2.cause")),
    )


def index_records_from_raw(packets: list[dict[str, Any]]) -> list[PacketIndexRecord]:
    """Convert a list of mock raw packet dicts to :class:`PacketIndexRecord` objects."""
    records = []
    for pkt in packets:
        try:
            records.append(index_record_from_raw(pkt))
        except Exception:  # noqa: BLE001
            pass  # skip malformed packets silently, matching pipeline behavior
    return records


# ---------------------------------------------------------------------------
# Context manager: mock all three runner methods at once
# ---------------------------------------------------------------------------

@contextmanager
def mock_runner_two_pass(runner: Any, packets: list[dict[str, Any]]):
    """Mock all TShark runner methods needed by the two-pass pipeline.

    Patches:
    - ``export_packet_index`` → :class:`PacketIndexRecord` list derived from *packets*
    - ``export_packets``      → *packets* (used for non-truncated pass-2 export)
    - ``export_selected_packets`` → filtered subset of *packets* by frame number
      (used for truncated pass-2 export)

    Usage::

        with mock_runner_two_pass(runner, packets):
            artifacts = analyze_capture(...)
    """
    index_records = index_records_from_raw(packets)

    # Build a frame-number → packet mapping for export_selected_packets
    frame_map: dict[int, dict[str, Any]] = {}
    for pkt in packets:
        layers = _layers(pkt)
        fn = _field(layers, "frame.number")
        try:
            frame_map[int(str(fn))] = pkt
        except (TypeError, ValueError):
            pass

    def _export_selected(capture_path, *, frame_numbers, extra_args=None, two_pass=False):
        return [frame_map[fn] for fn in frame_numbers if fn in frame_map]

    with patch.object(runner, "export_packet_index", return_value=index_records):
        with patch.object(runner, "export_packets", return_value=packets):
            with patch.object(runner, "export_selected_packets", side_effect=_export_selected):
                yield
