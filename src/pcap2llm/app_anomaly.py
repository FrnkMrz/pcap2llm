"""Application-layer anomaly detection for telecom protocols.

Anomaly strings use the format:
    "[<layer>][<severity>] <description> at packet <N>"

where severity is one of: info, warn, error.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _layers(packet: dict[str, Any]) -> dict[str, Any]:
    src = packet.get("_source")
    if not isinstance(src, dict):
        return {}
    layers = src.get("layers")
    return layers if isinstance(layers, dict) else {}


def _get(layers: dict[str, Any], *keys: str) -> Any:
    """Return the first non-None value found for any of the given field names.

    Tries both flat lookup (``layers[key]``) and nested lookup
    (``layers[prefix][key]``) to match the dual structure TShark may emit.
    Single-element lists are automatically unwrapped.
    """
    for key in keys:
        value = layers.get(key)
        if value is None and "." in key:
            prefix = key.split(".", 1)[0]
            nested = layers.get(prefix)
            if isinstance(nested, dict):
                value = nested.get(key)
        if value is not None:
            if isinstance(value, list):
                return value[0] if len(value) == 1 else value
            return value
    return None


# ---------------------------------------------------------------------------
# Diameter anomaly detection
# ---------------------------------------------------------------------------

# Command-flags R-bit (bit 7) indicates a request.
_DIAMETER_R_BIT = 0x80

# Result-Code values < 2000 are informational/provisional,
# 2xxx are success, ≥ 3000 indicate a problem.
_DIAMETER_SUCCESS_MIN = 2000
_DIAMETER_SUCCESS_MAX = 2999


def _is_diameter_request(flags: Any) -> bool:
    if flags is None:
        return False
    try:
        f = int(str(flags), 16) if str(flags).startswith("0x") else int(str(flags))
        return bool(f & _DIAMETER_R_BIT)
    except (ValueError, TypeError):
        return False


def _detect_diameter(raw_packets: list[dict[str, Any]]) -> list[str]:
    """Detect Diameter application-layer anomalies.

    Detects:
    - Error result codes (Result-Code ≥ 3000 or outside 2xxx success range)
    - Duplicate hop-by-hop IDs (retransmitted requests)
    - Unanswered requests still pending at end of capture
    """
    anomalies: list[str] = []
    # pending[hop_by_hop_id] = (packet_no, cmd_code)
    pending: dict[str, tuple[str, str]] = {}

    for packet in raw_packets:
        layers = _layers(packet)
        diam = layers.get("diameter")
        if diam is None and not any(k.startswith("diameter") for k in layers):
            continue
        try:
            pkt_no = str(_get(layers, "frame.number") or "?")
            flags = _get(layers, "diameter.flags")
            cmd_code = str(_get(layers, "diameter.cmd.code") or "?")
            hbh = str(_get(layers, "diameter.hop_by_hop_id", "diameter.hopbyhopid") or "")
            result_code = _get(layers, "diameter.Result-Code", "diameter.result_code",
                               "diameter.resultcode")

            if _is_diameter_request(flags):
                if hbh:
                    if hbh in pending:
                        anomalies.append(
                            f"[diameter][warn] Duplicate hop-by-hop ID {hbh} "
                            f"(cmd={cmd_code}) at packet {pkt_no}"
                        )
                    pending[hbh] = (pkt_no, cmd_code)
            else:
                # Answer — remove from pending
                if hbh:
                    pending.pop(hbh, None)
                if result_code is not None:
                    try:
                        rc = int(str(result_code))
                        if not (_DIAMETER_SUCCESS_MIN <= rc <= _DIAMETER_SUCCESS_MAX):
                            severity = "error" if rc >= 5000 else "warn"
                            anomalies.append(
                                f"[diameter][{severity}] Result-Code {rc} "
                                f"(cmd={cmd_code}) at packet {pkt_no}"
                            )
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("Diameter anomaly scan skipped packet: %s", exc)

    # Requests still without an answer
    for hbh, (pkt_no, cmd_code) in pending.items():
        anomalies.append(
            f"[diameter][warn] Unanswered request cmd={cmd_code} "
            f"hop-by-hop={hbh} from packet {pkt_no}"
        )

    return anomalies


# ---------------------------------------------------------------------------
# GTPv2-C anomaly detection
# ---------------------------------------------------------------------------

# GTPv2 message type values (decimal)
_GTP_CREATE_SESSION_REQ = "32"
_GTP_CREATE_SESSION_RSP = "33"
_GTP_MODIFY_BEARER_REQ = "34"
_GTP_MODIFY_BEARER_RSP = "35"
_GTP_DELETE_SESSION_REQ = "36"
_GTP_DELETE_SESSION_RSP = "37"
_GTP_ERROR_INDICATION = "26"
# GTPv2 cause value 16 = "Request accepted"
_GTP_CAUSE_ACCEPTED = 16


def _gtp_cause_int(cause: Any) -> int | None:
    if cause is None:
        return None
    try:
        s = str(cause)
        return int(s, 16) if s.startswith("0x") else int(s)
    except (ValueError, TypeError):
        return None


def _detect_gtpv2(raw_packets: list[dict[str, Any]]) -> list[str]:
    """Detect GTPv2-C application-layer anomalies.

    Detects:
    - Create Session Requests without a corresponding response
    - Create Session Responses with non-success cause values
    - Error Indication messages
    """
    anomalies: list[str] = []
    # pending_create[seq_no] = packet_no
    pending_create: dict[str, str] = {}

    for packet in raw_packets:
        layers = _layers(packet)
        if "gtpv2" not in layers and not any(k.startswith("gtpv2") for k in layers):
            continue
        try:
            pkt_no = str(_get(layers, "frame.number") or "?")
            msg_type = str(_get(layers, "gtpv2.message_type") or "")
            seq_no = str(_get(layers, "gtpv2.seq_no", "gtpv2.sequence_number") or "")
            cause = _gtp_cause_int(_get(layers, "gtpv2.cause"))

            if msg_type == _GTP_CREATE_SESSION_REQ:
                if seq_no:
                    pending_create[seq_no] = pkt_no
            elif msg_type == _GTP_CREATE_SESSION_RSP:
                if seq_no:
                    pending_create.pop(seq_no, None)
                if cause is not None and cause != _GTP_CAUSE_ACCEPTED:
                    anomalies.append(
                        f"[gtpv2][warn] Create Session rejected cause={cause} "
                        f"at packet {pkt_no}"
                    )
            elif msg_type == _GTP_ERROR_INDICATION:
                anomalies.append(
                    f"[gtpv2][error] Error Indication at packet {pkt_no}"
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("GTPv2 anomaly scan skipped packet: %s", exc)

    for seq_no, pkt_no in pending_create.items():
        anomalies.append(
            f"[gtpv2][warn] Unanswered Create Session Request "
            f"seq={seq_no} from packet {pkt_no}"
        )

    return anomalies


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_app_anomalies(
    raw_packets: list[dict[str, Any]],
    profile_name: str = "",
) -> list[str]:
    """Detect application-layer anomalies for all supported protocols.

    Returns a list of formatted anomaly strings that can be appended to
    :attr:`InspectResult.anomalies`.  Currently checks:

    - Diameter (all profiles)
    - GTPv2-C (lte-core profile)
    """
    anomalies: list[str] = []
    anomalies.extend(_detect_diameter(raw_packets))
    if profile_name in ("lte-core", ""):
        anomalies.extend(_detect_gtpv2(raw_packets))
    return anomalies
