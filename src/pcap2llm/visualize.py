from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from http import HTTPStatus
from typing import Any


def _to_ms(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return _to_text(value[0])
    text = str(value).strip()
    return text or None


def _truncate(text: str, max_len: int) -> str:
    value = text.strip()
    if len(value) <= max_len:
        return value
    return f"{value[:max_len - 3]}..."


def _bool_from_field(value: Any) -> bool | None:
    text = _to_text(value)
    if text is None:
        return None
    lowered = text.lower()
    if lowered in {"1", "true", "yes", "set"}:
        return True
    if lowered in {"0", "false", "no", "unset"}:
        return False
    return None


_GTPV2_MESSAGE_NAMES: dict[int, str] = {
    1: "Echo Request",
    2: "Echo Response",
    32: "Create Session",
    33: "Create Session",
    34: "Modify Bearer",
    35: "Modify Bearer",
    36: "Delete Session",
    37: "Delete Session",
    38: "Change Notification",
    39: "Change Notification",
    64: "Modify Bearer Command",
    65: "Modify Bearer Failure Indication",
    66: "Delete Bearer Command",
    67: "Delete Bearer Failure Indication",
    68: "Bearer Resource Command",
    69: "Bearer Resource Failure Indication",
    70: "DL Data Notification Failure",
    95: "Create Bearer",
    96: "Create Bearer",
    97: "Update Bearer",
    98: "Update Bearer",
    99: "Delete Bearer",
    100: "Delete Bearer",
    101: "Delete PDN Connection Set",
    102: "Delete PDN Connection Set",
    128: "Identification",
    129: "Identification",
    130: "Context",
    131: "Context",
    132: "Context Acknowledge",
    133: "Forward Relocation",
    134: "Forward Relocation",
    135: "Forward Relocation Complete Notification",
    136: "Forward Relocation Complete Acknowledge",
    139: "Relocation Cancel",
    140: "Relocation Cancel",
    149: "Detach Notification",
    150: "Detach Acknowledge",
    151: "CS Paging Indication",
    162: "Suspend Notification",
    163: "Suspend Acknowledge",
    164: "Resume Notification",
    165: "Resume Acknowledge",
    166: "Create Indirect Data Forwarding Tunnel",
    167: "Create Indirect Data Forwarding Tunnel",
    168: "Delete Indirect Data Forwarding Tunnel",
    169: "Delete Indirect Data Forwarding Tunnel",
    170: "Release Access Bearers",
    171: "Release Access Bearers",
    176: "Downlink Data Notification",
    177: "Downlink Data Notification Ack",
    179: "PGW Restart Notification",
    180: "PGW Restart Notification Ack",
    200: "Update PDN Connection Set",
    201: "Update PDN Connection Set",
    211: "Modify Access Bearers",
    212: "Modify Access Bearers",
}

_GTPV2_REQUEST_CODES: frozenset[int] = frozenset([
    1,32,34,36,38,64,66,68,95,97,99,101,128,130,133,135,139,149,151,
    162,164,166,168,170,176,179,200,211,
])


def _gtpv2_message_label(code: int) -> str:
    base = _GTPV2_MESSAGE_NAMES.get(code)
    if base is None:
        return f"GTPv2 Message {code}"
    if code in _GTPV2_REQUEST_CODES:
        return f"{base} Request ({code})"
    return f"{base} Response ({code})"


_KNOWN_NE_ROLES: frozenset[str] = frozenset([
    "ue", "gnb", "enb", "mme", "sgw", "pgw", "hss", "pcrf", "msc", "dns",
    "amf", "smf", "upf", "ausf", "udm", "udr", "pcf", "chf", "dra",
    "p-cscf", "i-cscf", "s-cscf", "as", "sbc", "ocs", "ofcs",
])

# Maps protocol-level role strings (from resolver) to display abbreviations
_ROLE_DISPLAY: dict[str, str] = {
    "ue": "UE",
    "gnb": "gNB",
    "enb": "eNB",
    "mme": "MME",
    "sgw": "SGW",
    "pgw": "PGW",
    "hss": "HSS",
    "pcrf": "PCRF",
    "msc": "MSC",
    "dns": "DNS",
    "amf": "AMF",
    "smf": "SMF",
    "upf": "UPF",
    "ausf": "AUSF",
    "udm": "UDM",
    "udr": "UDR",
    "pcf": "PCF",
    "chf": "CHF",
    "dra": "DRA",
    "p-cscf": "P-CSCF",
    "i-cscf": "I-CSCF",
    "s-cscf": "S-CSCF",
    "as": "AS",
    "sbc": "SBC",
    "ocs": "OCS",
    "ofcs": "OFCS",
    # protocol-name based roles from resolver/normalizer
    "diameter": "DIA-NE",
    "gtpc": "GTP-NE",
    "gtpu": "GTP-NE",
    "sip": "SIP-NE",
    "http2": "SBI-NE",
    "pfcp": "PFCP-NE",
    "s1ap": "eNB",
    "ngap": "gNB",
    "sccp": "SS7-NE",
    "m3ua": "SS7-NE",
}


_DIAMETER_COMMAND_NAMES: dict[int, str] = {
    257: "Capabilities-Exchange",
    258: "Re-Auth",
    271: "Accounting",
    272: "Credit-Control",
    274: "Abort-Session",
    275: "Session-Termination",
    280: "Device-Watchdog",
    282: "Disconnect-Peer",
    300: "User-Authorization",
    301: "Server-Assignment",
    302: "Location-Info",
    303: "Multimedia-Auth",
    304: "Registration-Termination",
    305: "Push-Profile",
    306: "User-Data",
    307: "Profile-Update",
    308: "Subscribe-Notifications",
    309: "Push-Notification",
    310: "Bootstrapping-Info",
    311: "Message-Process",
    312: "Diameter-EAP",
    313: "AA",
    314: "ST",
    315: "AS",
    316: "Update-Location",
    317: "Cancel-Location",
    318: "Authentication-Information",
    319: "Insert-Subscriber-Data",
    320: "Delete-Subscriber-Data",
    321: "Purge-UE",
    322: "Reset",
    323: "Notify",
    324: "ME-Identity-Check",
    325: "Update-Location",
    326: "Delete-Subscriber-Data",
    8388622: "Re-Auth",
    8388620: "Spending-Limit",
}


def _diameter_command_label(code: int, is_request: bool | None) -> str:
    base = _DIAMETER_COMMAND_NAMES.get(code)
    if base is None:
        return f"Diameter Command {code}"
    if is_request is True:
        return f"{base} Request ({code})"
    if is_request is False:
        return f"{base} Answer ({code})"
    return f"{base} ({code})"


def _http_status_label(code: int) -> str:
    try:
        phrase = HTTPStatus(code).phrase
    except ValueError:
        phrase = ""
    if phrase:
        return f"HTTP {code} {phrase}"
    return f"HTTP {code}"


def _label_for_endpoint(endpoint: dict[str, Any] | None) -> str:
    if not endpoint:
        return "unknown"

    ip = _to_text(endpoint.get("ip"))
    hostname = _to_text(endpoint.get("hostname"))
    alias = _to_text(endpoint.get("alias"))
    role = _to_text(endpoint.get("role"))

    name = None
    for candidate in (hostname, alias):
        if candidate and candidate != ip:
            name = candidate
            break

    if name and ip:
        return f"{name} ({ip})"
    if ip:
        return ip
    if name:
        return name
    if role:
        return role
    return "unknown"


def _endpoint_key(endpoint: dict[str, Any] | None) -> str:
    if not endpoint:
        return "unknown"
    for key in ("alias", "role", "hostname", "ip"):
        value = endpoint.get(key)
        if value:
            return f"{key}:{value}"
    return "unknown"


def _event_name(packet: dict[str, Any]) -> str:
    message = packet.get("message") or {}
    fields = message.get("fields") or {}

    message_name = _to_text(fields.get("message_name"))
    if message_name:
        return message_name

    diameter_request = _bool_from_field(fields.get("diameter.flags.request"))
    if diameter_request is None:
        diameter_request = _bool_from_field(fields.get("diameter.flags.request_tree"))

    command_code = _to_int(fields.get("command_code") or fields.get("diameter.cmd.code"))
    if command_code is not None:
        return _diameter_command_label(command_code, diameter_request)

    http_status = _to_int(fields.get("http.response.code") or fields.get("http2.headers.status"))
    if http_status is not None:
        return _http_status_label(http_status)

    gtpv2_type = _to_int(fields.get("gtpv2.message_type"))
    if gtpv2_type is not None:
        return _gtpv2_message_label(gtpv2_type)

    candidates = (
        "nas_eps.message_type",
        "pfcp.message_type",
        "ngap.procedureCode",
        "http2.headers.path",
    )
    for key in candidates:
        value = fields.get(key)
        if value not in (None, ""):
            return str(value)
    protocol = message.get("protocol") or packet.get("top_protocol") or "signal"
    return str(protocol).upper()


def _event_status(packet: dict[str, Any], event_name: str) -> str:
    message = packet.get("message") or {}
    fields = message.get("fields") or {}

    result_code = _to_int(fields.get("diameter.Result-Code") or fields.get("diameter.result_code"))
    if result_code is not None and result_code >= 3000:
        return "error"

    http_status = _to_int(fields.get("http.response.code") or fields.get("http2.headers.status"))
    if http_status is not None and http_status >= 400:
        return "error"

    diameter_request = _bool_from_field(fields.get("diameter.flags.request"))
    if diameter_request is None:
        diameter_request = _bool_from_field(fields.get("diameter.flags.request_tree"))
    if diameter_request is True:
        return "request"
    if diameter_request is False:
        return "response"

    anomalies = packet.get("anomalies") or []
    if anomalies:
        return "error"

    lowered = event_name.lower()
    if any(token in lowered for token in ("reject", "failure", "error", "timeout")):
        return "error"
    if any(token in lowered for token in ("response", "answer", "resp", "ack")):
        return "response"
    return "request"


def _profile_family(profile: str) -> str:
    lowered = profile.lower()
    if lowered.startswith("5g"):
        return "5g"
    if lowered.startswith("lte"):
        return "lte"
    if lowered.startswith("2g3g"):
        return "2g3g"
    if "ims" in lowered or "voice" in lowered:
        return "ims"
    return "generic"


def _lane_priority_for_family(family: str) -> dict[str, int]:
    if family == "5g":
        return {
            "ue": 10,
            "gnb": 20,
            "amf": 30,
            "smf": 40,
            "upf": 50,
            "ausf": 60,
            "udm": 70,
            "udr": 80,
            "pcf": 90,
            "chf": 100,
            "dns": 110,
        }
    if family == "lte":
        return {
            "ue": 10,
            "enb": 20,
            "mme": 30,
            "sgw": 40,
            "pgw": 50,
            "hss": 60,
            "pcrf": 70,
            "msc": 80,
            "dns": 90,
        }
    if family == "ims":
        return {
            "ue": 10,
            "p-cscf": 20,
            "i-cscf": 30,
            "s-cscf": 40,
            "hss": 50,
            "as": 60,
            "sbc": 70,
        }
    return {
        "ue": 10,
        "gnb": 20,
        "enb": 20,
        "mme": 30,
        "amf": 30,
        "smf": 40,
        "upf": 50,
        "sgw": 40,
        "pgw": 50,
        "hss": 60,
        "ausf": 60,
        "udm": 70,
        "udr": 80,
        "pcf": 90,
        "chf": 100,
        "dns": 110,
    }


def _lane_order(nodes: list[dict[str, Any]], *, profile: str) -> list[dict[str, Any]]:
    role_priority = _lane_priority_for_family(_profile_family(profile))

    def key_fn(item: dict[str, Any]) -> tuple[int, str, str]:
        role = str(item.get("role") or "").lower()
        return (role_priority.get(role, 500), str(item.get("label") or ""), item["id"])

    return sorted(nodes, key=key_fn)


def _base_message_name(name: str) -> str:
    lowered = name.lower().strip()
    for token in (" response", " answer", " resp", " request", " req"):
        if lowered.endswith(token):
            return lowered[: -len(token)].strip()
    return lowered


def _message_is_response(name: str, status: str) -> bool:
    lowered = name.lower().strip()
    if status == "response":
        return True
    response_hints = (
        " response",
        " answer",
        " ack",
        " complete",
        "accept",
        "success",
        " aia",
    )
    return any(hint in lowered for hint in response_hints)


def _correlation_id(packet: dict[str, Any]) -> str | None:
    fields = ((packet.get("message") or {}).get("fields") or {})
    candidates = (
        "diameter.hopbyhopid",
        "diameter.endtoendid",
        "http2.streamid",
        "gtpv2.seq_no",
        "gtpv2.sequence_number",
        "pfcp.sequence_number",
        "nas_eps.procedure_transaction_id",
        "ngap.AMF_UE_NGAP_ID",
        "ngap.RAN_UE_NGAP_ID",
    )
    for key in candidates:
        value = _to_text(fields.get(key))
        if value:
            return f"{key}:{value}"
    return None


def _phase_kind(event_name: str, status: str, profile_family: str) -> tuple[str, str]:
    lowered = event_name.lower()

    if profile_family == "5g":
        if any(token in lowered for token in ("registration", "initial ue", "ng setup")):
            return ("registration", "Registration")
        if any(token in lowered for token in ("nsmf", "createsmcontext", "pdu session", "pfcp")):
            return ("session_setup", "Session Setup")
    elif profile_family == "lte":
        if any(token in lowered for token in ("attach", "initial ue", "downlink nas transport")):
            return ("registration", "Registration")
        if any(token in lowered for token in ("create session", "modify bearer", "gtpv2")):
            return ("session_setup", "Session Setup")
    elif profile_family == "ims":
        if any(token in lowered for token in ("register", "401", "407", "challenge")):
            return ("authentication", "Authentication")
        if any(token in lowered for token in ("invite", "183", "180", "200 ok", "bye")):
            return ("signaling", "Call Signaling")

    if any(token in lowered for token in ("reject", "fail", "error", "timeout", "401", "403", "500")):
        return ("failure", "Failure / Retry")
    if any(token in lowered for token in ("auth", "air", "aia", "aka", "eap")):
        return ("authentication", "Authentication")
    if any(token in lowered for token in ("security", "smc", "security mode")):
        return ("security", "Security Mode")
    if any(token in lowered for token in ("session", "createsmcontext", "create session", "pfcp")):
        return ("session_setup", "Session Setup")
    if any(token in lowered for token in ("register", "attach", "initial ue")):
        return ("registration", "Registration")
    if any(token in lowered for token in ("release", "detach", "delete session")):
        return ("release", "Release")
    if status == "error":
        return ("failure", "Failure / Retry")
    return ("signaling", "Signaling")


def _build_phases(events: list[dict[str, Any]], *, profile: str) -> list[dict[str, Any]]:
    if not events:
        return []

    phases: list[dict[str, Any]] = []
    family = _profile_family(profile)
    current_kind, current_label = _phase_kind(
        str(events[0].get("message_name") or ""),
        str(events[0].get("status") or ""),
        family,
    )
    start_event = str(events[0]["id"])
    previous_event_id = str(events[0]["id"])

    for event in events[1:]:
        kind, label = _phase_kind(
            str(event.get("message_name") or ""),
            str(event.get("status") or ""),
            family,
        )
        if kind != current_kind:
            phases.append(
                {
                    "id": f"phase-{len(phases) + 1}",
                    "label": current_label,
                    "start_event": start_event,
                    "end_event": previous_event_id,
                    "kind": current_kind,
                }
            )
            current_kind = kind
            current_label = label
            start_event = str(event["id"])
        previous_event_id = str(event["id"])

    end_event = str(events[-1]["id"])
    phases.append(
        {
            "id": f"phase-{len(phases) + 1}",
            "label": current_label,
            "start_event": start_event,
            "end_event": end_event,
            "kind": current_kind,
        }
    )
    return phases


def _correlate_request_response(events: list[dict[str, Any]]) -> None:
    pending: dict[tuple[str, str, str, str], list[str]] = {}

    def _enqueue(key: tuple[str, str, str, str], event_id: str) -> None:
        pending.setdefault(key, []).append(event_id)

    def _dequeue(key: tuple[str, str, str, str]) -> str | None:
        queue = pending.get(key)
        if not queue:
            return None
        event_id = queue.pop(0)
        if not queue:
            pending.pop(key, None)
        return event_id

    for event in events:
        protocol = str(event.get("protocol") or "")
        correlation_id = str(event.get("correlation_id") or "")
        base = _base_message_name(str(event.get("message_name") or ""))
        src = str(event.get("src_node") or "")
        dst = str(event.get("dst_node") or "")
        status = str(event.get("status") or "")

        strict_key = correlation_id or base
        req_key = (protocol, strict_key, src, dst)
        resp_key = (protocol, strict_key, dst, src)
        loose_req_key = (protocol, base, src, dst)
        loose_resp_key = (protocol, base, dst, src)

        if not _message_is_response(str(event.get("message_name") or ""), status) and not event.get("is_response"):
            _enqueue(req_key, str(event["id"]))
            if req_key != loose_req_key:
                _enqueue(loose_req_key, str(event["id"]))
            continue

        paired_id = _dequeue(resp_key)
        if paired_id is None and resp_key != loose_resp_key:
            paired_id = _dequeue(loose_resp_key)
        if paired_id is None:
            continue

        event["is_response"] = True
        event["is_request"] = False
        event["status"] = "response" if status != "error" else status
        event["message_type"] = event["status"]
        event["paired_event_id"] = paired_id
        for candidate in events:
            if str(candidate.get("id")) == paired_id:
                candidate["paired_event_id"] = str(event["id"])
                break


def build_flow_model(
    packets: list[dict[str, Any]],
    *,
    capture_file: str,
    profile: str,
    privacy_profile: str | None,
    max_events: int = 120,
    title: str | None = None,
    collapse_repeats: bool = True,
) -> dict[str, Any]:
    warnings: list[str] = []
    total_packets = len(packets)
    event_packets = packets[: max_events if max_events > 0 else len(packets)]
    if max_events > 0 and total_packets > max_events:
        warnings.append(
            f"Flow visualization truncated to {max_events} events out of {total_packets}."
        )

    node_map: dict[str, dict[str, Any]] = {}
    events: list[dict[str, Any]] = []
    last_signature: tuple[str, str, str, str] | None = None

    for index, packet in enumerate(event_packets, start=1):
        src = packet.get("src") or {}
        dst = packet.get("dst") or {}
        src_key = _endpoint_key(src)
        dst_key = _endpoint_key(dst)

        if src_key not in node_map:
            node_map[src_key] = {
                "id": src_key,
                "label": _label_for_endpoint(src),
                "role": src.get("role"),
                "family": "endpoint",
                "endpoint_keys": [src_key],
                "pseudonymized": bool(src.get("alias") and src.get("alias") != src.get("ip")),
                "sort_key": src_key,
                "lane_index": 0,
            }
        if dst_key not in node_map:
            node_map[dst_key] = {
                "id": dst_key,
                "label": _label_for_endpoint(dst),
                "role": dst.get("role"),
                "family": "endpoint",
                "endpoint_keys": [dst_key],
                "pseudonymized": bool(dst.get("alias") and dst.get("alias") != dst.get("ip")),
                "sort_key": dst_key,
                "lane_index": 0,
            }

        message_name = _event_name(packet)
        status = _event_status(packet, message_name)
        relative_ms = _to_ms(packet.get("time_rel_ms"))
        correlation_id = _correlation_id(packet)
        protocol_name = (packet.get("message") or {}).get("protocol") or packet.get("top_protocol")
        signature = (str(src_key), str(dst_key), str(message_name), str(protocol_name))

        if collapse_repeats and events and signature == last_signature:
            events[-1]["repeat_count"] = int(events[-1].get("repeat_count") or 1) + 1
            events[-1]["raw_refs"].append({"packet_no": packet.get("packet_no")})
            events[-1]["detail_label"] = f"pkt {events[-1].get('packet_no')}..{packet.get('packet_no')}"
            continue

        events.append(
            {
                "id": f"event-{len(events) + 1}",
                "packet_no": packet.get("packet_no"),
                "timestamp": packet.get("time_epoch"),
                "relative_ms": relative_ms,
                "src_node": src_key,
                "dst_node": dst_key,
                "protocol_family": packet.get("top_protocol"),
                "protocol": protocol_name,
                "message_name": message_name,
                "message_type": status,
                "status": status,
                "direction": "outbound",
                "is_request": status == "request",
                "is_response": status == "response",
                "is_error": status == "error",
                "correlation_id": correlation_id,
                "session_key": None,
                "short_label": message_name,
                "detail_label": f"pkt {packet.get('packet_no')}",
                "notes": packet.get("anomalies") or [],
                "emphasis": "high" if status == "error" else "normal",
                "raw_refs": [{"packet_no": packet.get("packet_no")}],
                "repeat_count": 1,
                "paired_event_id": None,
            }
        )
        last_signature = signature

    _correlate_request_response(events)
    phases = _build_phases(events, profile=profile)

    nodes = _lane_order(list(node_map.values()), profile=profile)
    for lane_index, node in enumerate(nodes):
        node["lane_index"] = lane_index

    relative_values = [e["relative_ms"] for e in events if isinstance(e.get("relative_ms"), (int, float))]
    time_span_ms = 0.0
    if relative_values:
        time_span_ms = float(max(relative_values) - min(relative_values))

    return {
        "capture_file": capture_file,
        "profile": profile,
        "privacy_profile": privacy_profile,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "title": title or "Signaling Flow",
        "subtitle": f"{profile} | {privacy_profile or 'privacy-default'}",
        "packet_count_total": total_packets,
        "event_count_rendered": len(events),
        "event_count_uncollapsed": len(event_packets),
        "time_span_ms": round(time_span_ms, 3),
        "nodes": nodes,
        "events": events,
        "phases": phases,
        "warnings": warnings,
    }


def render_flow_svg(flow: dict[str, Any], *, width: int = 1600) -> str:
    nodes = flow.get("nodes") or []
    events = flow.get("events") or []
    phases = flow.get("phases") or []
    title = escape(str(flow.get("title") or "Signaling Flow"))
    subtitle = escape(str(flow.get("subtitle") or ""))

    left_margin = 130
    right_margin = 90
    top_margin = 170
    row_height = 34
    footer_height = 60

    lane_count = max(1, len(nodes))
    lane_spacing = max(220, int((width - left_margin - right_margin) / lane_count))
    canvas_width = max(width, left_margin + right_margin + lane_spacing * lane_count)
    # 3 header lines: role + name + ip  →  need 36 px for labels (y=62,74,86) before lane_top=100
    lane_label_y = 62
    height = top_margin + max(1, len(events)) * row_height + footer_height

    node_x: dict[str, int] = {}
    for i, node in enumerate(nodes):
        node_x[node["id"]] = left_margin + i * lane_spacing

    event_y: dict[str, int] = {}
    for idx, event in enumerate(events, start=1):
        event_y[str(event.get("id"))] = top_margin + (idx - 1) * row_height

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_width}" height="{height}" viewBox="0 0 {canvas_width} {height}">')
    parts.append("<defs>")
    parts.append("<marker id=\"arrow\" markerWidth=\"10\" markerHeight=\"7\" refX=\"9\" refY=\"3.5\" orient=\"auto\">")
    parts.append("<polygon points=\"0 0, 10 3.5, 0 7\" fill=\"#3d5a80\" />")
    parts.append("</marker>")
    parts.append("<marker id=\"arrow-error\" markerWidth=\"10\" markerHeight=\"7\" refX=\"9\" refY=\"3.5\" orient=\"auto\">")
    parts.append("<polygon points=\"0 0, 10 3.5, 0 7\" fill=\"#b22222\" />")
    parts.append("</marker>")
    parts.append("</defs>")

    parts.append('<rect x="0" y="0" width="100%" height="100%" fill="#f8f8f2" />')
    parts.append(f'<text x="24" y="30" font-family="Georgia, serif" font-size="20" fill="#1f2a44">{title}</text>')
    parts.append(f'<text x="24" y="56" font-family="Georgia, serif" font-size="13" fill="#3a4a66">{subtitle}</text>')
    parts.append(f'<line x1="18" y1="64" x2="{canvas_width - 18}" y2="64" stroke="#d7dde8" stroke-width="1" />')

    parts.append('<g class="lanes">')
    lane_top = 100
    lane_bottom = top_margin + max(1, len(events)) * row_height
    for node in nodes:
        x = node_x[node["id"]]
        node_label = str(node.get("label") or node["id"])
        role_raw = str(node.get("role") or "").lower().strip()
        role_tag = _ROLE_DISPLAY.get(role_raw)

        if " (" in node_label and node_label.endswith(")"):
            split_at = node_label.rfind(" (")
            main = _truncate(node_label[:split_at], 28)
            ip_part = _truncate(node_label[split_at + 2 : -1], 24)
            if role_tag:
                label_lines = [(role_tag, True), (main, False), (f"({ip_part})", False)]
            else:
                label_lines = [(main, False), (f"({ip_part})", False)]
        else:
            if role_tag:
                label_lines = [(role_tag, True), (_truncate(node_label, 32), False)]
            else:
                label_lines = [(_truncate(node_label, 34), False)]

        for line_index, (text, bold) in enumerate(label_lines):
            weight = 'font-weight="bold" ' if bold else ''
            color = '"#0a1a3a"' if bold else '"#1f2a44"'
            parts.append(
                f'<text x="{x}" y="{lane_label_y + line_index * 13}" text-anchor="middle" '
                f'{weight}font-family="Georgia, serif" font-size="11" fill={color}>{escape(text)}</text>'
            )
        parts.append(f'<line x1="{x}" y1="{lane_top}" x2="{x}" y2="{lane_bottom}" stroke="#b9c1cc" stroke-width="1.2" />')
    parts.append("</g>")

    phase_color = {
        "registration": "#e8f1ff",
        "authentication": "#eef8e9",
        "security": "#fff7dd",
        "session_setup": "#f3ecff",
        "failure": "#ffecec",
        "release": "#f0f0f0",
        "signaling": "#f7f7f7",
    }
    parts.append('<g class="phases">')
    for phase in phases:
        start_y = event_y.get(str(phase.get("start_event")))
        end_y = event_y.get(str(phase.get("end_event")))
        if start_y is None or end_y is None:
            continue
        y = min(start_y, end_y) - 12
        h = abs(end_y - start_y) + row_height
        kind = str(phase.get("kind") or "signaling")
        fill = phase_color.get(kind, "#f7f7f7")
        label = escape(str(phase.get("label") or "Phase"))
        parts.append(
            f'<rect x="8" y="{y}" width="108" height="{h}" fill="{fill}" stroke="#d2d8e2" stroke-width="0.8" rx="4" />'
        )
        parts.append(
            f'<text x="14" y="{y + 16}" font-family="Georgia, serif" font-size="10" fill="#2f3a4d">{label}</text>'
        )
    parts.append("</g>")

    parts.append('<g class="events">')
    for idx, event in enumerate(events, start=1):
        y = event_y[str(event.get("id"))]
        src = event.get("src_node")
        dst = event.get("dst_node")
        src_x = node_x.get(str(src), left_margin)
        dst_x = node_x.get(str(dst), src_x)

        color = "#3d5a80"
        marker = "url(#arrow)"
        if event.get("is_error"):
            color = "#b22222"
            marker = "url(#arrow-error)"
        elif event.get("is_response"):
            color = "#2a9d8f"

        packet_no = event.get("packet_no")
        repeat_count = int(event.get("repeat_count") or 1)
        label_text = str(event.get("short_label") or event.get("message_name") or "event")
        if repeat_count > 1:
            label_text = f"{label_text} x{repeat_count}"
        label_text = _truncate(label_text, 56)
        label = escape(label_text)
        protocol = escape(str(event.get("protocol") or ""))
        status = escape(str(event.get("status") or ""))
        session_key = escape(str(event.get("session_key") or ""))

        if src_x == dst_x:
            loop_to = src_x + 48
            parts.append(
                f'<path d="M {src_x} {y} C {loop_to} {y-8}, {loop_to} {y+8}, {src_x} {y+16}" '
                f'stroke="{color}" stroke-width="1.7" fill="none" marker-end="{marker}" '
                f'data-event-id="{escape(str(event.get("id")))}" data-packet-no="{escape(str(packet_no))}" '
                f'data-protocol="{protocol}" data-session-key="{session_key}" '
                f'data-src="{escape(str(src))}" data-dst="{escape(str(dst))}" data-status="{status}" />'
            )
            # clamp to canvas so the label never lands outside the viewport
            text_x = min(loop_to + 8, canvas_width - 120)
            text_anchor = "start"
            label_y = y - 8
        else:
            parts.append(
                f'<line x1="{src_x}" y1="{y}" x2="{dst_x}" y2="{y}" stroke="{color}" stroke-width="1.7" '
                f'marker-end="{marker}" data-event-id="{escape(str(event.get("id")))}" '
                f'data-packet-no="{escape(str(packet_no))}" data-protocol="{protocol}" '
                f'data-session-key="{session_key}" data-src="{escape(str(src))}" '
                f'data-dst="{escape(str(dst))}" data-status="{status}" />'
            )
            text_x = int((src_x + dst_x) / 2)
            text_anchor = "middle"
            # place label above for left-to-right arrows, below for right-to-left so
            # that bidirectional pairs between the same two nodes don't overlap
            label_y = y - 8 if src_x <= dst_x else y + 18

        meta_label = f"#{packet_no}" if packet_no is not None else ""
        parts.append(
            f'<text x="{text_x}" y="{label_y}" text-anchor="{text_anchor}" font-family="Georgia, serif" '
            f'font-size="11" fill="#2c3647">{label}</text>'
        )
        # Packet-Nr. rechts-bündig an left_margin-Kante, klar rechts vom Phase-Band (endet ~x=116)
        parts.append(
            f'<text x="{left_margin - 4}" y="{y + 4}" text-anchor="end" font-family="Courier New, monospace" font-size="10" fill="#5b6473">{escape(meta_label)}</text>'
        )

    parts.append("</g>")

    rendered = flow.get("event_count_rendered", 0)
    expanded = flow.get("event_count_uncollapsed", rendered)
    footer = f"Rendered events: {rendered} (from {expanded}) / packets: {flow.get('packet_count_total', 0)}"
    parts.append(f'<text x="24" y="{height - 20}" font-family="Georgia, serif" font-size="12" fill="#3a4a66">{escape(footer)}</text>')
    parts.append("</svg>")
    return "\n".join(parts)
