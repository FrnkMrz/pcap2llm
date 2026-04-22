from __future__ import annotations

from datetime import datetime, timezone
from html import escape
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


def _label_for_endpoint(endpoint: dict[str, Any] | None) -> str:
    if not endpoint:
        return "unknown"
    for key in ("alias", "role", "hostname", "ip"):
        value = endpoint.get(key)
        if value:
            return str(value)
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
    candidates = (
        "message_name",
        "command_code",
        "diameter.cmd.code",
        "nas_eps.message_type",
        "gtpv2.message_type",
        "pfcp.message_type",
        "ngap.procedureCode",
        "http2.headers.path",
        "http.response.code",
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
        value = fields.get(key)
        if value not in (None, ""):
            return f"{key}:{value}"
    return None


def _phase_kind(event_name: str, status: str) -> tuple[str, str]:
    lowered = event_name.lower()
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


def _build_phases(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not events:
        return []

    phases: list[dict[str, Any]] = []
    current_kind, current_label = _phase_kind(str(events[0].get("message_name") or ""), str(events[0].get("status") or ""))
    start_event = str(events[0]["id"])
    previous_event_id = str(events[0]["id"])

    for event in events[1:]:
        kind, label = _phase_kind(str(event.get("message_name") or ""), str(event.get("status") or ""))
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
    pending: dict[tuple[str, str, str, str], str] = {}
    for event in events:
        protocol = str(event.get("protocol") or "")
        correlation_id = str(event.get("correlation_id") or "")
        base = _base_message_name(str(event.get("message_name") or ""))
        src = str(event.get("src_node") or "")
        dst = str(event.get("dst_node") or "")

        req_key = (protocol, correlation_id or base, src, dst)
        resp_key = (protocol, correlation_id or base, dst, src)

        if event.get("is_request"):
            pending[req_key] = str(event["id"])
            continue

        if event.get("is_response") and resp_key in pending:
            paired_id = pending.pop(resp_key)
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
    phases = _build_phases(events)

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

    left_margin = 120
    right_margin = 80
    top_margin = 120
    row_height = 34
    lane_label_y = 42
    footer_height = 60

    lane_count = max(1, len(nodes))
    lane_spacing = max(160, int((width - left_margin - right_margin) / lane_count))
    height = top_margin + max(1, len(events)) * row_height + footer_height

    node_x: dict[str, int] = {}
    for i, node in enumerate(nodes):
        node_x[node["id"]] = left_margin + i * lane_spacing

    event_y: dict[str, int] = {}
    for idx, event in enumerate(events, start=1):
        event_y[str(event.get("id"))] = top_margin + (idx - 1) * row_height

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">')
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

    parts.append('<g class="lanes">')
    lane_top = 70
    lane_bottom = top_margin + max(1, len(events)) * row_height
    for node in nodes:
        x = node_x[node["id"]]
        label = escape(str(node.get("label") or node["id"]))
        parts.append(f'<text x="{x}" y="{lane_label_y}" text-anchor="middle" font-family="Georgia, serif" font-size="12" fill="#1f2a44">{label}</text>')
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
            f'<rect x="8" y="{y}" width="100" height="{h}" fill="{fill}" stroke="#d2d8e2" stroke-width="0.8" rx="4" />'
        )
        parts.append(
            f'<text x="14" y="{y + 16}" font-family="Georgia, serif" font-size="10" fill="#2f3a4d">{label}</text>'
        )
    parts.append("</g>")

    parts.append('<g class="events">')
    for idx, event in enumerate(events, start=1):
        y = top_margin + (idx - 1) * row_height
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
            text_x = loop_to + 8
            text_anchor = "start"
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

        meta_label = f"#{packet_no}" if packet_no is not None else ""
        parts.append(
            f'<text x="{text_x}" y="{y - 5}" text-anchor="{text_anchor}" font-family="Georgia, serif" '
            f'font-size="11" fill="#2c3647">{label}</text>'
        )
        parts.append(
            f'<text x="32" y="{y + 4}" font-family="Courier New, monospace" font-size="10" fill="#5b6473">{escape(meta_label)}</text>'
        )

    parts.append("</g>")

    rendered = flow.get("event_count_rendered", 0)
    expanded = flow.get("event_count_uncollapsed", rendered)
    footer = f"Rendered events: {rendered} (from {expanded}) / packets: {flow.get('packet_count_total', 0)}"
    parts.append(f'<text x="24" y="{height - 20}" font-family="Georgia, serif" font-size="12" fill="#3a4a66">{escape(footer)}</text>')
    parts.append("</svg>")
    return "\n".join(parts)
