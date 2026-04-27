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
    if value is None:
        return None
    try:
        text = str(value).strip()
    except Exception:
        return None
    if not text:
        return None
    try:
        # int(x, 0) handles "0x..", "0b..", "0o.." and decimal transparently
        return int(text, 0)
    except (TypeError, ValueError):
        try:
            return int(float(text))
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


def _timestamp_datetime(value: Any) -> datetime | None:
    text = _to_text(value)
    if text is None:
        return None
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        try:
            normalized = text.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)


def _format_timestamp_time(value: Any) -> str | None:
    dt = _timestamp_datetime(value)
    if dt is None:
        return None
    return dt.strftime("%H:%M:%S")


def _format_timestamp_date(value: Any) -> str | None:
    dt = _timestamp_datetime(value)
    if dt is None:
        return None
    return dt.strftime("%d.%m.%Y")


def _format_event_time_span(first_ms: float | None, last_ms: float | None) -> str | None:
    if first_ms is None and last_ms is None:
        return None
    if first_ms is None:
        return f"t={last_ms:.1f} ms"
    if last_ms is None or abs(last_ms - first_ms) < 0.05:
        return f"t={first_ms:.1f} ms"
    return f"t={first_ms:.1f}-{last_ms:.1f} ms"


def _event_tooltip_text(
    event: dict[str, Any],
    *,
    src: str,
    dst: str,
    label_text: str,
    packet_no: Any,
    first_no: Any,
    last_no: Any,
    repeat_count: int,
) -> str:
    parts: list[str] = []

    if repeat_count > 1 and first_no is not None and last_no is not None:
        parts.append(f"pkts {first_no}-{last_no} (x{repeat_count})")
    elif packet_no is not None:
        parts.append(f"pkt #{packet_no}")
    else:
        parts.append("event")

    parts.append(f"{src} → {dst}")

    protocol = _to_text(event.get("protocol"))
    if protocol and protocol.lower() != label_text.strip().lower():
        parts.append(protocol)

    status = _to_text(event.get("status"))
    if status == "error":
        parts.append("error")
    elif status == "response":
        parts.append("response")

    time_span = _format_event_time_span(
        _to_ms(event.get("first_relative_ms")),
        _to_ms(event.get("last_relative_ms")),
    )
    if time_span:
        parts.append(time_span)

    correlation_id = _to_text(event.get("correlation_id"))
    if correlation_id:
        parts.append(f"corr={correlation_id}")

    session_key = _to_text(event.get("session_key"))
    if session_key:
        parts.append(f"session={session_key}")

    return " | ".join(parts)


def _find_nested_field(container: Any, target_keys: tuple[str, ...], max_depth: int = 12) -> Any:
    """Walk nested dict/list structures and return the first value whose key is in target_keys.

    Needed because verbatim protocols (NGAP) keep tshark's tree structure, so
    fields like `ngap.procedureCode` or `nas_5gs.mm.message_type` sit inside
    `..._tree` sub-dicts rather than at the top level.
    """
    if not isinstance(container, (dict, list)) or max_depth <= 0:
        return None
    if isinstance(container, dict):
        for key in target_keys:
            if key in container and not isinstance(container[key], (dict, list)):
                return container[key]
        for value in container.values():
            found = _find_nested_field(value, target_keys, max_depth - 1)
            if found is not None:
                return found
        return None
    for item in container:
        found = _find_nested_field(item, target_keys, max_depth - 1)
        if found is not None:
            return found
    return None


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
    1: "Echo",
    2: "Echo",
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


_GTPV2_CAUSE_NAMES: dict[int, str] = {
    16: "Request accepted",
    17: "Request accepted partially",
    18: "New PDN type network preference",
    19: "New PDN type single address bearer only",
    64: "Context Not Found",
    65: "Invalid Message Format",
    66: "Version not supported",
    67: "Invalid length",
    68: "Service not supported",
    69: "Mandatory IE incorrect",
    70: "Mandatory IE missing",
    72: "System failure",
    73: "No resources available",
    78: "Missing or unknown APN",
    82: "Denied in RAT",
    83: "Preferred PDN type not supported",
    84: "All dynamic addresses are occupied",
    86: "Protocol type not supported",
    87: "UE not responding",
    88: "UE refuses",
    89: "Service denied",
    91: "No memory available",
    92: "User authentication failed",
    93: "APN access denied - no subscription",
    94: "Request rejected",
    96: "IMSI/IMEI not known",
    100: "Remote peer not responding",
    101: "Collision with network initiated request",
    103: "Conditional IE missing",
    110: "Temporarily rejected (handover in progress)",
    113: "APN Congestion",
    116: "Multiple PDN connections for APN not allowed",
}


def _gtpv2_cause_suffix(code: int) -> str:
    name = _GTPV2_CAUSE_NAMES.get(code)
    if code <= 17:
        return f" · Cause {code}"
    if name:
        return f" · Cause {code} ({name})"
    return f" · Cause {code}"


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


_NGAP_PROCEDURE_NAMES: dict[int, str] = {
    0: "AMFConfigurationUpdate",
    4: "HandoverCancel",
    5: "HandoverPreparation",
    6: "HandoverResourceAllocation",
    7: "InitialContextSetup",
    9: "NGReset",
    10: "NGSetup",
    11: "PathSwitchRequest",
    12: "PDUSessionResourceModify",
    13: "PDUSessionResourceModifyIndication",
    14: "PDUSessionResourceRelease",
    15: "PDUSessionResourceSetup",
    16: "PWSCancel",
    17: "RANConfigurationUpdate",
    18: "UEContextModification",
    19: "UEContextRelease",
    20: "UERadioCapabilityCheck",
    21: "WriteReplaceWarning",
    22: "AMFStatusIndication",
    23: "CellTrafficTrace",
    24: "DeactivateTrace",
    25: "DownlinkNASTransport",
    26: "DownlinkNonUEAssociatedNRPPaTransport",
    27: "DownlinkRANConfigurationTransfer",
    28: "DownlinkRANStatusTransfer",
    29: "DownlinkUEAssociatedNRPPaTransport",
    30: "ErrorIndication",
    31: "HandoverNotification",
    32: "InitialUEMessage",
    33: "LocationReportingControl",
    34: "LocationReportingFailureIndication",
    35: "LocationReport",
    36: "NASNonDeliveryIndication",
    37: "OverloadStart",
    38: "OverloadStop",
    39: "Paging",
    40: "PDUSessionResourceNotify",
    41: "PrivateMessage",
    42: "PWSFailureIndication",
    43: "PWSRestartIndication",
    44: "RerouteNASRequest",
    45: "RRCInactiveTransitionReport",
    46: "TraceFailureIndication",
    47: "TraceStart",
    48: "UEContextReleaseRequest",
    49: "UEInformationTransfer",
    50: "UERadioCapabilityInfoIndication",
    51: "UETNLABindingRelease",
    52: "UplinkNASTransport",
    53: "UplinkNonUEAssociatedNRPPaTransport",
    54: "UplinkRANConfigurationTransfer",
    55: "UplinkRANStatusTransfer",
    56: "UplinkUEAssociatedNRPPaTransport",
}


def _ngap_procedure_label(code: int) -> str:
    name = _NGAP_PROCEDURE_NAMES.get(code)
    return f"{name} ({code})" if name else f"NGAP Procedure {code}"


_NAS_EPS_MESSAGE_NAMES: dict[int, str] = {
    0x41: "Attach Request",
    0x42: "Attach Accept",
    0x43: "Attach Complete",
    0x44: "Attach Reject",
    0x45: "Detach Request",
    0x46: "Detach Accept",
    0x48: "Tracking Area Update Request",
    0x49: "Tracking Area Update Accept",
    0x4a: "Tracking Area Update Complete",
    0x4b: "Tracking Area Update Reject",
    0x4c: "Extended Service Request",
    0x4d: "Service Reject",
    0x4e: "Service Request",
    0x50: "GUTI Reallocation Command",
    0x51: "GUTI Reallocation Complete",
    0x52: "Authentication Request",
    0x53: "Authentication Response",
    0x54: "Authentication Reject",
    0x5c: "Authentication Failure",
    0x55: "Identity Request",
    0x56: "Identity Response",
    0x5d: "Security Mode Command",
    0x5e: "Security Mode Complete",
    0x5f: "Security Mode Reject",
    0x60: "EMM Status",
    0x61: "EMM Information",
    0x62: "Downlink NAS Transport",
    0x63: "Uplink NAS Transport",
    0xc1: "Activate Default EPS Bearer Context Request",
    0xc2: "Activate Default EPS Bearer Context Accept",
    0xc3: "Activate Default EPS Bearer Context Reject",
    0xc5: "Activate Dedicated EPS Bearer Context Request",
    0xc6: "Activate Dedicated EPS Bearer Context Accept",
    0xc7: "Activate Dedicated EPS Bearer Context Reject",
    0xc9: "Modify EPS Bearer Context Request",
    0xca: "Modify EPS Bearer Context Accept",
    0xcb: "Modify EPS Bearer Context Reject",
    0xcd: "Deactivate EPS Bearer Context Request",
    0xce: "Deactivate EPS Bearer Context Accept",
    0xd0: "PDN Connectivity Request",
    0xd1: "PDN Connectivity Reject",
    0xd2: "PDN Disconnect Request",
    0xd3: "PDN Disconnect Reject",
}


_NAS_5GS_MESSAGE_NAMES: dict[int, str] = {
    0x41: "Registration Request",
    0x42: "Registration Accept",
    0x43: "Registration Complete",
    0x44: "Registration Reject",
    0x45: "Deregistration Request (UE originating)",
    0x46: "Deregistration Accept (UE originating)",
    0x47: "Deregistration Request (UE terminated)",
    0x48: "Deregistration Accept (UE terminated)",
    0x4c: "Service Request",
    0x4d: "Service Reject",
    0x4e: "Service Accept",
    0x54: "Configuration Update Command",
    0x55: "Configuration Update Complete",
    0x56: "Authentication Request",
    0x57: "Authentication Response",
    0x58: "Authentication Reject",
    0x59: "Authentication Failure",
    0x5a: "Authentication Result",
    0x5b: "Identity Request",
    0x5c: "Identity Response",
    0x5d: "Security Mode Command",
    0x5e: "Security Mode Complete",
    0x5f: "Security Mode Reject",
    0x64: "5GMM Status",
    0x65: "Notification",
    0x66: "Notification Response",
    0x67: "UL NAS Transport",
    0x68: "DL NAS Transport",
    0xc1: "PDU Session Establishment Request",
    0xc2: "PDU Session Establishment Accept",
    0xc3: "PDU Session Establishment Reject",
    0xc5: "PDU Session Authentication Command",
    0xc6: "PDU Session Authentication Complete",
    0xc7: "PDU Session Authentication Result",
    0xc9: "PDU Session Modification Request",
    0xca: "PDU Session Modification Reject",
    0xcb: "PDU Session Modification Command",
    0xcc: "PDU Session Modification Complete",
    0xcd: "PDU Session Modification Command Reject",
    0xd1: "PDU Session Release Request",
    0xd2: "PDU Session Release Reject",
    0xd3: "PDU Session Release Command",
    0xd4: "PDU Session Release Complete",
    0xd6: "5GSM Status",
}


def _nas_label(code: int, variant: str) -> str:
    table = _NAS_5GS_MESSAGE_NAMES if variant == "5gs" else _NAS_EPS_MESSAGE_NAMES
    name = table.get(code)
    return name if name else f"NAS-{variant.upper()} 0x{code:02x}"


_DNS_QUERY_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    65: "HTTPS",
    255: "ANY",
}

_DNS_RCODE_NAMES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}


def _dns_label(
    qry_name: str | None,
    qry_type: int | None,
    is_response: bool,
    rcode: int | None,
    answer_count: int | None,
) -> str:
    type_name = _DNS_QUERY_TYPES.get(qry_type) if qry_type is not None else None
    type_str = type_name or (f"TYPE{qry_type}" if qry_type is not None else "")
    name = qry_name.rstrip(".") if qry_name else ""
    base = f"DNS {type_str} {name}".strip() or "DNS"
    if not is_response:
        return base
    rcode_name = _DNS_RCODE_NAMES.get(rcode) if rcode is not None else None
    if rcode and rcode != 0:
        return f"{base} · {rcode_name or f'rcode {rcode}'}"
    if answer_count:
        return f"{base} · NOERROR ({answer_count} ans)"
    return f"{base} · NOERROR"


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
    # alias > ip > hostname > role: IP is a unique host identifier; role alone
    # causes collisions when multiple NEs share the same protocol role (e.g. ngap)
    for key in ("alias", "ip", "hostname", "role"):
        value = endpoint.get(key)
        if value:
            return f"{key}:{value}"
    return "unknown"


def _first_text_field(fields: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = fields.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            value = next((item for item in value if item not in (None, "")), None)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _diameter_route_identities(packet: dict[str, Any]) -> tuple[str | None, str | None]:
    fields = (packet.get("message") or {}).get("fields") or {}
    if not isinstance(fields, dict):
        return None, None
    origin = _first_text_field(fields, ("diameter.Origin-Host", "diameter.origin_host"))
    destination = _first_text_field(fields, ("diameter.Destination-Host", "diameter.destination_host"))
    return origin, destination


def _with_endpoint_alias(endpoint: dict[str, Any], alias: str | None) -> dict[str, Any]:
    enriched = dict(endpoint)
    if not alias:
        return enriched
    enriched.setdefault("alias", alias)
    return enriched


def _event_name(packet: dict[str, Any]) -> str:
    message = packet.get("message") or {}
    fields = message.get("fields") or {}

    message_name = _to_text(fields.get("message_name"))
    if message_name:
        # If Diameter, append the Result-Code so answers carry outcome in the label
        result_code = _to_int(fields.get("diameter.Result-Code") or fields.get("diameter.result_code"))
        if result_code is not None and "result" not in message_name.lower():
            return f"{message_name} · Result {result_code}"
        return message_name

    diameter_request = _bool_from_field(fields.get("diameter.flags.request"))
    if diameter_request is None:
        diameter_request = _bool_from_field(fields.get("diameter.flags.request_tree"))

    command_code = _to_int(fields.get("command_code") or fields.get("diameter.cmd.code"))
    if command_code is not None:
        label = _diameter_command_label(command_code, diameter_request)
        result_code = _to_int(fields.get("diameter.Result-Code") or fields.get("diameter.result_code"))
        if result_code is not None and diameter_request is not True:
            return f"{label} · Result {result_code}"
        return label

    # HTTP/2: prefer method + path on requests (":status" marks responses)
    http_status = _to_int(fields.get("http.response.code") or fields.get("http2.headers.status"))
    if http_status is not None:
        return _http_status_label(http_status)

    http2_method = _to_text(fields.get("http2.headers.method"))
    http2_path = _to_text(fields.get("http2.headers.path"))
    if http2_method and http2_path:
        return f"{http2_method} {http2_path}"
    if http2_path:
        return http2_path

    gtpv2_type = _to_int(fields.get("gtpv2.message_type"))
    if gtpv2_type is not None:
        label = _gtpv2_message_label(gtpv2_type)
        if gtpv2_type not in _GTPV2_REQUEST_CODES:
            cause = _to_int(_find_nested_field(fields, ("gtpv2.cause",)))
            if cause is not None:
                label = f"{label}{_gtpv2_cause_suffix(cause)}"
        return label

    nas_eps_type = _to_int(
        fields.get("nas_eps.message_type")
        or _find_nested_field(fields, ("nas_eps.message_type",))
    )
    if nas_eps_type is not None:
        return _nas_label(nas_eps_type, "eps")

    nas_5gs_type = _to_int(
        fields.get("nas_5gs.mm.message_type")
        or fields.get("nas_5gs.sm.message_type")
        or _find_nested_field(
            fields,
            ("nas_5gs.mm.message_type", "nas_5gs.sm.message_type", "nas-5gs.mm.message_type", "nas-5gs.sm.message_type"),
        )
    )
    if nas_5gs_type is not None:
        return _nas_label(nas_5gs_type, "5gs")

    ngap_proc = _to_int(
        fields.get("ngap.procedureCode")
        or _find_nested_field(fields, ("ngap.procedureCode",))
    )
    if ngap_proc is not None:
        return _ngap_procedure_label(ngap_proc)

    pfcp_type = fields.get("pfcp.message_type")
    if pfcp_type not in (None, ""):
        return str(pfcp_type)

    dns_flag_response = _to_int(_find_nested_field(fields, ("dns.flags.response",)))
    dns_qry_name = _to_text(_find_nested_field(fields, ("dns.qry.name",)))
    if dns_flag_response is not None or dns_qry_name:
        qry_type = _to_int(_find_nested_field(fields, ("dns.qry.type",)))
        rcode = _to_int(_find_nested_field(fields, ("dns.flags.rcode",)))
        answers = _to_int(
            fields.get("dns.count.answers")
            or _find_nested_field(fields, ("dns.count.answers",))
        )
        is_response = dns_flag_response == 1 or (
            dns_flag_response is None and rcode is not None and rcode != 0
        )
        return _dns_label(
            qry_name=dns_qry_name,
            qry_type=qry_type,
            is_response=is_response,
            rcode=rcode,
            answer_count=answers,
        )

    # Last resort: use frame_protocols to identify the application protocol even when
    # the analysis profile only extracts transport-layer fields (e.g. lte-core + SIP pcap)
    frame_protos = packet.get("frame_protocols") or []
    _FRAME_PROTO_LABELS: dict[str, str] = {
        "sip": "SIP",
        "ngap": "NGAP",
        "nas-5gs": "NAS-5GS",
        "nas_5gs": "NAS-5GS",
        "s1ap": "S1AP",
        "pfcp": "PFCP",
        "gtpv2": "GTPv2",
        "gtpv1": "GTPv1",
        "diameter": "Diameter",
        "radius": "RADIUS",
        "sccp": "SCCP",
        "map": "MAP",
        "isup": "ISUP",
    }
    for proto in reversed(frame_protos):
        label = _FRAME_PROTO_LABELS.get(proto.lower())
        if label:
            return label

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

    # GTPv2 cause ≥ 64 is an error (3GPP TS 29.274 clause 8.4) — cause lives
    # nested inside "Cause:..." sub-dicts when Diameter/GTPv2 is verbatim.
    gtpv2_cause = _to_int(_find_nested_field(fields, ("gtpv2.cause",)))
    if gtpv2_cause is not None and gtpv2_cause >= 64:
        return "error"

    # DNS rcode > 0 (NXDOMAIN, SERVFAIL, REFUSED, …) = error
    dns_rcode = _to_int(_find_nested_field(fields, ("dns.flags.rcode",)))
    if dns_rcode is not None and dns_rcode != 0:
        return "error"
    dns_response = _to_int(_find_nested_field(fields, ("dns.flags.response",)))
    if dns_response == 1:
        return "response"
    if dns_response == 0:
        return "request"

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
        "gtpv2.seq",
        "gtpv2.seq_no",
        "gtpv2.sequence_number",
        "pfcp.sequence_number",
        "nas_eps.procedure_transaction_id",
        "ngap.AMF_UE_NGAP_ID",
        "ngap.RAN_UE_NGAP_ID",
        "dns.id",
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
    diameter_alias_by_ip: dict[str, str] = {}
    events: list[dict[str, Any]] = []
    last_signature: tuple[str, str, str, str] | None = None

    for index, packet in enumerate(event_packets, start=1):
        src = packet.get("src") or {}
        dst = packet.get("dst") or {}
        origin_host, destination_host = _diameter_route_identities(packet)
        src = _with_endpoint_alias(src, origin_host)
        dst = _with_endpoint_alias(dst, destination_host)
        for endpoint, alias in ((src, origin_host), (dst, destination_host)):
            ip = _to_text(endpoint.get("ip"))
            if ip and alias:
                diameter_alias_by_ip[ip] = alias
        for endpoint in (src, dst):
            ip = _to_text(endpoint.get("ip"))
            if ip and ip in diameter_alias_by_ip and not endpoint.get("alias"):
                endpoint["alias"] = diameter_alias_by_ip[ip]
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
            last_event = events[-1]
            last_event["repeat_count"] = int(last_event.get("repeat_count") or 1) + 1
            last_event["raw_refs"].append({"packet_no": packet.get("packet_no")})
            last_event["last_packet_no"] = packet.get("packet_no")
            last_event["last_relative_ms"] = relative_ms
            first_no = last_event.get("first_packet_no")
            last_no = last_event.get("last_packet_no")
            last_event["detail_label"] = f"pkt {first_no}..{last_no}"
            continue

        events.append(
            {
                "id": f"event-{len(events) + 1}",
                "packet_no": packet.get("packet_no"),
                "first_packet_no": packet.get("packet_no"),
                "last_packet_no": packet.get("packet_no"),
                "timestamp": packet.get("time_epoch"),
                "relative_ms": relative_ms,
                "first_relative_ms": relative_ms,
                "last_relative_ms": relative_ms,
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

    first_packet_date = None
    if packets:
        first_packet_date = _format_timestamp_date(packets[0].get("time_epoch"))

    subtitle = f"{profile} | {privacy_profile or 'privacy-default'}"
    if first_packet_date:
        subtitle = f"{subtitle} | first packet {first_packet_date}"

    return {
        "capture_file": capture_file,
        "profile": profile,
        "privacy_profile": privacy_profile,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "title": title or "Signaling Flow",
        "subtitle": subtitle,
        "first_packet_date": first_packet_date,
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
    title = escape(str(flow.get("title") or "Signaling Flow"))
    subtitle = escape(str(flow.get("subtitle") or ""))

    left_margin = 130
    right_margin = 90
    top_margin = 210
    row_height = 34
    footer_height = 60

    lane_count = max(1, len(nodes))
    lane_spacing = max(220, int((width - left_margin - right_margin) / lane_count))
    canvas_width = max(width, left_margin + right_margin + lane_spacing * lane_count)
    # Keep lane labels well below the title/subtitle block. Three-line
    # endpoint labels (role + name + IP) occupy y=112..138 before lane_top=154.
    lane_label_y = 112
    height = top_margin + max(1, len(events)) * row_height + footer_height

    node_x: dict[str, int] = {}
    for i, node in enumerate(nodes):
        node_x[node["id"]] = left_margin + i * lane_spacing
    node_label_by_id = {str(node["id"]): str(node.get("label") or node["id"]) for node in nodes}

    event_y: dict[str, int] = {}
    for idx, event in enumerate(events, start=1):
        event_y[str(event.get("id"))] = top_margin + (idx - 1) * row_height

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_width}" height="{height}" '
        f'viewBox="0 0 {canvas_width} {height}" role="img" aria-labelledby="flow-title flow-desc">'
    )
    parts.append(f'<title id="flow-title">{title}</title>')
    parts.append(
        f'<desc id="flow-desc">{subtitle} — '
        f'{len(nodes)} lanes, {len(events)} events.</desc>'
    )
    parts.append("<defs>")
    parts.append(
        "<style>"
        ".event-tooltip{display:none;pointer-events:none;font-family:Georgia,serif;"
        "font-size:11px;fill:#111827;paint-order:stroke;stroke:#f8f8f2;"
        "stroke-width:4px;stroke-linejoin:round;}"
        ".event:hover .event-tooltip{display:inline;}"
        "</style>"
    )
    parts.append("<marker id=\"arrow\" markerWidth=\"10\" markerHeight=\"7\" refX=\"9\" refY=\"3.5\" orient=\"auto\">")
    parts.append("<polygon points=\"0 0, 10 3.5, 0 7\" fill=\"#3d5a80\" />")
    parts.append("</marker>")
    parts.append("<marker id=\"arrow-error\" markerWidth=\"10\" markerHeight=\"7\" refX=\"9\" refY=\"3.5\" orient=\"auto\">")
    parts.append("<polygon points=\"0 0, 10 3.5, 0 7\" fill=\"#b22222\" />")
    parts.append("</marker>")
    parts.append("</defs>")

    parts.append('<rect x="0" y="0" width="100%" height="100%" fill="#f8f8f2" />')
    parts.append(f'<text x="24" y="32" font-family="Georgia, serif" font-size="20" fill="#1f2a44">{title}</text>')
    parts.append(f'<text x="24" y="60" font-family="Georgia, serif" font-size="13" fill="#3a4a66">{subtitle}</text>')
    parts.append(f'<line x1="18" y1="82" x2="{canvas_width - 18}" y2="82" stroke="#d7dde8" stroke-width="1" />')

    parts.append('<g class="lanes">')
    lane_top = 154
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

    parts.append('<g class="events">')
    for idx, event in enumerate(events, start=1):
        y = event_y[str(event.get("id"))]
        src = event.get("src_node")
        dst = event.get("dst_node")
        src_x = node_x.get(str(src), left_margin)
        dst_x = node_x.get(str(dst), src_x)
        src_label = node_label_by_id.get(str(src), str(src))
        dst_label = node_label_by_id.get(str(dst), str(dst))

        color = "#3d5a80"
        marker = "url(#arrow)"
        if event.get("is_error"):
            color = "#b22222"
            marker = "url(#arrow-error)"
        elif event.get("is_response"):
            color = "#2a9d8f"

        packet_no = event.get("packet_no")
        first_no = event.get("first_packet_no") if event.get("first_packet_no") is not None else packet_no
        last_no = event.get("last_packet_no") if event.get("last_packet_no") is not None else packet_no
        repeat_count = int(event.get("repeat_count") or 1)
        label_text = str(event.get("short_label") or event.get("message_name") or "event")
        if repeat_count > 1:
            label_text = f"{label_text} x{repeat_count} (pkts {first_no}–{last_no})"
        label_text = _truncate(label_text, 64)
        label = escape(label_text)
        protocol = escape(str(event.get("protocol") or ""))
        status = escape(str(event.get("status") or ""))
        session_key = escape(str(event.get("session_key") or ""))

        tooltip_text = _event_tooltip_text(
            event,
            src=src_label,
            dst=dst_label,
            label_text=label_text,
            packet_no=packet_no,
            first_no=first_no,
            last_no=last_no,
            repeat_count=repeat_count,
        )
        tooltip = escape(tooltip_text)
        visible_tooltip = escape(_truncate(tooltip_text, 96))
        event_attrs = (
            f'data-event-id="{escape(str(event.get("id")))}" data-packet-no="{escape(str(packet_no))}" '
            f'data-protocol="{protocol}" data-session-key="{session_key}" '
            f'data-src="{escape(str(src))}" data-dst="{escape(str(dst))}" data-status="{status}"'
        )
        visible_attrs = f'stroke="{color}" stroke-width="1.7" marker-end="{marker}"'

        parts.append(f'<g class="event" cursor="help" {event_attrs}>')
        parts.append(f'<title>{tooltip}</title>')

        if src_x == dst_x:
            loop_to = src_x + 48
            path_d = f"M {src_x} {y} C {loop_to} {y-8}, {loop_to} {y+8}, {src_x} {y+16}"
            parts.append(
                f'<path d="{path_d}" fill="none" stroke="transparent" stroke-width="18" '
                f'pointer-events="stroke" />'
            )
            parts.append(
                f'<path d="{path_d}" fill="none" {visible_attrs} pointer-events="none" />'
            )
            # clamp to canvas so the label never lands outside the viewport
            text_x = min(loop_to + 8, canvas_width - 120)
            text_anchor = "start"
            label_y = y - 8
        else:
            parts.append(
                f'<line x1="{src_x}" y1="{y}" x2="{dst_x}" y2="{y}" '
                f'stroke="transparent" stroke-width="18" pointer-events="stroke" />'
            )
            parts.append(
                f'<line x1="{src_x}" y1="{y}" x2="{dst_x}" y2="{y}" '
                f'{visible_attrs} pointer-events="none" />'
            )
            text_x = int((src_x + dst_x) / 2)
            text_anchor = "middle"
            # always above the arrow — guarantees row_height (34px) gap between
            # any two consecutive labels regardless of direction combination
            label_y = y - 8

        packet_clock = _format_timestamp_time(event.get("timestamp"))
        meta_parts = []
        if packet_no is not None:
            meta_parts.append(f"#{packet_no}")
        if packet_clock:
            meta_parts.append(packet_clock)
        meta_label = " ".join(meta_parts)
        parts.append(
            f'<text x="{text_x}" y="{label_y}" text-anchor="{text_anchor}" font-family="Georgia, serif" '
            f'font-size="11" fill="#2c3647">{label}</text>'
        )
        parts.append(
            f'<text x="{left_margin - 4}" y="{y + 4}" text-anchor="end" font-family="Courier New, monospace" font-size="10" fill="#5b6473">{escape(meta_label)}</text>'
        )
        parts.append(
            f'<text class="event-tooltip" x="{text_x}" y="{label_y - 14}" text-anchor="{text_anchor}">{visible_tooltip}</text>'
        )
        parts.append("</g>")

    parts.append("</g>")

    rendered = flow.get("event_count_rendered", 0)
    expanded = flow.get("event_count_uncollapsed", rendered)
    footer = f"Rendered events: {rendered} (from {expanded}) / packets: {flow.get('packet_count_total', 0)}"
    parts.append(f'<text x="24" y="{height - 20}" font-family="Georgia, serif" font-size="12" fill="#3a4a66">{escape(footer)}</text>')
    parts.append("</svg>")
    return "\n".join(parts)
