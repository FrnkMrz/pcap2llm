from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Pattern


IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    r"|(?i:\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b)"
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URI_RE = re.compile(r"(?:https?://|sip:|tel:|www\.)", re.IGNORECASE)
TOKEN_RE = re.compile(r"(?:bearer\s+[A-Za-z0-9._-]+|authorization|cookie|token=)", re.IGNORECASE)
IMSI_RE = re.compile(r"\b\d{14,16}\b")
MSISDN_RE = re.compile(r"\b(?:\+?\d{10,15})\b")


CANONICAL_PRIVACY_CLASSES: dict[str, dict[str, Any]] = {
    "network_address": {
        "maps_to": ["ip", "hostname"],
        "notes": "IP addresses, DNS names, hostnames, and related network identifiers.",
    },
    "subscriber_identifier": {
        "maps_to": ["subscriber_id", "imsi", "msisdn"],
        "notes": "Subscriber and account identifiers such as IMSI, MSISDN, SUPI, SUCI.",
    },
    "device_identifier": {
        "maps_to": ["imei"],
        "notes": "Device identifiers such as IMEI or PEI.",
    },
    "operator_internal_name": {
        "maps_to": ["hostname", "diameter_identity", "apn_dnn"],
        "notes": "Operator-internal node names, Diameter identities, APN/DNN labels.",
    },
    "application_secret": {
        "maps_to": ["token"],
        "notes": "Credentials, cookies, bearer tokens, or opaque secrets.",
    },
    "payload_text": {
        "maps_to": ["payload_text", "email", "uri"],
        "notes": "Free-form text or embedded customer content that may contain PII or URLs.",
    },
}


@dataclass(frozen=True)
class PrivacyRule:
    data_class: str
    path_keywords: tuple[str, ...] = ()
    value_patterns: tuple[Pattern[str], ...] = ()
    protocols: tuple[str, ...] = ()

    def matches(self, *, path: str, value: Any, protocol: str | None) -> bool:
        normalized_path = path.lower()
        if self.protocols and (protocol or "").lower() not in self.protocols:
            return False
        if self.path_keywords and any(keyword in normalized_path for keyword in self.path_keywords):
            return True
        text = "" if value is None else str(value)
        return any(pattern.search(text) for pattern in self.value_patterns)


_GENERIC_RULES: tuple[PrivacyRule, ...] = (
    PrivacyRule("ip", path_keywords=("src.ip", "dst.ip", ".ip", "ipv4", "ipv6"), value_patterns=(IP_RE,)),
    PrivacyRule("hostname", path_keywords=("hostname", "dns.qry.name", "authority", "src_name", "dst_name", "host")),
    PrivacyRule("imsi", path_keywords=("imsi", "supi", "suci")),
    PrivacyRule("msisdn", path_keywords=("msisdn",)),
    PrivacyRule("imei", path_keywords=("imei", "pei")),
    PrivacyRule("payload_text", path_keywords=("payload", ".text", "message.body", "blob")),
    PrivacyRule("email", path_keywords=("email",), value_patterns=(EMAIL_RE,)),
    PrivacyRule("token", path_keywords=("token", "bearer", "cookie", "authorization"), value_patterns=(TOKEN_RE,)),
    PrivacyRule("uri", path_keywords=("uri", "url", "referer", ":path"), value_patterns=(URI_RE,)),
    PrivacyRule("apn_dnn", path_keywords=("apn", "dnn")),
    PrivacyRule("hostname", path_keywords=("dns",)),
    PrivacyRule("diameter_identity", path_keywords=("realm", "origin_host", "destination_host", "origin-realm", "destination-realm")),
    PrivacyRule("distinguished_name", path_keywords=("distinguished", ".dn", "issuer", "subject")),
    PrivacyRule("subscriber_id", path_keywords=("subscriber", ".id", "ueid")),
)

_PROTOCOL_RULES: tuple[PrivacyRule, ...] = (
    PrivacyRule("diameter_identity", path_keywords=("diameter.origin_host", "diameter.destination_host"), protocols=("diameter",)),
    PrivacyRule("subscriber_id", path_keywords=("diameter.user_name", "diameter.subscription"), protocols=("diameter",)),
    PrivacyRule("apn_dnn", path_keywords=("gtpv2.apn", "nas_eps.apn", "nas_5gs.dnn", "pfcp.dnn"), protocols=("gtpv2", "nas-eps", "nas-5gs", "pfcp")),
    PrivacyRule("subscriber_id", path_keywords=("ngap.suci", "ngap.supi", "nas_5gs.suci", "nas_5gs.supi"), protocols=("ngap", "nas-5gs")),
    PrivacyRule("imei", path_keywords=("ngap.pei", "nas_5gs.pei"), protocols=("ngap", "nas-5gs")),
    PrivacyRule("token", path_keywords=("http2.header.authorization", "http2.header.cookie"), protocols=("http2",)),
    PrivacyRule("hostname", path_keywords=("http2.header.:authority", "dns.qry.name"), protocols=("http2", "dns")),
    PrivacyRule("uri", path_keywords=("http2.header.:path", "http2.header.referer"), protocols=("http2",)),
)


class PrivacyPolicyEngine:
    version = "2026-04-08"

    def classify(self, path: str, value: Any, packet: dict[str, Any] | None = None) -> str | None:
        normalized_path = path.lower()
        if normalized_path.startswith(("privacy.modes", "privacy_modes")):
            return None

        protocol = None
        if isinstance(packet, dict):
            protocol = str(packet.get("top_protocol") or packet.get("message", {}).get("protocol") or "").lower()

        for rule in _PROTOCOL_RULES:
            if rule.matches(path=path, value=value, protocol=protocol):
                return rule.data_class

        for rule in _GENERIC_RULES:
            if rule.matches(path=path, value=value, protocol=protocol):
                return rule.data_class

        if not isinstance(value, str):
            return None

        lowered = value.lower()
        if any(marker in lowered for marker in ("imsi", "msisdn", "imei", "supi", "suci")):
            return "payload_text"
        if EMAIL_RE.search(value) or URI_RE.search(value) or TOKEN_RE.search(value):
            return "payload_text"
        if IMSI_RE.search(value) or MSISDN_RE.search(value):
            return "payload_text"
        return None

    def metadata(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "rule_layers": ["generic", "protocol-aware", "privacy-profile-overrides"],
            "canonical_classes": CANONICAL_PRIVACY_CLASSES,
        }
