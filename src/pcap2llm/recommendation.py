from __future__ import annotations

import re
from collections import Counter
from typing import Any

from pcap2llm.models import InspectResult, ProfileDefinition, SelectorMetadata

# Protocols that alone do NOT indicate a specific network domain.
# They may add a small bonus only when a domain-specific signal is already present.
_TRANSPORT_PROTOCOLS: frozenset[str] = frozenset({
    "ip", "ipv6", "tcp", "udp", "sctp", "eth", "ethertype", "vlan", "frame", "data",
    "arp", "ppp", "pppoe", "pppoed", "pppoes", "lcp", "ipcp", "pap", "chap",
    "wlan", "wlan_radio", "radiotap", "ieee80211", "llc", "sll", "null", "loop",
})

# Raw-only protocol presence is weaker than counted packets, but still strong
# enough to influence discovery when the decoded top protocols are too coarse.
_RAW_PROTOCOL_FACTOR = 0.85
_RAW_TRANSPORT_FACTOR = 0.35
_DOMAIN_BONUS_SCALE = 3.0

_PROTOCOL_EQUIVALENTS: dict[str, tuple[str, ...]] = {
    "bssap": ("bssap", "gsm_a.bssap"),
    "bssap+": ("bssap+", "bssap", "gsm_a.bssap"),
    "bssmap": ("bssmap", "gsm_a.bssmap"),
    "dtap": ("dtap", "gsm_a.dtap", "gsm_dtap"),
    "http": ("http", "http2"),
    "map": ("map", "gsm_map"),
    "mtp3": ("mtp3", "mtp3mg"),
    "nas-eps": ("nas-eps", "nas_eps"),
    "nas-5gs": ("nas-5gs", "nas_5gs"),
    "ss7": ("ss7", "m3ua", "m2pa", "mtp"),
}

_LEGACY_PARTNER_PROTOCOLS: frozenset[str] = frozenset({
    "bssap", "bssmap", "sccp", "mtp3", "ss7", "map", "tcap", "cap", "gtpv1",
})

_STRONG_LEGACY_COMBOS: tuple[frozenset[str], ...] = (
    frozenset({"bssap", "dtap", "sccp"}),
    frozenset({"bssap", "dtap", "mtp3"}),
    frozenset({"bssap", "dtap", "ss7"}),
    frozenset({"map", "tcap", "sccp"}),
    frozenset({"sccp", "tcap", "mtp3"}),
    frozenset({"sccp", "tcap", "ss7"}),
    frozenset({"gtpv1", "udp"}),
)

_VOICE_INDICATOR_PROTOCOLS: frozenset[str] = frozenset({"sip", "sdp", "dns", "rtp", "rtcp"})
_HYBRID_VOICE_PROFILES: frozenset[str] = frozenset({"vonr-n1-n2-voice", "vonr-ims-core"})
_IMS_DIAMETER_PROFILES: frozenset[str] = frozenset({
    "volte-diameter-cx",
    "volte-diameter-rx",
    "volte-diameter-sh",
    "volte-ims-core",
})
_IMS_CORE_PROFILES: frozenset[str] = frozenset({"volte-ims-core", "vonr-ims-core"})
_VOICE_SIP_PROFILES: frozenset[str] = frozenset({
    "volte-sbc",
    "volte-sip",
    "volte-sip-call",
    "volte-sip-register",
    "vonr-sbc",
    "vonr-sip",
    "vonr-sip-call",
    "vonr-sip-register",
})
_VOICE_DNS_PROFILES: frozenset[str] = frozenset({"volte-dns", "vonr-dns"})
_VOICE_CALL_PROTOCOLS: frozenset[str] = frozenset({"sdp", "rtp", "rtcp"})
_REGISTER_HINT_TOKENS: frozenset[str] = frozenset({
    "pcscf", "scscf", "icscf", "registrar", "register", "auth", "aka", "hss",
})
_SBC_HINT_TOKENS: frozenset[str] = frozenset({
    "sbc", "ibcf", "ebcf", "session-border", "border-controller",
})

# ---------------------------------------------------------------------------
# core-name-resolution: telecom naming patterns
# ---------------------------------------------------------------------------

# Regex for MCC/MNC operator naming: mnc001.mcc262 (2-3 MNC digits, 3 MCC digits).
# More precise than a bare "mnc" substring which matches unrelated words (e.g. "mnemonic").
_MCC_MNC_RE: re.Pattern = re.compile(r"mnc\d{2,3}\.mcc\d{3}", re.IGNORECASE)

# Strong naming evidence: list of (substring_or_None, compiled_regex_or_None, reason_text).
# Each entry contributes exactly one strong hit when it matches the dns_blob.
# Multiple entries may match the same blob — that is intentional (more hits = stronger evidence).
_CORE_NAMING_STRONG: list = [
    # (substring,          regex,       reason_text)
    ("3gppnetwork.org",    None,        "3gppnetwork.org naming detected"),
    (".gprs",              None,        ".gprs operator domain detected"),
    ("epc.mnc",            None,        "APN/EPC MCC/MNC naming pattern detected"),
    ("ims.mnc",            None,        "IMS MCC/MNC naming pattern detected"),
    ("5gc.mnc",            None,        "5GC MCC/MNC naming pattern detected"),
    ("apn.epc",            None,        "APN resolution naming detected"),
    # TOPON prefix: 3GPP TS 29.303 DNS-based node resolution for GTPv1/v2 routing.
    # Present only in operator-internal traces — very strong telecom signal.
    ("topon.",             None,        "TOPON DNS routing prefix detected (3GPP node resolution)"),
    (None,                 _MCC_MNC_RE, "MCC/MNC operator naming pattern detected"),
]

# Supporting naming evidence: (substring, reason_text).
# Each match contributes one supporting hit.  Supporting evidence alone contributes a
# smaller score bonus and appears as a summarized reason rather than per-hit detail.
_CORE_NAMING_SUPPORTING: list = [
    # (substring,   reason_text)
    ("pcscf",       "P-CSCF IMS host naming"),
    ("scscf",       "S-CSCF IMS host naming"),
    ("icscf",       "I-CSCF IMS host naming"),
    ("mmtel",       "MMTel IMS service naming"),
    ("nrf.",        "5G NRF service naming"),
    ("amf.",        "5G AMF naming"),
    ("smf.",        "5G SMF naming"),
    ("udm.",        "5G UDM naming"),
    ("ausf.",       "5G AUSF naming"),
    ("nssf.",       "5G NSSF naming"),
    ("3gpp",        "3GPP naming context"),
    # EPC/LTE core node naming — commonly seen in operator DNS for GTP and Diameter
    ("pgw.",        "P-GW node naming"),
    ("sgw.",        "S-GW node naming"),
    ("mme.",        "MME node naming"),
    ("hss.",        "HSS node naming"),
    ("enb.",        "eNodeB naming"),
    ("gnb.",        "gNodeB naming"),
]
_LTE_ANCHOR_PROTOCOLS: frozenset[str] = frozenset({"s1ap", "diameter", "gtpv2"})
_IMS_HINT_TOKENS: frozenset[str] = frozenset({
    "ims", "cscf", "pcscf", "scscf", "icscf", "sbc", "tas", "bgcf", "as", "mmtel",
})
_LTE_S6A_HINT_TOKENS: frozenset[str] = frozenset({"s6a", "mme", "hss"})
_S5_S8_HINT_TOKENS: frozenset[str] = frozenset({"s5", "s8", "s5-s8", "pgw", "sgw", "spgw", "roaming"})
_S10_HINT_TOKENS: frozenset[str] = frozenset({"s10", "inter-mme", "relocation"})
_S11_HINT_TOKENS: frozenset[str] = frozenset({"s11", "mme", "sgw"})
_N26_HINT_TOKENS: frozenset[str] = frozenset({"n26", "interworking", "amf", "mme"})
_GENERIC_SBI_KEEP_PROFILES: frozenset[str] = frozenset({"5g-sbi", "5g-core"})
_SBI_PROFILE_HINTS: dict[str, frozenset[str]] = {
    "5g-n10": frozenset({"smf", "udm", "udr"}),
    "5g-n11": frozenset({"amf", "smf", "sm-context", "pdu"}),
    "5g-n12": frozenset({"amf", "ausf"}),
    "5g-n13": frozenset({"amf", "udm", "udr"}),
    "5g-n14": frozenset({"amf", "pcf"}),
    "5g-n15": frozenset({"amf", "pcf", "af"}),
    "5g-n16": frozenset({"smf", "pcf"}),
    "5g-n22": frozenset({"amf", "nssf"}),
    "5g-n40": frozenset({"smf", "nrf", "service"}),
    "5g-n8": frozenset({"udm", "ausf"}),
    "5g-sbi-auth": frozenset({"ausf", "udm", "udr", "auth"}),
    "vonr-policy": frozenset({"pcf", "policy", "ims"}),
    "vonr-sbi-auth": frozenset({"ausf", "auth", "ims"}),
    "vonr-sbi-pdu": frozenset({"smf", "pdu", "ims"}),
}

# Domain combo rules: (required_protocol_set, domain, base_score, summary_reason)
# Ordered: best match per domain wins. base_score assumes meaningful protocol
# evidence, with raw_protocols able to contribute when top_protocols are too flat.
_DOMAIN_COMBOS: list[tuple[frozenset[str], str, float, str]] = [
    # 5G SA Core — N1/N2/NAS
    (frozenset({"ngap", "nas-5gs", "sctp"}),  "5g-sa-core", 0.95, "ngap + nas-5gs + sctp = strong 5G N1/N2 signal"),
    (frozenset({"ngap", "nas-5gs"}),           "5g-sa-core", 0.88, "ngap + nas-5gs = 5G N1/N2 control-plane"),
    (frozenset({"ngap", "sctp"}),              "5g-sa-core", 0.80, "ngap + sctp = 5G N2 interface"),
    (frozenset({"ngap"}),                      "5g-sa-core", 0.55, "ngap detected"),
    (frozenset({"nas-5gs"}),                   "5g-sa-core", 0.45, "nas-5gs detected"),
    # 5G SA Core — SBI
    (frozenset({"http", "json"}),              "5g-sa-core-sbi", 0.65, "http + json = 5G SBI interface"),
    (frozenset({"http"}),                      "5g-sa-core-sbi", 0.40, "http detected (possible SBI)"),
    # LTE / EPC — radio core
    (frozenset({"s1ap", "nas-eps", "sctp"}),   "lte-eps", 0.95, "s1ap + nas-eps + sctp = strong LTE S1 signal"),
    (frozenset({"s1ap", "nas-eps"}),           "lte-eps", 0.88, "s1ap + nas-eps = LTE S1/NAS"),
    (frozenset({"s1ap", "sctp"}),              "lte-eps", 0.80, "s1ap + sctp = LTE S1 interface"),
    (frozenset({"s1ap"}),                      "lte-eps", 0.55, "s1ap detected"),
    # LTE / EPC — Diameter
    (frozenset({"diameter", "sctp"}),          "lte-eps", 0.72, "diameter + sctp = Diameter over SCTP (S6a / Cx / Rx)"),
    (frozenset({"diameter"}),                  "lte-eps", 0.50, "diameter detected"),
    # LTE / EPC — GTPv2
    (frozenset({"gtpv2", "udp"}),              "lte-eps", 0.70, "gtpv2 + udp = GTPv2-C (S11 / S5 / S8)"),
    (frozenset({"gtpv2"}),                     "lte-eps", 0.55, "gtpv2 detected"),
    # IMS / Voice
    (frozenset({"sip", "sdp"}),                "ims-voice", 0.90, "sip + sdp = active call flow"),
    (frozenset({"sip", "dns"}),                "ims-voice", 0.72, "sip + dns = IMS registration or discovery"),
    (frozenset({"sip"}),                       "ims-voice", 0.55, "sip detected"),
    # 2G/3G — only strong partner combinations should produce a real legacy hint
    (frozenset({"bssap", "dtap", "sccp"}),     "legacy-2g3g", 0.88, "bssap + dtap + sccp = strong GERAN/A-interface signal"),
    (frozenset({"bssap", "dtap", "mtp3"}),     "legacy-2g3g", 0.88, "bssap + dtap + mtp3 = strong GERAN/A-interface signal"),
    (frozenset({"bssap", "dtap", "ss7"}),      "legacy-2g3g", 0.84, "bssap + dtap + ss7 = strong GERAN/A-interface signal"),
    (frozenset({"map", "tcap", "sccp"}),       "legacy-2g3g", 0.92, "map + tcap + sccp = SS7/MAP core"),
    (frozenset({"sccp", "tcap", "mtp3"}),      "legacy-2g3g", 0.84, "sccp + tcap + mtp3 = legacy SS7 control plane"),
    (frozenset({"sccp", "tcap", "ss7"}),       "legacy-2g3g", 0.82, "sccp + tcap + ss7 = legacy SS7 control plane"),
    (frozenset({"sccp", "mtp3"}),              "legacy-2g3g", 0.52, "sccp + mtp3 = legacy SS7 transport/signaling"),
    (frozenset({"gtpv1", "udp"}),              "legacy-2g3g-gprs", 0.70, "gtpv1 + udp = 2G/3G GPRS Gn/Gp"),
    # DNS support
    (frozenset({"dns"}),                       "dns-support", 0.40, "dns detected"),
]

# Domains that suppress dns-support when co-present in infer_domains().
# The bare `dns` rule fires for any trace that has DNS traffic — including IMS,
# 5G, and LTE traces that use DNS as ancillary infrastructure.  When a primary
# telecom domain is already identified, dns-support adds no useful information
# and causes false state=mixed in _classification_state.
_DNS_SUPPORT_SUPPRESSORS: frozenset[str] = frozenset({
    "ims-voice",
    "5g-sa-core",
    "5g-sa-core-sbi",
    "lte-eps",
    "legacy-2g3g",
    "legacy-2g3g-gprs",
})


def _protocol_variants(protocol: str) -> tuple[str, ...]:
    return _PROTOCOL_EQUIVALENTS.get(protocol, (protocol,))


def _protocol_count(inspect_result: InspectResult, protocol: str) -> int:
    total = 0
    for variant in _protocol_variants(protocol):
        if variant in _TRANSPORT_PROTOCOLS:
            count = inspect_result.protocol_counts.get(variant, 0) or inspect_result.transport_counts.get(variant, 0)
            total += count
        else:
            total += inspect_result.protocol_counts.get(variant, 0)
    return total


def _protocol_presence(inspect_result: InspectResult) -> frozenset[str]:
    present: set[str] = set()

    for protocol, count in inspect_result.protocol_counts.items():
        if count <= 0:
            continue
        present.add(protocol)
        for canonical, variants in _PROTOCOL_EQUIVALENTS.items():
            if protocol in variants:
                present.add(canonical)

    for protocol, count in inspect_result.transport_counts.items():
        if count > 0:
            present.add(protocol)

    for protocol in inspect_result.metadata.raw_protocols:
        present.add(protocol)
        for canonical, variants in _PROTOCOL_EQUIVALENTS.items():
            if protocol in variants:
                present.add(canonical)

    return frozenset(present)


def _protocol_evidence(
    inspect_result: InspectResult,
    protocol: str,
    total_packets: int,
    present: frozenset[str],
) -> tuple[float, int, str]:
    count = _protocol_count(inspect_result, protocol)
    if count > 0:
        return _freq_factor(count, total_packets), count, "count"
    if protocol in present:
        factor = _RAW_TRANSPORT_FACTOR if protocol in _TRANSPORT_PROTOCOLS else _RAW_PROTOCOL_FACTOR
        return factor, 0, "raw"
    return 0.0, 0, "none"


def _domain_family(domain: str) -> str | None:
    if domain.startswith("5g-"):
        return "5g"
    if domain.startswith("lte-"):
        return "lte"
    if domain.startswith("legacy-"):
        return "2g3g"
    if domain.startswith("ims-"):
        return "voice"
    return None


def _format_protocol_reason(protocol: str, count: int, source: str) -> str:
    if protocol in _TRANSPORT_PROTOCOLS:
        if source == "count" and count > 0:
            return f"{protocol} transport present ({count} pkts)"
        return f"{protocol} transport present"
    if source == "count" and count > 0:
        return f"{protocol} detected ({count} pkts)"
    return f"{protocol} detected in raw_protocols"


def _dns_naming_blob(inspect_result: InspectResult) -> str:
    """Return a combined lowercase string from sampled DNS query names and resolved peer names.

    Used for telecom naming pattern detection (core-name-resolution scoring).
    Cheap — only processes the sampled names stored in CaptureMetadata.
    """
    parts: list[str] = list(inspect_result.metadata.dns_qry_names)
    for peer in inspect_result.metadata.resolved_peers:
        for key in ("name", "hostname", "alias"):
            value = peer.get(key)
            if value:
                parts.append(str(value).lower())
    return " ".join(parts).lower()


def _telecom_naming_evidence(dns_blob: str) -> tuple[int, int, list[str]]:
    """Count strong and supporting telecom naming evidence in *dns_blob*.

    Returns (strong_hits, supporting_hits, matched_reason_fragments).

    Strong hits: 3GPP-standard patterns — 3gppnetwork.org, .gprs, MCC/MNC structures,
    EPC/IMS/5GC sub-domains.  Each matched entry in _CORE_NAMING_STRONG = one strong hit.
    Supporting hits: IMS CSCF/MMTel names, 5G NF hostnames, generic 3GPP context.
    """
    strong_hits = 0
    supporting_hits = 0
    reasons: list[str] = []
    seen_reasons: set[str] = set()

    for substring, pattern, reason_text in _CORE_NAMING_STRONG:
        matched = (
            (substring is not None and substring in dns_blob)
            or (pattern is not None and pattern.search(dns_blob) is not None)
        )
        if matched and reason_text not in seen_reasons:
            strong_hits += 1
            reasons.append(reason_text)
            seen_reasons.add(reason_text)

    matched_supporting: list[str] = []
    for substring, reason_text in _CORE_NAMING_SUPPORTING:
        if substring in dns_blob:
            supporting_hits += 1
            if reason_text not in seen_reasons:
                matched_supporting.append(reason_text)
                seen_reasons.add(reason_text)

    # Interpretive summary — placed first so it is the primary visible reason.
    # Added when any telecom naming evidence is present; explains *meaning*
    # rather than just *which pattern matched*.
    summary: list[str] = []
    if strong_hits >= 1:
        summary = ["DNS trace matches telecom core naming — APN/realm/core service resolution support traffic"]
    elif supporting_hits >= 2:
        summary = ["DNS naming context suggests telecom core support traffic"]

    # Summarize supporting signal with actual matched pattern names (up to 3)
    if supporting_hits >= 2 and not reasons:
        reasons.extend(matched_supporting[:3])
    elif supporting_hits >= 1 and reasons:
        reasons.extend(matched_supporting[:2])

    return strong_hits, supporting_hits, list(dict.fromkeys([*summary, *reasons]))


def _resolved_peer_blob(inspect_result: InspectResult) -> str:
    parts: list[str] = []
    for peer in inspect_result.metadata.resolved_peers:
        for key in ("name", "hostname", "alias", "role", "site"):
            value = peer.get(key)
            if value:
                parts.append(str(value).lower())
    return " ".join(parts)


def _resolved_peer_roles(inspect_result: InspectResult) -> set[str]:
    roles: set[str] = set()
    for peer in inspect_result.metadata.resolved_peers:
        value = peer.get("role")
        if value:
            roles.add(str(value).lower())
    return roles


def _has_peer_hint(peer_blob: str, hints: frozenset[str]) -> bool:
    return any(hint in peer_blob for hint in hints)


def _has_call_context(present: frozenset[str]) -> bool:
    return any(proto in present for proto in _VOICE_CALL_PROTOCOLS)


def _has_registration_context(
    present: frozenset[str],
    peer_blob: str,
    has_ims_peer_hint: bool,
) -> bool:
    if _has_peer_hint(peer_blob, _REGISTER_HINT_TOKENS):
        return True
    return has_ims_peer_hint and any(proto in present for proto in {"diameter", "dns"})


def _has_sbc_context(peer_blob: str, peer_roles: set[str]) -> bool:
    return "sbc" in peer_roles or _has_peer_hint(peer_blob, _SBC_HINT_TOKENS)


def _is_specific_sbi_profile(profile: ProfileDefinition) -> bool:
    if profile.name in _GENERIC_SBI_KEEP_PROFILES or profile.name == "5g-n26":
        return False
    protocols = set(profile.relevant_protocols)
    return {"http", "json"}.issubset(protocols)


def _has_strong_legacy_combo(present: frozenset[str]) -> bool:
    return any(combo.issubset(present) for combo in _STRONG_LEGACY_COMBOS)


def _apply_profile_gates(
    inspect_result: InspectResult,
    profile: ProfileDefinition,
    selector: SelectorMetadata,
    score: float,
    reasons: list[str],
    matched_domain_protocols: set[str],
    present: frozenset[str],
    total_packets: int,
    peer_blob: str,
    peer_roles: set[str],
) -> tuple[float, list[str]]:
    if score <= 0:
        return score, reasons

    if selector.family == "2g3g":
        dtap_present = "dtap" in matched_domain_protocols
        partner_present = bool((present & _LEGACY_PARTNER_PROTOCOLS) - {"dtap"})
        strong_legacy_combo = _has_strong_legacy_combo(present)
        dtap_count = _protocol_count(inspect_result, "dtap")
        rare_dtap_cutoff = max(5, int(total_packets * 0.01))

        if dtap_present and not partner_present:
            score *= 0.12
            reasons.append("DTAP gated: no BSSAP/SCCP/MTP3 partners")
        elif not strong_legacy_combo:
            score *= 0.45
            reasons.append("legacy evidence partial: no strong SS7 partner combo")

        if dtap_present and 0 < dtap_count < rare_dtap_cutoff and not strong_legacy_combo:
            score *= 0.5
            reasons.append("rare dtap signal treated as a side signal")

    has_strong_ims_signal = any(proto in present for proto in {"sip", "sdp", "rtp", "rtcp"})
    has_ims_peer_hint = _has_peer_hint(peer_blob, _IMS_HINT_TOKENS)
    has_call_context = _has_call_context(present)
    has_registration_context = _has_registration_context(present, peer_blob, has_ims_peer_hint)
    has_sbc_context = _has_sbc_context(peer_blob, peer_roles)

    if profile.name in _HYBRID_VOICE_PROFILES and not has_strong_ims_signal:
        score *= 0.35
        reasons.append("voice profile downranked: no SIP/IMS indicators")

    # All vonr-* profiles (beyond the hybrid gate above) require 5G SA context.
    # In a pure SIP/SDP IMS trace without ngap/nas-5gs, VoNR profiles should be
    # clearly weaker than their VoLTE equivalents — they represent a different
    # generation's voice architecture and need more than generic IMS evidence.
    if profile.name.startswith("vonr-") and profile.name not in _HYBRID_VOICE_PROFILES:
        has_5g_context = any(proto in present for proto in {"ngap", "nas-5gs"})
        if not has_5g_context:
            score *= 0.3
            reasons.append("VoNR profile downranked: no 5G SA context (ngap/nas-5gs) detected")

    # IMS/voice profile gates — applied at most once per profile to avoid stacking.
    # Profiles in both _IMS_DIAMETER_PROFILES and _IMS_CORE_PROFILES (e.g. volte-ims-core)
    # receive the combined penalty once with a single reason rather than two separate gates.
    _ims_condition_fails = not (has_strong_ims_signal or has_ims_peer_hint)
    _in_ims_diam = profile.name in _IMS_DIAMETER_PROFILES
    _in_ims_core = profile.name in _IMS_CORE_PROFILES

    if _in_ims_diam and _in_ims_core and _ims_condition_fails:
        # Combined gate for profiles that are both Diameter-IMS and IMS-core
        score *= 0.3
        reasons.append("IMS Diameter/core profile downranked: no IMS peer or signaling hints")
    elif _in_ims_diam and _ims_condition_fails:
        score *= 0.35
        reasons.append("IMS Diameter profile downranked: no IMS peer or signaling hints")
    elif _in_ims_core and _ims_condition_fails:
        score *= 0.3
        reasons.append("IMS core profile downranked: no IMS peer or signaling hints")

    # IMS-core profiles need Diameter or IMS peer hints — SIP alone is insufficient.
    # A SIP+SDP call trace does not confirm IMS core infrastructure; the core role
    # requires either Diameter (Cx/Rx/Sh) or resolved peer evidence placing a CSCF/HSS.
    if profile.name in _IMS_CORE_PROFILES and has_strong_ims_signal and not (
        "diameter" in present or has_ims_peer_hint
    ):
        score *= 0.4
        reasons.append("IMS core profile downranked: SIP alone is insufficient — Diameter or IMS peer evidence needed")

    if profile.name in _VOICE_SIP_PROFILES and not ("sip" in present or has_ims_peer_hint):
        score *= 0.12
        reasons.append("SIP voice profile downranked: no SIP or IMS hints")

    if profile.name.endswith("-sip-call") and not has_call_context:
        score *= 0.4
        reasons.append("SIP call profile downranked: no SDP/media call markers")

    if profile.name.endswith("-sip-register") and not has_registration_context:
        score *= 0.25
        reasons.append("SIP register profile downranked: no registrar/auth-style context")

    if profile.name.endswith("-sbc") and not has_sbc_context:
        score *= 0.35
        reasons.append("SBC profile downranked: no SBC peer or topology hints")

    if profile.name in _VOICE_DNS_PROFILES and not ("sip" in present or has_ims_peer_hint):
        score *= 0.55
        reasons.append("voice DNS profile downranked: no IMS hints")

    if profile.name == "5g-n26":
        has_interworking = (
            ("gtpv2" in present and any(proto in present for proto in {"http", "json", "ngap", "nas-5gs"}))
            or _has_peer_hint(peer_blob, _N26_HINT_TOKENS)
        )
        if not has_interworking:
            # Pure EPS without 5GC indicators: suppress strongly — N26 requires explicit
            # EPC↔5GC interworking context (dual-registration, AMF-MME connectivity).
            has_lte_only = "gtpv2" in present and not any(proto in present for proto in {"ngap", "nas-5gs"})
            if has_lte_only:
                score *= 0.1
                reasons.append("N26 profile suppressed: clear EPS/GTPv2 context without any 5GC indicators")
            else:
                score *= 0.3
                reasons.append("N26 profile downranked: no EPC↔5GC interworking hints")

    # DNS family spread: gate all family-specific DNS profiles when no anchor for that family exists.
    #
    # lte-dns / 5g-dns: exempted from the generic gate in the previous round, but they
    # still need per-family anchors — otherwise both score equally on pure DNS-only traces.
    #   5g-dns requires a 5G anchor: ngap, nas-5gs, or http+json (SBI)
    #   lte-dns requires an LTE anchor: s1ap, nas-eps, diameter, or gtpv2
    # voice/2g3g DNS profiles: require IMS/voice or CP anchor (as before, stricter)
    _5G_DNS_ANCHORS: frozenset[str] = frozenset({"ngap", "nas-5gs"})
    _LTE_DNS_ANCHORS: frozenset[str] = frozenset({"s1ap", "nas-eps", "diameter", "gtpv2"})
    _CP_PROTOCOLS: frozenset[str] = frozenset({"ngap", "nas-5gs", "s1ap", "nas-eps", "sip", "sdp"})

    if profile.name == "5g-dns" and not (
        any(proto in present for proto in _5G_DNS_ANCHORS)
        or (_has_peer_hint(peer_blob, frozenset({"amf", "smf", "pcf", "udm", "ausf", "nrf", "ngap", "n2", "5g"})))
    ):
        score *= 0.4
        reasons.append("5G DNS profile downranked: no 5G anchor (ngap/nas-5gs) detected")

    elif profile.name == "lte-dns" and not (
        any(proto in present for proto in _LTE_DNS_ANCHORS)
        or _has_peer_hint(peer_blob, frozenset({"mme", "sgw", "pgw", "hss", "enb", "lte", "s1", "s6", "s11"}))
    ):
        score *= 0.4
        reasons.append("LTE DNS profile downranked: no LTE anchor (s1ap/diameter/gtpv2) detected")

    elif (
        profile.name.endswith("-dns")
        and profile.name not in {"lte-dns", "5g-dns"}
        and not _has_peer_hint(peer_blob, _IMS_HINT_TOKENS)
        and not any(proto in present for proto in _CP_PROTOCOLS)
    ):
        score *= 0.25
        reasons.append("family-specific DNS profile downranked: no domain context beyond DNS")

    # Legacy profile gates
    _ISUP_PROFILES: frozenset[str] = frozenset({"2g3g-isup", "isup"})
    if profile.name in _ISUP_PROFILES and "isup" not in present:
        score = 0.0
        reasons.append("ISUP profile suppressed: no isup protocol evidence detected")

    has_bssap_evidence = any(proto in present for proto in {"bssap", "bssap+", "bssmap"})
    has_geran_evidence = has_bssap_evidence or any(proto in present for proto in {"dtap", "gsm_a"})

    if profile.name == "2g3g-bssap" and not has_bssap_evidence:
        score = 0.0
        reasons.append("BSSAP profile suppressed: no BSSAP/BSSMAP evidence")

    if profile.name == "2g3g-geran" and not has_geran_evidence:
        score = 0.0
        reasons.append("GERAN profile suppressed: no BSSAP/DTAP/GSM-A evidence")

    if profile.name == "2g3g-ss7-geran" and not has_geran_evidence:
        # Without BSSAP/DTAP/GSM-A evidence the SS7 part is already covered by
        # 2g3g-map-core / 2g3g-sccp-mtp; this bundle profile adds no value.
        score = 0.0
        reasons.append("legacy GERAN bundle suppressed: no BSSAP/DTAP/GSM-A evidence")

    if profile.name == "2g3g-gs" and not (has_bssap_evidence or "dtap" in present):
        score = 0.0
        reasons.append("Gs interface profile suppressed: no BSSAP/DTAP evidence")

    if profile.name == "2g3g-gn":
        has_gtp1 = any(proto in present for proto in {"gtpv1", "gtp"})
        has_gtpv2 = "gtpv2" in present
        if not has_gtp1:
            score = 0.0
            reasons.append("Gn profile not applicable: no GTPv1 evidence detected")
        elif has_gtpv2:
            score = 0.0
            reasons.append("Gn profile not applicable: GTPv2 control plane present — GTP user-plane is LTE-U, not legacy Gn")

    # Gp is the inter-PLMN roaming equivalent of Gn — same GTPv1 requirement.
    # When no GTPv1 evidence exists, or when GTPv2 is present (LTE context),
    # the Gp profile is equally inapplicable.
    if profile.name == "2g3g-gp":
        has_gtp1 = any(proto in present for proto in {"gtpv1", "gtp"})
        has_gtpv2 = "gtpv2" in present
        if not has_gtp1:
            score = 0.0
            reasons.append("Gp profile not applicable: no GTPv1 evidence detected")
        elif has_gtpv2:
            score = 0.0
            reasons.append("Gp profile not applicable: GTPv2 control plane present — GTP user-plane is LTE-U, not legacy Gp/roaming")

    if profile.name in {"lte-s5", "lte-s8"}:
        _has_gtp1_only = (
            any(proto in present for proto in {"gtpv1", "gtp"})
            and "gtpv2" not in present
        )
        if _has_gtp1_only:
            score *= 0.12
            reasons.append(
                "lte-s5/s8 downranked: GTP (v1) without GTPv2 control plane — suggests legacy Gn/Gp, not LTE S5/S8"
            )

    if _is_specific_sbi_profile(profile):
        profile_hints = _SBI_PROFILE_HINTS.get(profile.name, frozenset({"amf", "smf", "pcf", "udm", "ausf", "nrf", "nssf", "scp"}))
        if not _has_peer_hint(peer_blob, profile_hints):
            score *= 0.3
            reasons.append("specific SBI interface downranked because no NF or interface hints were detected")

    return score, reasons


def _supporting_context_bonus(
    inspect_result: InspectResult,
    profile: ProfileDefinition,
    present: frozenset[str],
    peer_blob: str,
    peer_roles: set[str],
) -> tuple[float, list[str]]:
    bonus = 0.0
    reasons: list[str] = []

    if profile.name in _IMS_DIAMETER_PROFILES and _has_peer_hint(peer_blob, _IMS_HINT_TOKENS):
        bonus += 0.6
        reasons.append("resolved peer hints reinforce IMS/CSCF Diameter context")

    if profile.name in _IMS_CORE_PROFILES and "diameter" in present and _has_peer_hint(peer_blob, _IMS_HINT_TOKENS):
        bonus += 1.0
        reasons.append("Diameter plus IMS peer hints support broad IMS core context")

    if profile.name.endswith("-sip-call") and _has_call_context(present):
        bonus += 0.9
        reasons.append("SDP/media markers support call-flow specialization")

    if profile.name.endswith("-sip-register") and _has_registration_context(present, peer_blob, _has_peer_hint(peer_blob, _IMS_HINT_TOKENS)):
        bonus += 0.8
        reasons.append("registrar/auth-style hints support registration specialization")

    if profile.name.endswith("-sbc") and _has_sbc_context(peer_blob, peer_roles):
        bonus += 0.9
        reasons.append("resolved peer hints support SBC boundary interpretation")

    if profile.name == "lte-s6a" and (
        {"mme", "hss"}.issubset(peer_roles) or _has_peer_hint(peer_blob, _LTE_S6A_HINT_TOKENS)
    ):
        bonus += 1.2
        reasons.append("protocol evidence is partial; resolved peer hints strongly suggest MME/HSS Diameter context")

    if profile.name in {"lte-s5", "lte-s8"} and (
        {"sgw", "pgw"}.issubset(peer_roles) or _has_peer_hint(peer_blob, _S5_S8_HINT_TOKENS)
    ):
        bonus += 1.5
        reasons.append("protocol evidence is partial; resolved peer hints strongly suggest S5/S8 context")

    if profile.name == "lte-s11" and (
        {"mme", "sgw"}.issubset(peer_roles) or _has_peer_hint(peer_blob, _S11_HINT_TOKENS)
    ):
        bonus += 1.1
        reasons.append("protocol evidence is partial; resolved peer hints suggest S11 MME↔SGW context")

    if profile.name == "lte-s10" and _has_peer_hint(peer_blob, _S10_HINT_TOKENS):
        bonus += 1.1
        reasons.append("protocol evidence is partial; resolved peer hints suggest S10 inter-MME context")

    if profile.name == "5g-n26" and _has_peer_hint(peer_blob, _N26_HINT_TOKENS):
        bonus += 1.0
        reasons.append("protocol evidence is partial; resolved peer hints suggest EPC↔5GC interworking context")

    if profile.name in _VOICE_DNS_PROFILES and _has_peer_hint(peer_blob, _IMS_HINT_TOKENS):
        bonus += 0.8
        reasons.append("protocol evidence is partial; resolved peer hints suggest IMS-oriented DNS context")

    # MAP + TCAP + SCCP combo bonus for legacy SS7 core profiles
    _MAP_CORE_PROFILES: frozenset[str] = frozenset({"2g3g-map-core", "2g3g-gr"})
    if profile.name in _MAP_CORE_PROFILES and {"map", "tcap", "sccp"}.issubset(present):
        bonus += 0.5
        reasons.append("strong MAP/TCAP/SCCP combo supports core SS7 context")

    if profile.name == "5g-sbi" and {"http", "json"}.issubset(present):
        profile_hints = set().union(*_SBI_PROFILE_HINTS.values())
        if not _has_peer_hint(peer_blob, frozenset(profile_hints)):
            bonus += 1.2
            reasons.append("generic SBI candidate favored because no specific NF/interface hints were detected")

    if profile.name == "5g-core" and {"http", "json"}.issubset(present):
        profile_hints = set().union(*_SBI_PROFILE_HINTS.values())
        if not _has_peer_hint(peer_blob, frozenset(profile_hints)):
            bonus += 2.0
            reasons.append("generic 5G core candidate kept prominent because SBI traffic is broad but unspecific")

    return bonus, reasons


def _candidate_evidence(
    inspect_result: InspectResult,
    profile: ProfileDefinition,
    reasons: list[str],
) -> tuple[str, str]:
    # core-name-resolution: evidence class is determined by telecom naming quality,
    # not by signaling protocol counts — the profile has no signaling indicators.
    if profile.name == "core-name-resolution":
        _present = _protocol_presence(inspect_result)
        _total = inspect_result.metadata.packet_count or sum(inspect_result.protocol_counts.values()) or 1
        _dns_factor, _, _ = _protocol_evidence(inspect_result, "dns", _total, _present)
        if _dns_factor == 0:
            return "low", "weak"
        _strong, _supporting, _ = _telecom_naming_evidence(_dns_naming_blob(inspect_result))
        if _strong >= 2:
            return "high", "protocol_strong"
        if _strong >= 1:
            return "medium", "protocol_partial"
        if _supporting >= 2:
            return "medium", "protocol_partial"
        return "low", "protocol_partial"

    present = _protocol_presence(inspect_result)
    total_packets = inspect_result.metadata.packet_count or sum(inspect_result.protocol_counts.values()) or 1
    selector = _infer_selector_metadata(profile)
    protocol_hits = 0
    raw_hits = 0

    for proto in list(selector.strong_indicators) + selector.triggers.get("protocols", []) + list(selector.weak_indicators):
        if proto in _TRANSPORT_PROTOCOLS:
            continue
        factor, count, source = _protocol_evidence(inspect_result, proto, total_packets, present)
        if factor == 0:
            continue
        if source == "count" and count > 0:
            protocol_hits += 1
        elif source == "raw":
            raw_hits += 1

    has_host_hints = any("resolved peer hints" in reason for reason in reasons)

    if profile.name in {"lte-s5", "lte-s8"} and _protocol_count(inspect_result, "gtpv2") == 0 and _protocol_count(inspect_result, "gtp") > 0:
        if has_host_hints:
            return "low", "protocol_partial_with_host_hints"
        return "low", "protocol_partial"

    if protocol_hits >= 2 and not has_host_hints:
        return "high", "protocol_strong"
    if protocol_hits >= 2 and has_host_hints:
        return "high", "protocol_strong_with_host_hints"
    if protocol_hits >= 1 and raw_hits >= 1 and has_host_hints:
        return "medium", "protocol_partial_with_host_hints"
    if protocol_hits >= 1:
        return "medium", "protocol_partial"
    if raw_hits >= 1 and has_host_hints:
        return "low", "protocol_partial_with_host_hints"
    if raw_hits >= 1:
        return "low", "raw_protocol_partial"
    if has_host_hints:
        return "low", "host_hints_only"
    return "low", "weak"


def _domain_alignment_bonus(
    profile: ProfileDefinition,
    suspected_domains: list[dict[str, Any]],
) -> tuple[float, list[str]]:
    selector = _infer_selector_metadata(profile)
    best_bonus = 0.0
    best_reason: str | None = None

    for item in suspected_domains:
        domain = item["domain"]
        score = float(item.get("score", 0.0))
        family = _domain_family(domain)

        if domain == selector.domain:
            bonus = score * _DOMAIN_BONUS_SCALE
        elif family is not None and family == selector.family:
            bonus = score * (_DOMAIN_BONUS_SCALE * 0.7)
        else:
            continue

        if bonus > best_bonus:
            best_bonus = bonus
            best_reason = f"aligned with suspected domain {domain}"

    return best_bonus, ([best_reason] if best_reason else [])


def _domain_mismatch_penalty(
    inspect_result: InspectResult,
    profile: ProfileDefinition,
    suspected_domains: list[dict[str, Any]],
) -> tuple[float, list[str]]:
    if not suspected_domains:
        return 1.0, []

    selector = _infer_selector_metadata(profile)
    top = suspected_domains[0]
    top_family = _domain_family(top["domain"])
    top_score = float(top.get("score", 0.0))
    present_families = {_domain_family(item["domain"]) for item in suspected_domains}
    total_packets = inspect_result.metadata.packet_count or sum(inspect_result.protocol_counts.values()) or 1
    present = _protocol_presence(inspect_result)

    if top_family is None or top_score < 0.75:
        return 1.0, []

    if selector.family == "lte" and top["domain"] in {"5g-sa-core", "5g-sa-core-sbi"}:
        has_nas_eps = _protocol_evidence(inspect_result, "nas-eps", total_packets, present)[0] > 0
        has_anchor = any(
            _protocol_evidence(inspect_result, proto, total_packets, present)[0] > 0
            for proto in _LTE_ANCHOR_PROTOCOLS
        )
        if has_nas_eps and not has_anchor:
            return 0.35, [f"treated as cross-generation side signal; primary domain evidence points to {top['domain']}"]
        if not has_nas_eps and not has_anchor:
            return 0.15, ["LTE profile suppressed: no LTE anchor signal in strongly 5G SA dominated trace"]

    if selector.family == "2g3g" and top_family in {"5g", "lte"} and "2g3g" not in present_families:
        return 0.25, [f"strong {top['domain']} evidence outweighs weak legacy side signals"]

    if selector.family in {"5g", "lte"} and top_family == "2g3g" and selector.family not in present_families:
        return 0.35, [f"strong {top['domain']} evidence outweighs weak modern side signals"]

    if profile.name.startswith("vonr-") and top["domain"] == "lte-eps" and "5g" not in present_families:
        return 0.55, ["voice-over-5GS profile downranked because primary domain evidence points to LTE/EPS"]

    if profile.name.startswith("volte-") and top_family == "5g" and "lte" not in present_families:
        return 0.55, ["VoLTE/EPS voice profile downranked because primary domain evidence points to 5G SA"]

    # In a strong 5G SA trace without any voice signaling, voice profiles are side noise.
    # Neither VoNR nor VoLTE profiles have enough independent evidence to rank prominently
    # when the primary domain is clearly 5G SA and no SIP/SDP/RTP evidence exists.
    if top_family == "5g" and top_score >= 0.75:
        is_voice_profile = profile.name.startswith("vonr-") or profile.name.startswith("volte-")
        if is_voice_profile:
            has_voice = any(proto in present for proto in {"sip", "sdp", "rtp", "rtcp"})
            if not has_voice:
                return 0.2, ["voice profile suppressed: primary domain is 5G SA with no voice evidence detected"]

    return 1.0, []


def _prioritize_reasons(reasons: list[str]) -> list[str]:
    def sort_key(reason: str) -> tuple[int, str]:
        if reason.startswith("aligned with suspected domain"):
            return (0, reason)
        if reason.startswith("treated as cross-generation side signal"):
            return (1, reason)
        if reason.startswith("voice profile downranked"):
            return (2, reason)
        if "outweighs weak" in reason:
            return (3, reason)
        # Interpretive summary for core-name-resolution — appears before specific patterns
        if "telecom core naming" in reason or "telecom core DNS naming" in reason:
            return (5, reason)
        return (10, reason)

    unique = list(dict.fromkeys(reasons))
    return sorted(unique, key=sort_key)


def _infer_selector_metadata(profile: ProfileDefinition) -> SelectorMetadata:
    if profile.selector_metadata is not None:
        return profile.selector_metadata

    name = profile.name
    family = "generic"
    domain = "mixed"
    interface = None

    if name.startswith("lte-"):
        family = "lte"
        domain = "eps"
        interface = name.removeprefix("lte-")
    elif name.startswith("5g-"):
        family = "5g"
        domain = "5g-sa-core"
        interface = name.removeprefix("5g-")
    elif name.startswith("volte-"):
        family = "voice"
        domain = "volte-eps"
        interface = name.removeprefix("volte-")
    elif name.startswith("vonr-"):
        family = "voice"
        domain = "vonr-5gs"
        interface = name.removeprefix("vonr-")
    elif name.startswith("2g3g-"):
        family = "2g3g"
        domain = "legacy-core"
        interface = name.removeprefix("2g3g-")

    triggers = {"protocols": sorted(set(profile.relevant_protocols))}
    return SelectorMetadata(
        family=family,
        domain=domain,
        interface=interface,
        triggers=triggers,
        strong_indicators=profile.top_protocol_priority[:2],
        weak_indicators=profile.relevant_protocols[2:4],
        output_focus="control_plane",
    )


def _freq_factor(count: int, total: int) -> float:
    """Frequency dampening factor for rare protocol presence.

    Returns a multiplier in [0.0, 1.0]:
    - <0.5%  of total packets → 0.2 (very rare, strong dampening)
    - <1%    of total packets → 0.4
    - <5%    of total packets → 0.7
    - ≥5%    of total packets → 1.0 (full weight)
    """
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


def _score_profile(
    inspect_result: InspectResult,
    profile: ProfileDefinition,
) -> tuple[float, list[str]]:
    """Score a profile against an InspectResult.

    Rules:
    - Only domain-specific protocols (not in _TRANSPORT_PROTOCOLS) generate
      significant score contributions.
    - Scores are frequency-dampened so rare protocols contribute less.
    - Transport protocols (sctp, tcp, udp) add a small bonus ONLY when at least
      one domain-specific signal has already matched — they must not independently
      push profiles to the top of the ranking.
    - A profile with zero domain-signal matches scores 0.
    """
    total_packets = inspect_result.metadata.packet_count or sum(inspect_result.protocol_counts.values()) or 1
    present = _protocol_presence(inspect_result)
    peer_blob = _resolved_peer_blob(inspect_result)
    peer_roles = _resolved_peer_roles(inspect_result)
    selector = _infer_selector_metadata(profile)
    reasons: list[str] = []
    domain_score = 0.0
    matched_domain_protocols: set[str] = set()

    # --- Special path: core-name-resolution ---
    # This profile's value comes from telecom naming patterns in DNS query content,
    # not from signaling protocol counts.  Score it based on dns presence + naming evidence.
    if profile.name == "core-name-resolution":
        dns_factor, dns_count, dns_source = _protocol_evidence(inspect_result, "dns", total_packets, present)
        if dns_factor == 0:
            return 0.0, []  # DNS not present — profile irrelevant
        # Telecom naming evidence from sampled dns.qry.name values + resolved peer names
        dns_blob = _dns_naming_blob(inspect_result)
        strong_hits, supporting_hits, naming_reasons = _telecom_naming_evidence(dns_blob)
        # Naming evidence reasons come first — they are the primary value signal
        reasons = [*naming_reasons, _format_protocol_reason("dns", dns_count, dns_source)]
        # Base score from DNS presence (frequency-dampened) + naming evidence bonus
        base = 2.5 * dns_factor
        if strong_hits >= 2:
            base += 4.0
        elif strong_hits == 1:
            base += 2.5
        elif supporting_hits >= 3:
            base += 1.5
        elif supporting_hits >= 1:
            base += 0.8
        score, reasons = _apply_profile_gates(
            inspect_result, profile, selector, base, reasons,
            {"dns"}, present, total_packets, peer_blob, peer_roles,
        )
        return score, list(dict.fromkeys(reasons))

    # Strong indicators — high weight, frequency-dampened, transport excluded
    for proto in selector.strong_indicators:
        if proto in _TRANSPORT_PROTOCOLS:
            continue
        factor, count, source = _protocol_evidence(inspect_result, proto, total_packets, present)
        if factor == 0:
            continue
        weight = 5.0 * factor
        domain_score += weight
        reasons.append(f"{_format_protocol_reason(proto, count, source)} (strong)")
        matched_domain_protocols.add(proto)

    # Trigger protocols (from relevant_protocols) — medium weight, transport excluded
    trigger_protocols = selector.triggers.get("protocols", [])
    counted = set(selector.strong_indicators)
    for proto in trigger_protocols:
        if proto in _TRANSPORT_PROTOCOLS or proto in counted:
            continue
        factor, count, source = _protocol_evidence(inspect_result, proto, total_packets, present)
        if factor == 0:
            continue
        weight = 2.0 * factor
        domain_score += weight
        counted.add(proto)
        reasons.append(_format_protocol_reason(proto, count, source))
        matched_domain_protocols.add(proto)

    # Weak indicators — low weight, transport excluded
    for proto in selector.weak_indicators:
        if proto in _TRANSPORT_PROTOCOLS or proto in counted:
            continue
        factor, count, source = _protocol_evidence(inspect_result, proto, total_packets, present)
        if factor == 0:
            continue
        weight = 0.5 * factor
        domain_score += weight
        reasons.append(f"supporting: {_format_protocol_reason(proto, count, source)}")
        matched_domain_protocols.add(proto)

    # Transport bonus: ONLY when domain signal already present
    transport_bonus = 0.0
    if domain_score > 0:
        sctp_factor, _, _ = _protocol_evidence(inspect_result, "sctp", total_packets, present)
        tcp_factor, _, _ = _protocol_evidence(inspect_result, "tcp", total_packets, present)
        udp_factor, _, _ = _protocol_evidence(inspect_result, "udp", total_packets, present)
        if "sctp" in profile.relevant_protocols and sctp_factor > 0:
            transport_bonus += 0.5
            reasons.append("sctp transport present")
        if "tcp" in profile.relevant_protocols and tcp_factor > 0:
            transport_bonus += 0.2
        if "udp" in profile.relevant_protocols and udp_factor > 0:
            transport_bonus += 0.2

    score = domain_score + transport_bonus
    score, reasons = _apply_profile_gates(
        inspect_result,
        profile,
        selector,
        score,
        reasons,
        matched_domain_protocols,
        present,
        total_packets,
        peer_blob,
        peer_roles,
    )
    return score, list(dict.fromkeys(reasons))


def infer_domains(inspect_result: InspectResult) -> list[dict[str, Any]]:
    """Infer likely network domains using combination rules.

    Specific protocol co-occurrences produce higher confidence than single-
    protocol presence. Scores are frequency-dampened for rare protocols.
    """
    total_packets = inspect_result.metadata.packet_count or sum(inspect_result.protocol_counts.values()) or 1
    present = _protocol_presence(inspect_result)

    domain_best: dict[str, tuple[float, list[str]]] = {}

    for required, domain, base_score, reason in _DOMAIN_COMBOS:
        if not required.issubset(present):
            continue

        domain_protos = required - _TRANSPORT_PROTOCOLS
        if domain_protos:
            min_ff = min(_protocol_evidence(inspect_result, p, total_packets, present)[0] for p in domain_protos)
            score = base_score * min_ff
        else:
            score = base_score * 0.3  # transport-only combo: greatly dampened

        evidence_reasons = [
            _format_protocol_reason(proto, count, source)
            for proto in required
            for factor, count, source in [_protocol_evidence(inspect_result, proto, total_packets, present)]
            if factor > 0
        ]
        # Merge combo summary reason with per-protocol evidence reasons.
        # Drop the combo summary if one of the evidence reasons already contains
        # the same information (e.g. "dns detected" is redundant when
        # "dns detected (400 pkts)" is already in the list).
        all_reasons = [reason, *evidence_reasons]
        merged: list[str] = []
        for r in all_reasons:
            if not any(r != other and other.startswith(r) for other in all_reasons):
                merged.append(r)
        deduped = list(dict.fromkeys(merged))

        existing = domain_best.get(domain, (0.0, []))[0]
        if score > existing:
            domain_best[domain] = (score, deduped)

    # GTPv1 domain inference for plain "gtp" protocol name.
    # TShark reports GTPv1 as "gtp" (not "gtpv1"), so the gtpv1+udp combo above may not fire.
    # Infer legacy-2g3g-gprs from plain "gtp" when gtpv2 is absent — when gtpv2 is present,
    # "gtp" is GTP-U (LTE user plane), not legacy Gn/Gp.  The "gtpv1" protocol name check
    # ensures we do not double-count when both names appear.
    if (
        "gtp" in present
        and "udp" in present
        and "gtpv2" not in present
        and "gtpv1" not in present
    ):
        gtp_ff = _protocol_evidence(inspect_result, "gtp", total_packets, present)[0]
        gtp_score = 0.65 * gtp_ff
        existing_gprs = domain_best.get("legacy-2g3g-gprs", (0.0, []))[0]
        if gtp_score > existing_gprs:
            domain_best["legacy-2g3g-gprs"] = (
                gtp_score,
                ["gtp (GTPv1) + udp = legacy GTPv1 packet-core (Gn/Gp ambiguous — no GTPv2 control plane detected)"],
            )

    # Suppress dns-support when a primary telecom domain is already present.
    # The bare dns rule fires on any trace that has DNS, including IMS, 5G, and
    # LTE captures where DNS is ancillary infrastructure.  When a stronger domain
    # explanation is already established, dns-support is noise that causes false
    # state=mixed in _classification_state.
    if "dns-support" in domain_best and domain_best.keys() & _DNS_SUPPORT_SUPPRESSORS:
        del domain_best["dns-support"]

    results = [
        {"domain": domain, "score": round(score, 2), "reason": reasons}
        for domain, (score, reasons) in domain_best.items()
        if score >= 0.35
    ]
    results = sorted(results, key=lambda x: x["score"], reverse=True)

    # Assign role field only when it adds meaningful interpretation.
    # Single domain: always "primary" — labeling the sole domain "secondary" is semantically broken.
    # Multiple domains: threshold-based (primary ≥ 0.7, secondary ≥ 0.4, supporting < 0.4).
    if len(results) == 1:
        results[0]["role"] = "primary"
    elif len(results) > 1:
        for entry in results:
            s = entry["score"]
            if s >= 0.7:
                entry["role"] = "primary"
            elif s >= 0.4:
                entry["role"] = "secondary"
            else:
                entry["role"] = "supporting"

    return results


# Profiles suppressed further when core-name-resolution clearly dominates a DNS trace.
# These are family-specific DNS profiles that contribute noise when the better
# explanation is already "telecom core naming support traffic, generation ambiguous".
_DNS_SUPPRESSION_FACTOR = 0.3

# Protocols that indicate a real signaling anchor — if any of these are present,
# the trace is not purely DNS-support and fan-out suppression should not apply.
_DNS_SUPPRESSION_ANCHORS: frozenset[str] = frozenset({
    "ngap", "nas-5gs", "s1ap", "nas-eps",
    "diameter", "sip", "sdp",
    "gtpv2", "gtpv1",
    "map", "tcap", "sccp", "isup",
})


def _apply_dns_fanout_suppression(
    scored: list[tuple[float, ProfileDefinition, list[str]]],
    present: frozenset[str],
    peer_blob: str,
) -> list[tuple[float, ProfileDefinition, list[str]]]:
    """Suppress family-specific DNS profiles when core-name-resolution clearly dominates.

    Triggered only when:
    1. core-name-resolution score ≥ 5.0 (strong telecom naming evidence present)
    2. No real signaling anchor in the trace (the trace is DNS support, not mixed)

    Under those conditions, family-specific *-dns profiles without independent
    justification are reduced by _DNS_SUPPRESSION_FACTOR.  They remain in the
    candidate list but move clearly into the background.

    Exception: voice DNS profiles (volte-dns, vonr-dns) with a genuine IMS peer hint
    are NOT suppressed — the peer hint is independent evidence that justifies their
    presence and they should remain visible alongside core-name-resolution.
    """
    core_score = next(
        (s for s, p, _ in scored if p.name == "core-name-resolution"),
        0.0,
    )
    if core_score < 4.0:
        return scored  # core-name-resolution not dominant — no suppression

    if any(proto in present for proto in _DNS_SUPPRESSION_ANCHORS):
        return scored  # real signaling anchor present — leave fan-out intact

    _VOICE_DNS_EXEMPT = frozenset({"volte-dns", "vonr-dns"})
    has_ims_peer = _has_peer_hint(peer_blob, _IMS_HINT_TOKENS)
    # Family-specific non-dns core profiles that add noise in DNS-only support traces.
    _FAMILY_CORE_SUPPRESS: frozenset[str] = frozenset({"lte-core", "5g-core", "lte-sbc-cbc", "2g3g-ss7-geran"})

    result: list[tuple[float, ProfileDefinition, list[str]]] = []
    for score, profile, reasons in scored:
        if profile.name == "core-name-resolution":
            result.append((score, profile, reasons))
            continue
        # Voice DNS with IMS peer hint: independent justification — leave intact
        if profile.name in _VOICE_DNS_EXEMPT and has_ims_peer:
            result.append((score, profile, reasons))
            continue
        # DNS family profiles: suppress
        if profile.name.endswith("-dns"):
            new_score = score * _DNS_SUPPRESSION_FACTOR
            new_reasons = list(dict.fromkeys([
                *reasons,
                "downranked: telecom core naming support profile provides the stronger explanation",
            ]))
            result.append((new_score, profile, new_reasons))
            continue
        # Family-specific core profiles without non-DNS signaling anchor: reduce further
        if profile.name in _FAMILY_CORE_SUPPRESS:
            new_score = score * 0.35
            new_reasons = list(dict.fromkeys([
                *reasons,
                "downranked: family-specific profile without signaling anchor in DNS support trace",
            ]))
            result.append((new_score, profile, new_reasons))
            continue
        result.append((score, profile, reasons))
    return result


def recommend_profiles_from_inspect(
    inspect_result: InspectResult,
    profiles: list[ProfileDefinition],
    *,
    limit: int = 8,
) -> dict[str, Any]:
    suspected_domains = infer_domains(inspect_result)
    scored: list[tuple[float, ProfileDefinition, list[str]]] = []
    suppressed: list[tuple[float, ProfileDefinition, list[str]]] = []
    present = _protocol_presence(inspect_result)
    peer_blob = _resolved_peer_blob(inspect_result)
    peer_roles = _resolved_peer_roles(inspect_result)
    for profile in profiles:
        score, reasons = _score_profile(inspect_result, profile)
        if score > 0:
            domain_bonus, domain_reasons = _domain_alignment_bonus(profile, suspected_domains)
            penalty, penalty_reasons = _domain_mismatch_penalty(inspect_result, profile, suspected_domains)
            context_bonus, context_reasons = _supporting_context_bonus(
                inspect_result,
                profile,
                present,
                peer_blob,
                peer_roles,
            )
            score = (score + domain_bonus + context_bonus) * penalty
            reasons = _prioritize_reasons([*reasons, *domain_reasons, *context_reasons, *penalty_reasons])
            scored.append((score, profile, reasons))
        else:
            suppressed.append((score, profile, reasons or ["no matching protocol evidence"]))

    # Post-scoring DNS fan-out suppression: when core-name-resolution clearly
    # dominates a DNS-support trace, push family-specific *-dns profiles further
    # into the background.  Must run after all scores are final.
    scored = _apply_dns_fanout_suppression(scored, present, peer_blob)

    scored.sort(key=lambda item: (-item[0], item[1].name))
    suppressed.sort(key=lambda item: (item[0], item[1].name))

    recommended = [
        {
            "profile": profile.name,
            "score": round(score, 2),
            "reason": reasons[:5],
            "confidence": _candidate_evidence(inspect_result, profile, reasons)[0],
            "evidence_class": _candidate_evidence(inspect_result, profile, reasons)[1],
            "selector_metadata": _infer_selector_metadata(profile).model_dump(),
        }
        for score, profile, reasons in scored[:limit]
    ]
    suppressed_payload = [
        {
            "profile": profile.name,
            "score": round(score, 2),
            "reason": reasons[:3],
        }
        for score, profile, reasons in suppressed[:limit]
    ]

    return {
        "status": "ok",
        "recommended_profiles": recommended,
        "suppressed_profiles": suppressed_payload,
        "suspected_domains": suspected_domains,
        "observed_protocols": [
            {"name": name, "count": count}
            for name, count in Counter(inspect_result.protocol_counts).most_common(10)
        ],
    }
