from __future__ import annotations

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
    "bssmap": ("bssmap", "gsm_a.bssmap"),
    "dtap": ("dtap", "gsm_a.dtap", "gsm_dtap"),
    "http": ("http", "http2"),
    "nas-eps": ("nas-eps", "nas_eps"),
    "nas-5gs": ("nas-5gs", "nas_5gs"),
    "ss7": ("ss7", "m3ua"),
}

_LEGACY_PARTNER_PROTOCOLS: frozenset[str] = frozenset({
    "bssap", "bssmap", "sccp", "mtp3", "ss7", "map", "tcap", "cap", "gtpv1",
})

_STRONG_LEGACY_COMBOS: tuple[frozenset[str], ...] = (
    frozenset({"bssap", "dtap", "sccp"}),
    frozenset({"bssap", "dtap", "mtp3"}),
    frozenset({"bssap", "dtap", "ss7"}),
    frozenset({"map", "tcap", "sccp"}),
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
    (frozenset({"gtpv1", "udp"}),              "legacy-2g3g-gprs", 0.70, "gtpv1 + udp = 2G/3G GPRS Gn/Gp"),
    # DNS support
    (frozenset({"dns"}),                       "dns-support", 0.40, "dns detected"),
]


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
            reasons.append("legacy dtap signal gated without bssap/sccp/mtp3-style partners")
        elif not strong_legacy_combo:
            score *= 0.45
            reasons.append("legacy evidence remains partial without a strong partner combo")

        if dtap_present and 0 < dtap_count < rare_dtap_cutoff and not strong_legacy_combo:
            score *= 0.5
            reasons.append("rare dtap signal treated as a side signal")

    has_voice_protocol = any(proto in present for proto in _VOICE_INDICATOR_PROTOCOLS)
    has_strong_ims_signal = any(proto in present for proto in {"sip", "sdp", "rtp", "rtcp"})
    has_ims_peer_hint = _has_peer_hint(peer_blob, _IMS_HINT_TOKENS)

    if profile.name in _HYBRID_VOICE_PROFILES and not has_voice_protocol:
        score *= 0.35
        reasons.append("voice profile downranked because no SIP/IMS indicators were detected")

    if profile.name in _IMS_DIAMETER_PROFILES and not (has_strong_ims_signal or has_ims_peer_hint):
        score *= 0.35
        reasons.append("IMS Diameter profile downranked because no IMS-specific peer or signaling hints were detected")

    if profile.name in _VOICE_SIP_PROFILES and not ("sip" in present or has_ims_peer_hint):
        score *= 0.12
        reasons.append("SIP-oriented voice profile downranked because no SIP or IMS-specific discovery hints were detected")

    if profile.name in _VOICE_DNS_PROFILES and not ("sip" in present or has_ims_peer_hint):
        score *= 0.55
        reasons.append("voice DNS profile downranked because no IMS-specific discovery hints were detected")

    if profile.name in _IMS_CORE_PROFILES and not (has_strong_ims_signal or has_ims_peer_hint):
        score *= 0.3
        reasons.append("IMS core profile downranked because no IMS-specific peer or signaling hints were detected")

    if profile.name == "5g-n26" and not (
        ("gtpv2" in present and any(proto in present for proto in {"http", "json", "ngap", "nas-5gs"}))
        or _has_peer_hint(peer_blob, _N26_HINT_TOKENS)
    ):
        score *= 0.3
        reasons.append("N26 profile downranked because no EPC↔5GC interworking hints were detected")

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

    if profile.name == "lte-s6a" and (
        {"mme", "hss"}.issubset(peer_roles) or _has_peer_hint(peer_blob, _LTE_S6A_HINT_TOKENS)
    ):
        bonus += 1.2
        reasons.append("resolved peer hints suggest MME/HSS Diameter context")

    if profile.name in {"lte-s5", "lte-s8"} and (
        {"sgw", "pgw"}.issubset(peer_roles) or _has_peer_hint(peer_blob, _S5_S8_HINT_TOKENS)
    ):
        bonus += 1.5
        reasons.append("resolved peer hints suggest S5/S8 GTPv2 context")

    if profile.name == "lte-s11" and (
        {"mme", "sgw"}.issubset(peer_roles) or _has_peer_hint(peer_blob, _S11_HINT_TOKENS)
    ):
        bonus += 1.1
        reasons.append("resolved peer hints suggest S11 MME↔SGW context")

    if profile.name == "lte-s10" and _has_peer_hint(peer_blob, _S10_HINT_TOKENS):
        bonus += 1.1
        reasons.append("resolved peer hints suggest S10 inter-MME context")

    if profile.name == "5g-n26" and _has_peer_hint(peer_blob, _N26_HINT_TOKENS):
        bonus += 1.0
        reasons.append("resolved peer hints suggest EPC↔5GC interworking context")

    if profile.name in _VOICE_DNS_PROFILES and _has_peer_hint(peer_blob, _IMS_HINT_TOKENS):
        bonus += 0.8
        reasons.append("resolved peer hints suggest IMS-oriented DNS context")

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

    if selector.family == "2g3g" and top_family in {"5g", "lte"} and "2g3g" not in present_families:
        return 0.25, [f"strong {top['domain']} evidence outweighs weak legacy side signals"]

    if selector.family in {"5g", "lte"} and top_family == "2g3g" and selector.family not in present_families:
        return 0.35, [f"strong {top['domain']} evidence outweighs weak modern side signals"]

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
        reasons = [reason, *evidence_reasons]

        existing = domain_best.get(domain, (0.0, []))[0]
        if score > existing:
            domain_best[domain] = (score, list(dict.fromkeys(reasons)))

    results = [
        {"domain": domain, "score": round(score, 2), "reason": reasons}
        for domain, (score, reasons) in domain_best.items()
        if score >= 0.35
    ]
    return sorted(results, key=lambda x: x["score"], reverse=True)


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

    scored.sort(key=lambda item: (-item[0], item[1].name))
    suppressed.sort(key=lambda item: (item[0], item[1].name))

    recommended = [
        {
            "profile": profile.name,
            "score": round(score, 2),
            "reason": reasons[:5],
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
