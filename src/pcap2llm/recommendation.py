from __future__ import annotations

from collections import Counter
from typing import Any

from pcap2llm.models import InspectResult, ProfileDefinition, SelectorMetadata

# Protocols that alone do NOT indicate a specific network domain.
# They may add a small bonus only when a domain-specific signal is already present.
_TRANSPORT_PROTOCOLS: frozenset[str] = frozenset({
    "ip", "ipv6", "tcp", "udp", "sctp", "eth", "frame", "data",
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
_LTE_ANCHOR_PROTOCOLS: frozenset[str] = frozenset({"s1ap", "diameter", "gtpv2"})

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

    if profile.name in _HYBRID_VOICE_PROFILES and not any(proto in present for proto in _VOICE_INDICATOR_PROTOCOLS):
        score *= 0.35
        reasons.append("voice profile downranked because no SIP/IMS indicators were detected")

    return score, reasons


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
    for profile in profiles:
        score, reasons = _score_profile(inspect_result, profile)
        if score > 0:
            domain_bonus, domain_reasons = _domain_alignment_bonus(profile, suspected_domains)
            penalty, penalty_reasons = _domain_mismatch_penalty(inspect_result, profile, suspected_domains)
            score = (score + domain_bonus) * penalty
            reasons = list(dict.fromkeys([*reasons, *domain_reasons, *penalty_reasons]))
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
