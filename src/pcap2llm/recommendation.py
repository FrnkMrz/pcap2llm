from __future__ import annotations

from collections import Counter
from typing import Any

from pcap2llm.models import InspectResult, ProfileDefinition, SelectorMetadata

# Protocols that alone do NOT indicate a specific network domain.
# They may add a small bonus only when a domain-specific signal is already present.
_TRANSPORT_PROTOCOLS: frozenset[str] = frozenset({
    "ip", "ipv6", "tcp", "udp", "sctp", "eth", "frame", "data",
})

# Domain combo rules: (required_protocol_set, domain, base_score, reason_text)
# Ordered: best match per domain wins. base_score assumes ≥5% relative frequency.
# Actual score is dampened for rare protocols: <0.5% → 0.2×, <1% → 0.4×, <5% → 0.7×.
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
    # 2G/3G — SS7 / MAP core
    (frozenset({"map", "tcap", "sccp"}),       "legacy-2g3g", 0.92, "map + tcap + sccp = SS7/MAP core"),
    (frozenset({"map", "tcap"}),               "legacy-2g3g", 0.82, "map + tcap = SS7/MAP signal"),
    (frozenset({"bssap", "sccp"}),             "legacy-2g3g", 0.82, "bssap + sccp = GERAN/BSSAP signal"),
    (frozenset({"bssap"}),                     "legacy-2g3g", 0.55, "bssap detected"),
    (frozenset({"map"}),                       "legacy-2g3g", 0.50, "map detected"),
    (frozenset({"isup"}),                      "legacy-2g3g", 0.45, "isup detected"),
    (frozenset({"gtpv1"}),                     "legacy-2g3g-gprs", 0.65, "gtpv1 = 2G/3G GPRS Gn/Gp"),
    # DNS support
    (frozenset({"dns"}),                       "dns-support", 0.40, "dns detected"),
]


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
    protocol_counts = inspect_result.protocol_counts
    transport_counts = inspect_result.transport_counts
    total = sum(protocol_counts.values()) or 1
    selector = _infer_selector_metadata(profile)
    reasons: list[str] = []
    domain_score = 0.0

    # Strong indicators — high weight, frequency-dampened, transport excluded
    for proto in selector.strong_indicators:
        if proto in _TRANSPORT_PROTOCOLS:
            continue
        count = protocol_counts.get(proto, 0)
        if count == 0:
            continue
        weight = 5.0 * _freq_factor(count, total)
        domain_score += weight
        reasons.append(f"{proto} ({count} pkts, strong)")

    # Trigger protocols (from relevant_protocols) — medium weight, transport excluded
    trigger_protocols = selector.triggers.get("protocols", [])
    counted = set(selector.strong_indicators)
    for proto in trigger_protocols:
        if proto in _TRANSPORT_PROTOCOLS or proto in counted:
            continue
        count = protocol_counts.get(proto, 0)
        if count == 0:
            continue
        weight = 2.0 * _freq_factor(count, total)
        domain_score += weight
        counted.add(proto)
        reasons.append(f"{proto} detected")

    # Weak indicators — low weight, transport excluded
    for proto in selector.weak_indicators:
        if proto in _TRANSPORT_PROTOCOLS or proto in counted:
            continue
        count = protocol_counts.get(proto, 0)
        if count == 0:
            continue
        weight = 0.5 * _freq_factor(count, total)
        domain_score += weight
        reasons.append(f"supporting: {proto}")

    # Transport bonus: ONLY when domain signal already present
    transport_bonus = 0.0
    if domain_score > 0:
        if "sctp" in profile.relevant_protocols and transport_counts.get("sctp", 0) > 0:
            transport_bonus += 0.5
            reasons.append("sctp transport present")
        if "tcp" in profile.relevant_protocols and transport_counts.get("tcp", 0) > 0:
            transport_bonus += 0.2
        if "udp" in profile.relevant_protocols and transport_counts.get("udp", 0) > 0:
            transport_bonus += 0.2

    score = domain_score + transport_bonus
    return score, list(dict.fromkeys(reasons))


def infer_domains(inspect_result: InspectResult) -> list[dict[str, Any]]:
    """Infer likely network domains using combination rules.

    Specific protocol co-occurrences produce higher confidence than single-
    protocol presence. Scores are frequency-dampened for rare protocols.
    """
    protocol_counts = inspect_result.protocol_counts
    total = sum(protocol_counts.values()) or 1
    present = frozenset(p for p, c in protocol_counts.items() if c > 0)

    domain_best: dict[str, tuple[float, str]] = {}

    for required, domain, base_score, reason in _DOMAIN_COMBOS:
        if not required.issubset(present):
            continue
        domain_protos = required - _TRANSPORT_PROTOCOLS
        if domain_protos:
            min_ff = min(_freq_factor(protocol_counts.get(p, 0), total) for p in domain_protos)
            score = base_score * min_ff
        else:
            score = base_score * 0.3  # transport-only combo: greatly dampened

        existing = domain_best.get(domain, (0.0, ""))[0]
        if score > existing:
            domain_best[domain] = (score, reason)

    results = [
        {"domain": domain, "score": round(score, 2), "reason": [reason]}
        for domain, (score, reason) in domain_best.items()
        if score >= 0.35
    ]
    return sorted(results, key=lambda x: x["score"], reverse=True)


def recommend_profiles_from_inspect(
    inspect_result: InspectResult,
    profiles: list[ProfileDefinition],
    *,
    limit: int = 8,
) -> dict[str, Any]:
    scored: list[tuple[float, ProfileDefinition, list[str]]] = []
    suppressed: list[tuple[float, ProfileDefinition, list[str]]] = []
    for profile in profiles:
        score, reasons = _score_profile(inspect_result, profile)
        if score > 0:
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
        "suspected_domains": infer_domains(inspect_result),
        "observed_protocols": [
            {"name": name, "count": count}
            for name, count in Counter(inspect_result.protocol_counts).most_common(10)
        ],
    }
