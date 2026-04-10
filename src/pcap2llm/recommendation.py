from __future__ import annotations

from collections import Counter
from typing import Any

from pcap2llm.models import InspectResult, ProfileDefinition, SelectorMetadata


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


def _score_profile(
    inspect_result: InspectResult,
    profile: ProfileDefinition,
) -> tuple[float, list[str]]:
    protocol_counts = inspect_result.protocol_counts
    transport_counts = inspect_result.transport_counts
    selector = _infer_selector_metadata(profile)
    reasons: list[str] = []
    score = 0.0

    trigger_protocols = selector.triggers.get("protocols", [])
    for proto in trigger_protocols:
        count = protocol_counts.get(proto, 0)
        if count > 0:
            score += 2.0
            reasons.append(f"{proto} detected")

    for proto in selector.strong_indicators:
        count = protocol_counts.get(proto, 0)
        if count > 0:
            score += 3.0
            reasons.append(f"strong indicator {proto}")

    for proto in selector.weak_indicators:
        count = protocol_counts.get(proto, 0)
        if count > 0:
            score += 1.0
            reasons.append(f"supporting indicator {proto}")

    for proto in profile.relevant_protocols:
        if protocol_counts.get(proto, 0) > 0:
            score += 0.5

    if "sctp" in profile.relevant_protocols and transport_counts.get("sctp", 0) > 0:
        score += 0.5
        reasons.append("sctp transport present")
    if "tcp" in profile.relevant_protocols and transport_counts.get("tcp", 0) > 0:
        score += 0.3
    if "udp" in profile.relevant_protocols and transport_counts.get("udp", 0) > 0:
        score += 0.3

    if selector.domain == "volte-eps" and protocol_counts.get("sip", 0) > 0:
        reasons.append("sip fits LTE/EPS IMS voice context")
    if selector.domain == "vonr-5gs" and (
        protocol_counts.get("http", 0) > 0
        or protocol_counts.get("ngap", 0) > 0
        or protocol_counts.get("nas-5gs", 0) > 0
    ):
        reasons.append("5GS control-plane evidence visible")

    deduped_reasons = list(dict.fromkeys(reasons))
    return score, deduped_reasons


def infer_domains(inspect_result: InspectResult) -> list[dict[str, Any]]:
    protocol_counts = inspect_result.protocol_counts
    domain_signals = {
        "lte-eps": ["diameter", "gtpv2", "s1ap", "nas-eps", "sgsap"],
        "5g-sa-core": ["ngap", "nas-5gs", "http", "json", "pfcp"],
        "ims-voice": ["sip", "sdp", "rtp", "rtcp"],
        "legacy-2g3g": ["map", "gsm_map", "cap", "isup", "bssap", "sccp"],
        "dns-support": ["dns"],
    }
    results: list[dict[str, Any]] = []
    for domain, signals in domain_signals.items():
        present = [sig for sig in signals if protocol_counts.get(sig, 0) > 0]
        if not present:
            continue
        score = min(1.0, 0.25 * len(present) + 0.1)
        results.append(
            {
                "domain": domain,
                "score": round(score, 2),
                "reason": [f"{sig} present" for sig in present],
            }
        )
    return sorted(results, key=lambda item: item["score"], reverse=True)


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
