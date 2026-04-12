"""Inspect enrichment: domain detection, profile ranking, trace shape, next-step hints.

Enriches an :class:`~pcap2llm.models.InspectResult` produced by the raw
inspection stage with higher-level diagnostic fields that are useful for human
triage and machine orchestration.

Reuses :func:`~pcap2llm.recommendation.infer_domains` and
:func:`~pcap2llm.recommendation.recommend_profiles_from_inspect` so the same
scoring logic applies to both ``inspect`` and ``discover``.
"""
from __future__ import annotations

from typing import Any

from pcap2llm.models import InspectResult, ProfileDefinition
from pcap2llm.recommendation import infer_domains, recommend_profiles_from_inspect
from pcap2llm.signaling import TRANSPORT_ONLY as _TRANSPORT_ONLY
from pcap2llm.signaling import dominant_signaling_names, protocol_presence, protocol_role


def _trace_shape(
    suspected_domains: list[dict[str, Any]],
    protocol_counts: dict[str, int],
    present_protocols: frozenset[str],
) -> tuple[str, list[str]]:
    """Classify the trace as single_domain, mixed_domain, transport_only, or unknown."""
    total = sum(protocol_counts.values()) or 1
    signaling_total = sum(
        c for p, c in protocol_counts.items() if p not in _TRANSPORT_ONLY
    )
    signaling_ratio = signaling_total / total
    raw_signaling = sorted(
        protocol for protocol in present_protocols if protocol_role(protocol) == "domain_signaling"
    )

    if signaling_ratio < 0.05 and not raw_signaling:
        return "transport_only", ["less than 5% signaling protocol traffic detected"]
    if signaling_ratio < 0.05 and raw_signaling:
        reason = ", ".join(raw_signaling[:4])
        return "single_domain" if suspected_domains else "unknown", [
            f"decoded top protocols are coarse, but raw signaling hints are present: {reason}"
        ]

    high_conf = [d for d in suspected_domains if d.get("score", 0) >= 0.6]
    medium_conf = [d for d in suspected_domains if 0.35 <= d.get("score", 0) < 0.6]

    if not high_conf and not medium_conf:
        return "unknown", ["no domain signal strong enough to classify"]

    if len(high_conf) == 1 and not medium_conf:
        return "single_domain", [f"strong {high_conf[0]['domain']} signal, no competing domain"]

    if len(high_conf) >= 2:
        names = [d["domain"] for d in high_conf[:3]]
        return "mixed_domain", [f"co-dominant domains: {', '.join(names)}"]

    if high_conf and medium_conf:
        other_names = [d["domain"] for d in medium_conf[:2]]
        return "mixed_domain", [
            f"primary domain {high_conf[0]['domain']}; secondary signals: {', '.join(other_names)}"
        ]

    # Only medium-confidence signals
    if len(medium_conf) == 1:
        return "single_domain", [f"moderate {medium_conf[0]['domain']} signal"]

    names = [d["domain"] for d in medium_conf[:3]]
    return "mixed_domain", [f"mixed moderate signals: {', '.join(names)}"]


def _inspect_anomalies(
    protocol_counts: dict[str, int],
    transport_counts: dict[str, int],
    suspected_domains: list[dict[str, Any]],
    trace_shape: str,
    present_protocols: frozenset[str],
    candidate_profiles: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Generate lightweight inspect-level anomaly and classification note flags.

    Returns a tuple of (network_anomalies, classification_notes).
    - network_anomalies: real network issues (transport-only, sparse diameter, etc.)
    - classification_notes: methodological notes about discovery confidence/limitations
    """
    network_anomalies: list[str] = []
    classification_notes: list[str] = []
    total = sum(protocol_counts.values()) or 1
    signaling_total = sum(
        c for p, c in protocol_counts.items() if p not in _TRANSPORT_ONLY
    )

    if not protocol_counts:
        network_anomalies.append("no protocols detected")
        return network_anomalies, classification_notes

    raw_signaling_present = any(protocol_role(protocol) == "domain_signaling" for protocol in present_protocols)

    if signaling_total == 0 and not raw_signaling_present:
        network_anomalies.append("transport-only trace: no application or signaling protocol decoded")
    elif signaling_total == 0 and raw_signaling_present:
        classification_notes.append("decoded top protocols are coarse; discovery is relying on raw signaling hints for classification")

    if trace_shape == "transport_only":
        sctp_count = transport_counts.get("sctp", 0)
        if sctp_count > 0 and signaling_total == 0:
            network_anomalies.append(
                "SCTP flows present but no upper-layer protocol decoded — "
                "check port assignments or try --tshark-arg '-d sctp.port==<port>,<dissector>'"
            )

    if protocol_counts.get("diameter", 0) > 0:
        total_diam = protocol_counts.get("diameter", 0)
        if total_diam / total < 0.03:
            network_anomalies.append("diameter present but sparse — may need '--tshark-arg \"-d sctp.port==3868,diameter\"'")

    if protocol_counts.get("http", 0) > 0:
        json_count = protocol_counts.get("json", 0)
        if json_count == 0:
            network_anomalies.append(
                "HTTP/2 detected without JSON body visibility — "
                "SBI payload content may not be decoded"
            )

    dns_count = protocol_counts.get("dns", 0)
    if dns_count > 0:
        control_protos = {"ngap", "s1ap", "diameter", "sip", "map", "gtpv2"}
        if not any(protocol_counts.get(p, 0) > 0 for p in control_protos):
            classification_notes.append(
                "DNS-only trace with no control-plane signaling — "
                "may be a support-traffic-only capture"
            )
            classification_notes.append(
                "family assignment remains ambiguous — DNS-only without domain-specific service markers"
            )

    if trace_shape == "mixed_domain":
        network_anomalies.append("mixed-domain trace — consider running discover for profile selection")

    if any(profile.get("evidence_class") in {"host_hints_only", "protocol_partial_with_host_hints"} for profile in candidate_profiles[:4]):
        classification_notes.append("low-confidence specialization due to host hints; treat interface naming as plausible rather than fully proven")

    # Rare legacy signal in modern trace
    modern_protos = {"ngap", "nas-5gs", "s1ap", "nas-eps", "http"}
    legacy_protos = {"map", "bssap", "dtap", "isup", "gsm_a", "tcap"}
    has_modern = any(protocol_counts.get(p, 0) > 0 for p in modern_protos)
    has_legacy = any(protocol_counts.get(p, 0) > 0 for p in legacy_protos)
    if has_modern and has_legacy:
        legacy_found = sorted(p for p in legacy_protos if protocol_counts.get(p, 0) > 0)
        network_anomalies.append(
            f"legacy protocol(s) present alongside modern signaling: {', '.join(legacy_found)} — "
            "may indicate interworking trace or stray frames"
        )

    return network_anomalies, classification_notes


def _next_step_hints(
    trace_shape: str,
    suspected_domains: list[dict[str, Any]],
    candidate_profiles: list[dict[str, Any]],
    packet_count: int,
) -> list[str]:
    """Generate actionable next-step hints for humans and orchestrators."""
    hints: list[str] = []

    if trace_shape == "transport_only":
        hints.append("run discover to see if a protocol dissector override is needed")
        return hints

    if not suspected_domains:
        hints.append("no strong domain detected — run discover for broad protocol inventory")
        return hints

    top_domain = suspected_domains[0]["domain"] if suspected_domains else None

    if trace_shape == "single_domain" and candidate_profiles:
        top_profile = candidate_profiles[0]["profile"]
        hints.append(f"run: pcap2llm analyze <capture> --profile {top_profile}")

    if trace_shape == "mixed_domain":
        hints.append("mixed domains detected — run discover to see full candidate profile list")
        if candidate_profiles:
            hints.append(
                f"or run separate analyze passes per domain, starting with: "
                f"--profile {candidate_profiles[0]['profile']}"
            )

    if packet_count > 5000:
        hints.append(
            "large capture — consider narrowing with -Y display filter before full analyze"
        )

    if top_domain in ("5g-sa-core", "5g-sa-core-sbi"):
        hints.append("5G SA Core signals detected — try profiles: 5g-n2, 5g-n1-n2, 5g-nas-5gs, 5g-sbi")
    elif top_domain == "lte-eps":
        hints.append("LTE/EPS signals detected — try profiles: lte-s1, lte-s1-nas, lte-s6a, lte-s11")
    elif top_domain == "ims-voice":
        hints.append("IMS/Voice signals detected — try profiles: volte-sip, volte-ims-core, vonr-sip")
    elif top_domain == "legacy-2g3g":
        hints.append("2G/3G core signals detected — try profiles: 2g3g-map-core, 2g3g-geran, 2g3g-gn")

    return hints


def _classification_state(
    trace_shape: str,
    suspected_domains: list[dict[Any, Any]],
    classification_notes: list[str],
    candidate_profiles: list[dict[Any, Any]],
) -> str:
    """Derive a structured top-level classification state.

    Returns one of:
    - ``"confident"``        — strong, single clear domain with high-confidence evidence
    - ``"ambiguous_support"``— DNS-only or generic support traffic without family context
    - ``"partial"``          — some evidence but weak or host-hint-driven
    - ``"mixed"``            — multiple competing domains
    - ``"unknown"``          — insufficient evidence to classify

    This is a machine-readable summary designed for orchestration decisions.
    It is derived from shape + suspected_domains + classification_notes.
    """
    if trace_shape == "transport_only":
        return "unknown"
    if trace_shape == "mixed_domain":
        return "mixed"

    # Ambiguous support: DNS-only or generic support without real domain signal
    is_dns_ambiguous = any(
        "DNS" in note or "dns" in note or "ambiguous" in note
        for note in classification_notes
    )
    only_dns_support = (
        len(suspected_domains) == 1
        and suspected_domains[0].get("domain") == "dns-support"
    )
    if is_dns_ambiguous or only_dns_support:
        return "ambiguous_support"

    # Partial: host-hint-only or weak evidence
    is_partial = any(
        "host hint" in note.lower() or "partial" in note.lower()
        for note in classification_notes
    )
    has_low_conf_only = candidate_profiles and all(
        p.get("confidence") == "low" for p in candidate_profiles[:3]
    )
    if is_partial or has_low_conf_only:
        return "partial"

    # Confident: top domain has strong score and no major caveats
    if suspected_domains and suspected_domains[0].get("score", 0) >= 0.7:
        return "confident"

    # Some signal but not strong enough for confident
    if suspected_domains:
        return "partial"

    return "unknown"


def enrich_inspect_result(
    result: InspectResult,
    profiles: list[ProfileDefinition],
) -> InspectResult:
    """Return a new :class:`InspectResult` enriched with domain, profile, and diagnostic fields.

    Does not mutate the input. Returns a new model instance with:
    - ``suspected_domains``
    - ``candidate_profiles``
    - ``dominant_signaling_protocols``
    - ``trace_shape`` + ``trace_shape_reasons``
    - ``next_step_hints``
    - additional ``anomalies`` from inspect-level heuristics (appended, not replaced)
    """
    # Domain detection and profile recommendation — reuse recommendation.py
    suspected = infer_domains(result)
    rec = recommend_profiles_from_inspect(result, profiles, limit=6)
    candidates = rec["recommended_profiles"]
    present_protocols = protocol_presence(result)

    # Protocol classification
    dominant = dominant_signaling_names(result)

    # Trace shape
    shape, shape_reasons = _trace_shape(suspected, result.protocol_counts, present_protocols)

    # Inspect-level anomaly heuristics (appended to existing transport/app anomalies)
    network_anomalies, classification_notes = _inspect_anomalies(
        result.protocol_counts,
        result.transport_counts,
        suspected,
        shape,
        present_protocols,
        candidates,
    )

    # Next-step hints
    hints = _next_step_hints(shape, suspected, candidates, result.metadata.packet_count)

    # Structured classification state — maps the combination of shape and confidence
    # to a machine-readable summary that is easier to act on than reading shape+notes.
    state = _classification_state(shape, suspected, classification_notes, candidates)

    return result.model_copy(update={
        "suspected_domains": suspected,
        "candidate_profiles": candidates,
        "dominant_signaling_protocols": dominant,
        "trace_shape": shape,
        "trace_shape_reasons": shape_reasons,
        "next_step_hints": hints,
        "anomalies": result.anomalies + network_anomalies,
        "classification_notes": classification_notes,
        "classification_state": state,
    })


def build_inspect_markdown(result: InspectResult) -> str:
    """Build a human-readable markdown report from an enriched InspectResult."""
    from datetime import datetime, timezone

    def _epoch_to_str(epoch: str | None) -> str:
        if not epoch:
            return "unknown"
        try:
            dt = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, OSError):
            return epoch

    lines: list[str] = [
        "# Inspect Report",
        "",
        "## Capture Overview",
        "",
        f"- File: `{result.metadata.capture_file}`",
        f"- Packets: {result.metadata.packet_count:,}",
        f"- First seen: {_epoch_to_str(result.metadata.first_seen_epoch)}",
        f"- Last seen: {_epoch_to_str(result.metadata.last_seen_epoch)}",
    ]
    if result.metadata.display_filter:
        lines.append(f"- Display filter: `{result.metadata.display_filter}`")

    state_label = result.classification_state.replace("_", " ").title()
    lines += [
        "",
        "## Trace Shape",
        "",
        f"**{result.trace_shape.replace('_', ' ').title()}**  "
        f"— classification state: `{result.classification_state}` ({state_label})",
    ]
    for reason in result.trace_shape_reasons:
        lines.append(f"- {reason}")

    lines += ["", "## Suspected Domains", ""]
    if result.suspected_domains:
        for d in result.suspected_domains:
            score_pct = int(d['score'] * 100)
            reasons = ", ".join(d.get("reason", []))
            lines.append(f"- **{d['domain']}** ({score_pct}% confidence): {reasons}")
    else:
        lines.append("- No strong domain signal detected.")

    lines += ["", "## Dominant Signaling Protocols", ""]
    if result.dominant_signaling_protocols:
        for proto in result.dominant_signaling_protocols:
            count = result.protocol_counts.get(proto, 0)
            lines.append(f"- `{proto}`: {count:,} packets")
    else:
        lines.append("- No significant signaling protocols detected.")

    lines += ["", "## Major Conversations", ""]
    if result.conversations:
        for conv in result.conversations[:8]:
            src = conv.get("src", "?")
            dst = conv.get("dst", "?")
            proto = conv.get("top_protocol", "?")
            transport = conv.get("transport", "?")
            count = conv.get("packet_count", 0)
            lines.append(f"- `{src}` → `{dst}` [{transport}/{proto}] {count:,} pkts")
    else:
        lines.append("- No conversations recorded.")

    lines += ["", "## Candidate Profiles", ""]
    if result.candidate_profiles:
        for p in result.candidate_profiles[:6]:
            score = p.get("score", 0)
            profile_name = p.get("profile", "?")
            reasons = ", ".join(p.get("reason", [])[:3])
            conf = "strong" if score >= 5 else ("medium" if score >= 2 else "weak")
            lines.append(f"- `{profile_name}` [{conf}]: {reasons}")
    else:
        lines.append("- No profile recommendations.")

    if result.classification_notes:
        lines += ["", "## Classification Notes", ""]
        for note in result.classification_notes:
            lines.append(f"- {note}")

    lines += ["", "## Notable Anomalies", ""]
    if result.anomalies:
        for a in result.anomalies[:10]:
            lines.append(f"- {a}")
    else:
        lines.append("- No anomalies detected.")

    lines += ["", "## Suggested Next Steps", ""]
    if result.next_step_hints:
        for hint in result.next_step_hints:
            lines.append(f"- {hint}")
    else:
        lines.append("- Run `pcap2llm analyze` with a focused profile.")

    return "\n".join(lines) + "\n"
