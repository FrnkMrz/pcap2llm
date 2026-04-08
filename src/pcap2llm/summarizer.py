from __future__ import annotations

from collections import Counter
from typing import Any

from pcap2llm.models import InspectResult, ProfileDefinition
from pcap2llm.serializers import build_markdown_summary as _build_markdown_summary


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------

def _timing_stats(detail_packets: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Compute inter-packet timing statistics from normalized packet list."""
    times = sorted(
        p["time_rel_ms"]
        for p in detail_packets
        if isinstance(p.get("time_rel_ms"), (int, float))
    )
    if len(times) < 2:
        return None
    diffs = sorted(times[i + 1] - times[i] for i in range(len(times) - 1))
    n = len(diffs)
    p95_idx = min(int(n * 0.95), n - 1)
    return {
        "packet_count": len(times),
        "duration_ms": round(times[-1] - times[0], 3),
        "inter_packet_ms": {
            "min": round(diffs[0], 3),
            "max": round(diffs[-1], 3),
            "mean": round(sum(diffs) / n, 3),
            "p95": round(diffs[p95_idx], 3),
        },
    }


def _detect_bursts(
    detail_packets: list[dict[str, Any]],
    *,
    threshold_ms: float = 1000.0,
    min_burst_size: int = 5,
) -> list[dict[str, Any]]:
    """Find groups of packets arriving within *threshold_ms* of each other.

    Returns a list of burst descriptors ``{start_ms, end_ms, packet_count}``.
    """
    sorted_times = sorted(
        p["time_rel_ms"]
        for p in detail_packets
        if isinstance(p.get("time_rel_ms"), (int, float))
    )
    if len(sorted_times) < min_burst_size:
        return []

    bursts: list[dict[str, Any]] = []
    burst_start = sorted_times[0]
    burst_count = 1

    for i in range(1, len(sorted_times)):
        gap = sorted_times[i] - sorted_times[i - 1]
        if gap <= threshold_ms:
            burst_count += 1
        else:
            if burst_count >= min_burst_size:
                bursts.append(
                    {
                        "start_ms": round(burst_start, 3),
                        "end_ms": round(sorted_times[i - 1], 3),
                        "packet_count": burst_count,
                    }
                )
            burst_start = sorted_times[i]
            burst_count = 1

    if burst_count >= min_burst_size:
        bursts.append(
            {
                "start_ms": round(burst_start, 3),
                "end_ms": round(sorted_times[-1], 3),
                "packet_count": burst_count,
            }
        )
    return bursts


# ---------------------------------------------------------------------------
# Anomaly classification helper
# ---------------------------------------------------------------------------

def _classify_anomalies(anomalies: list[str]) -> dict[str, int]:
    """Count anomalies by layer tag (e.g. 'transport', 'diameter', 'gtpv2')."""
    counts: dict[str, int] = {}
    for entry in anomalies:
        if entry.startswith("[") and "]" in entry:
            layer = entry[1:entry.index("]")]
            counts[layer] = counts.get(layer, 0) + 1
        else:
            counts.setdefault("transport", 0)
            counts["transport"] += 1
    return counts


# ---------------------------------------------------------------------------
# Main summary builder
# ---------------------------------------------------------------------------

def build_summary(
    inspect_result: InspectResult,
    detail_packets: list[dict[str, Any]],
    *,
    profile: ProfileDefinition,
    privacy_modes: dict[str, str],
) -> dict[str, Any]:
    top_protocols = Counter(packet["top_protocol"] for packet in detail_packets)
    deterministic_findings: list[str] = []

    # Anomaly summary — grouped by layer
    if inspect_result.anomalies:
        by_layer = _classify_anomalies(inspect_result.anomalies)
        total = sum(by_layer.values())
        layer_summary = ", ".join(f"{layer}: {n}" for layer, n in sorted(by_layer.items()))
        deterministic_findings.append(
            f"{total} anomalies detected ({layer_summary})"
        )

    for protocol, count in top_protocols.most_common(3):
        deterministic_findings.append(f"{protocol} accounts for {count} normalized packets")

    # Timing statistics
    timing = _timing_stats(detail_packets)
    if timing:
        p95 = timing["inter_packet_ms"]["p95"]
        if p95 > 500:
            deterministic_findings.append(
                f"High p95 inter-packet delay: {p95} ms — possible congestion or gaps"
            )

    # Burst detection
    bursts = _detect_bursts(detail_packets)
    if bursts:
        deterministic_findings.append(
            f"{len(bursts)} burst period(s) detected (≥5 packets within 1 s)"
        )

    summary: dict[str, Any] = {
        "capture_metadata": inspect_result.metadata.model_dump(),
        "relevant_protocols": inspect_result.metadata.relevant_protocols,
        "conversations": inspect_result.conversations,
        "packet_message_counts": {
            "total_packets": inspect_result.metadata.packet_count,
            "top_protocols": dict(top_protocols),
            "transport": inspect_result.transport_counts,
        },
        "anomalies": inspect_result.anomalies,
        "anomaly_counts_by_layer": _classify_anomalies(inspect_result.anomalies),
        "deterministic_findings": deterministic_findings,
        "probable_notable_findings": deterministic_findings,
        "profile": profile.name,
        "privacy_modes": privacy_modes,
    }
    if timing:
        summary["timing_stats"] = timing
    if bursts:
        summary["burst_periods"] = bursts
    return summary


def build_markdown_summary(*args: Any, **kwargs: Any) -> str:
    return _build_markdown_summary(*args, **kwargs)
