from __future__ import annotations

from collections import Counter
from typing import Any

from pcap2llm.models import InspectResult, ProfileDefinition


def build_summary(
    inspect_result: InspectResult,
    detail_packets: list[dict[str, Any]],
    *,
    profile: ProfileDefinition,
    privacy_modes: dict[str, str],
) -> dict[str, Any]:
    top_protocols = Counter(packet["top_protocol"] for packet in detail_packets)
    notable_findings: list[str] = []
    if inspect_result.anomalies:
        notable_findings.append(f"{len(inspect_result.anomalies)} transport anomalies detected")
    for protocol, count in top_protocols.most_common(3):
        notable_findings.append(f"{protocol} accounts for {count} normalized packets")

    return {
        "capture_metadata": inspect_result.metadata.model_dump(),
        "relevant_protocols": inspect_result.metadata.relevant_protocols,
        "conversations": inspect_result.conversations,
        "packet_message_counts": {
            "total_packets": inspect_result.metadata.packet_count,
            "top_protocols": dict(top_protocols),
            "transport": inspect_result.transport_counts,
        },
        "anomalies": inspect_result.anomalies,
        "probable_notable_findings": notable_findings,
        "profile": profile.name,
        "privacy_modes": privacy_modes,
    }


def build_markdown_summary(
    summary: dict[str, Any],
    *,
    detail_filename: str = "detail.json",
    mapping_filename: str | None = None,
    vault_filename: str | None = None,
) -> str:
    metadata = summary["capture_metadata"]
    lines = [
        "# PCAP2LLM Summary",
        "",
        "## Capture Overview",
        f"- Capture file: `{metadata['capture_file']}`",
        f"- Packet count: `{metadata['packet_count']}`",
        f"- Relevant protocols: `{', '.join(metadata['relevant_protocols']) or 'none detected'}`",
        f"- Display filter: `{metadata['display_filter'] or 'none'}`",
        "",
        "## Protocol Mix",
    ]
    for protocol, count in summary["packet_message_counts"]["top_protocols"].items():
        lines.append(f"- `{protocol}`: `{count}`")
    lines.extend(["", "## Notable Findings"])
    findings = summary["probable_notable_findings"] or ["No high-signal findings detected."]
    for finding in findings:
        lines.append(f"- {finding}")
    lines.extend(["", "## Privacy Model"])
    for data_class, mode in summary["privacy_modes"].items():
        lines.append(f"- `{data_class}`: `{mode}`")
    lines.extend(
        [
            "",
            "## File References",
            "- `summary.json`",
            f"- `{detail_filename}`",
        ]
    )
    if mapping_filename:
        lines.append(f"- `{mapping_filename}`")
    if vault_filename:
        lines.append(f"- `{vault_filename}`")
    return "\n".join(lines) + "\n"
