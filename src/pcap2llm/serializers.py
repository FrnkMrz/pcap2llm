from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pcap2llm.models import (
    ArtifactCoverage,
    DetailArtifactV1,
    InspectResult,
    ProfileDefinition,
    SCHEMA_VERSION,
    SummaryArtifactV1,
)


def _generated_at() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_coverage(
    *,
    detail_packets_included: int,
    detail_packets_available: int,
    summary_packet_count: int,
) -> ArtifactCoverage:
    truncated = detail_packets_included < detail_packets_available
    note = None
    if truncated:
        note = (
            f"detail artifact contains {detail_packets_included:,} of "
            f"{detail_packets_available:,} exported packets."
        )
    return ArtifactCoverage(
        detail_packets_included=detail_packets_included,
        detail_packets_available=detail_packets_available,
        detail_truncated=truncated,
        summary_packet_count=summary_packet_count,
        truncation_note=note,
    )


def serialize_summary_artifact(
    *,
    inspect_result: InspectResult,
    profile: ProfileDefinition,
    summary_payload: dict[str, Any],
    coverage: ArtifactCoverage,
    privacy_policy: dict[str, Any],
    capture_sha256: str | None,
) -> dict[str, Any]:
    artifact = SummaryArtifactV1(
        schema_version=SCHEMA_VERSION,
        generated_at=_generated_at(),
        capture_sha256=capture_sha256,
        profile=profile.name,
        capture_metadata=inspect_result.metadata.model_dump(),
        relevant_protocols=summary_payload.get("relevant_protocols", []),
        conversations=summary_payload.get("conversations", []),
        packet_message_counts=summary_payload.get("packet_message_counts", {}),
        anomalies=summary_payload.get("anomalies", []),
        anomaly_counts_by_layer=summary_payload.get("anomaly_counts_by_layer", {}),
        deterministic_findings=summary_payload.get("deterministic_findings", []),
        probable_notable_findings=summary_payload.get("probable_notable_findings", []),
        privacy_modes=summary_payload.get("privacy_modes", {}),
        privacy_policy=privacy_policy,
        coverage=coverage,
        timing_stats=summary_payload.get("timing_stats"),
        burst_periods=summary_payload.get("burst_periods", []),
        dropped_packets=summary_payload.get("dropped_packets"),
        detail_truncated=summary_payload.get("detail_truncated"),
        privacy_audit=summary_payload.get("privacy_audit"),
    )
    return artifact.model_dump(exclude_none=True)


def serialize_detail_artifact(
    *,
    profile: ProfileDefinition,
    packets: list[dict[str, Any]],
    coverage: ArtifactCoverage,
    capture_sha256: str | None,
) -> dict[str, Any]:
    artifact = DetailArtifactV1(
        schema_version=SCHEMA_VERSION,
        generated_at=_generated_at(),
        capture_sha256=capture_sha256,
        profile=profile.name,
        coverage=coverage,
        messages=packets,
        selected_packets=packets,
    )
    return artifact.model_dump()


def build_markdown_summary(
    summary: dict[str, Any],
    *,
    summary_filename: str = "summary.json",
    detail_filename: str = "detail.json",
    mapping_filename: str | None = None,
    vault_filename: str | None = None,
) -> str:
    metadata = summary["capture_metadata"]
    coverage = summary.get(
        "coverage",
        {
            "detail_packets_included": metadata.get("packet_count", 0),
            "detail_packets_available": metadata.get("packet_count", 0),
            "detail_truncated": False,
        },
    )
    lines = [
        "# PCAP2LLM Artifact Summary",
        "",
        "pcap2llm formats traces into a stable handoff artifact for downstream LLM reasoning.",
        "This tool does not perform generative analysis itself.",
        "",
        "## Capture Overview",
        f"- Capture file: `{metadata['capture_file']}`",
        f"- Summary packet count: `{metadata['packet_count']}`",
        f"- Detail packets included: `{coverage['detail_packets_included']}`",
        f"- Detail packets available after export: `{coverage['detail_packets_available']}`",
        f"- Detail truncated: `{coverage['detail_truncated']}`",
        f"- Relevant protocols: `{', '.join(metadata['relevant_protocols']) or 'none detected'}`",
        f"- Display filter: `{metadata['display_filter'] or 'none'}`",
        "",
        "## Deterministic Findings",
    ]
    findings = summary.get("deterministic_findings") or ["No deterministic high-signal findings generated."]
    for finding in findings:
        lines.append(f"- {finding}")
    lines.extend(["", "## Privacy Model"])
    for data_class, mode in summary["privacy_modes"].items():
        lines.append(f"- `{data_class}`: `{mode}`")
    lines.extend(
        [
            "",
            "## Artifact Roles",
            f"- `{detail_filename}`: primary LLM handoff artifact",
            f"- `{summary_filename}`: compact sidecar with counts, coverage, and policy metadata",
        ]
    )
    if mapping_filename:
        lines.append(f"- `{mapping_filename}`: pseudonym mapping sidecar")
    if vault_filename:
        lines.append(f"- `{vault_filename}`: encryption metadata sidecar")
    return "\n".join(lines) + "\n"
