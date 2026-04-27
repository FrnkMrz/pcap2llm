from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pcap2llm.index_inspector import inspect_index_records, select_frame_numbers
from pcap2llm.models import AnalyzeArtifacts, ProfileDefinition
from pcap2llm.normalizer import normalize_packets
from pcap2llm.output_metadata import (
    artifact_timestamp_prefix as output_artifact_timestamp_prefix,
    artifact_identity_from_filename,
    artifact_version_from_filename,
    build_artifact_metadata,
    semantic_artifact_filename,
)
from pcap2llm.protector import Protector
from pcap2llm.reducer import reduce_packets
from pcap2llm.resolver import EndpointResolver
from pcap2llm.serializers import (
    build_coverage,
    build_markdown_summary,
    serialize_detail_artifact,
    serialize_summary_artifact,
)
from pcap2llm.summarizer import build_summary
from pcap2llm.tshark_runner import TSharkRunner
from pcap2llm.visualize import build_flow_model, render_flow_svg

# Signature: (description, current_step, total_steps)
OnStage = Callable[[str, int, int], None]

_ANALYZE_STEPS = 7
_DEFAULT_MAX_PACKETS = 1000
_DEFAULT_OVERSIZE_FACTOR = 10.0


@dataclass(frozen=True)
class SelectedPackets:
    detail_packets: list[dict]
    total_exported: int
    truncated: bool


def artifact_timestamp_prefix(first_seen_epoch: str | None) -> str | None:
    """Return a ``YYYYMMDD_HHMMSS`` prefix from a first-seen epoch string.

    Handles both Unix-epoch decimal strings (TShark < 4.6) and ISO 8601 with
    nanoseconds (TShark ≥ 4.6).  Returns ``None`` when the string cannot be
    parsed so callers can fall back to a wall-clock timestamp.

    This is the single shared source of truth for artifact timestamp prefixes
    across ``analyze`` and ``discover`` runs.
    """
    return _artifact_timestamp_prefix(first_seen_epoch)


def _artifact_timestamp_prefix(first_seen_epoch: str | None) -> str | None:
    return output_artifact_timestamp_prefix(first_seen_epoch)


def _resolve_output_paths(
    out_dir: Path,
    *,
    action: str,
    capture_path: str | Path,
    start_packet_number: int | None,
    first_seen: str | None,
    include_mapping: bool,
    include_vault: bool,
    include_flow_json: bool,
    include_flow_svg: bool,
) -> dict[str, Path]:
    stems = {
        "summary": ("summary", ".json"),
        "detail": ("detail", ".json"),
        "markdown": ("summary", ".md"),
    }
    if include_mapping:
        stems["mapping"] = ("pseudonym_mapping", ".json")
    if include_vault:
        stems["vault"] = ("vault", ".json")
    if include_flow_json:
        stems["flow_json"] = ("flow", ".json")
    if include_flow_svg:
        stems["flow_svg"] = ("flow", ".svg")

    version = 1
    while True:
        suffix = f"V_{version:02d}"
        outputs = {
            key: out_dir / semantic_artifact_filename(
                action=action,
                capture_path=capture_path,
                start_packet_number=start_packet_number,
                first_seen=first_seen,
                version=suffix,
                extension=extension,
                artifact_kind=stem,
            )
            for key, (stem, extension) in stems.items()
        }
        if not any(path.exists() for path in outputs.values()):
            return outputs
        version += 1


def describe_output_paths(outputs: dict[str, Path]) -> dict[str, str | int | None]:
    return artifact_identity_from_filename(outputs["summary"].name)


def analyze_capture(
    capture_path: Path,
    *,
    out_dir: Path,
    runner: TSharkRunner,
    profile: ProfileDefinition,
    privacy_modes: dict[str, str],
    display_filter: str | None = None,
    hosts_file: Path | None = None,
    mapping_file: Path | None = None,
    subnets_file: Path | None = None,
    ss7pcs_file: Path | None = None,
    network_element_mapping_file: Path | None = None,
    extra_args: list[str] | None = None,
    two_pass: bool = False,
    max_packets: int = _DEFAULT_MAX_PACKETS,
    fail_on_truncation: bool = False,
    max_capture_size_mb: int = 250,
    oversize_factor: float = _DEFAULT_OVERSIZE_FACTOR,
    render_flow_svg_artifact: bool = False,
    flow_title: str | None = None,
    flow_max_events: int = 120,
    flow_svg_width: int = 1600,
    collapse_repeats: bool = True,
    privacy_profile_name: str | None = None,
    on_stage: OnStage | None = None,
) -> AnalyzeArtifacts:
    """Run the full two-pass analysis pipeline.

    **Pass 1** runs a lightweight TShark ``-T fields`` export to build per-packet
    index records.  These are used for inspection (metadata, protocol counts,
    anomaly detection) and frame selection.  The pass-1 records are released
    after selection.

    **Pass 2** exports full JSON *only* for the selected frames and feeds them
    into normalization, reduction, protection, and serialization.

    **Pass 2 decision:**

    - When ``max_packets > 0`` (bounded run): always uses ``export_selected_packets``
      regardless of truncation.  Both truncated and non-truncated paths go through
      the same code, making pass-2 behavior consistent and predictable.
    - When ``max_packets <= 0`` (unlimited / ``--all-packets``): falls back to
      ``export_packets`` to avoid constructing a potentially enormous frame-number
      filter string across many TShark invocations.
    """
    def _step(msg: str, i: int) -> None:
        if on_stage:
            on_stage(msg, i, _ANALYZE_STEPS)

    _check_capture_size(capture_path, max_capture_size_mb=max_capture_size_mb)

    # ------------------------------------------------------------------
    # Pass 1: lightweight packet-index export
    # ------------------------------------------------------------------
    _step("Pass 1: exporting lightweight packet index via TShark…", 0)
    index_records = runner.export_packet_index(
        capture_path,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
    )

    resolver = EndpointResolver(
        hosts_file=hosts_file,
        mapping_file=mapping_file,
        subnets_file=subnets_file,
        ss7pcs_file=ss7pcs_file,
        network_element_mapping_file=network_element_mapping_file,
    )

    _step(f"Pass 1: inspecting {len(index_records):,} packets…", 1)
    inspect_result = inspect_index_records(
        index_records,
        capture_path=capture_path,
        display_filter=display_filter,
        profile=profile,
        resolver=resolver,
        hosts_file_used=hosts_file is not None,
        mapping_file_used=mapping_file is not None,
        subnets_file_used=subnets_file is not None,
        ss7pcs_file_used=ss7pcs_file is not None,
    )

    # Normalise privacy_modes so the rest of the pipeline always sees a dict.
    privacy_modes = privacy_modes or {}

    # Validate the vault key before starting expensive packet processing so
    # the user gets a clear error rather than a crash mid-pipeline.
    protector = Protector(privacy_modes)
    protector.validate_vault_key()

    # Oversize guard: uses pass-1 counts — same semantics as before.
    _check_oversize_ratio(
        len(index_records),
        max_packets,
        oversize_factor=oversize_factor,
    )

    selected_frames = select_frame_numbers(index_records, max_packets=max_packets)
    if selected_frames.truncated and fail_on_truncation:
        raise RuntimeError(
            f"detail export would be truncated at {max_packets:,} of "
            f"{selected_frames.total_exported:,} packets"
        )
    # Release pass-1 index records — downstream stages only need frame numbers
    # and the inspect_result already derived from them.
    del index_records

    # ------------------------------------------------------------------
    # Pass 2: full JSON export for selected frames only
    # ------------------------------------------------------------------
    detail_count = len(selected_frames.frame_numbers)
    total_exported = selected_frames.total_exported
    detail_label = (
        f"{detail_count:,}"
        if not selected_frames.truncated
        else f"{detail_count:,}/{total_exported:,}"
    )
    _step(f"Pass 2: exporting {detail_label} selected frames via TShark…", 2)

    if max_packets > 0:
        # Bounded run (max_packets set): always use selected-frame export,
        # whether or not the capture is truncated.  This makes the two-pass path
        # consistent — pass 2 always processes exactly the frames selected in
        # pass 1, with no hybrid fallback for the non-truncation case.
        detail_raw = runner.export_selected_packets(
            capture_path,
            frame_numbers=selected_frames.frame_numbers,
            extra_args=extra_args,
            two_pass=two_pass,
        )
    else:
        # Unlimited run (--all-packets, max_packets=0): export all packets via a
        # single TShark invocation.  Building a frame-number filter for a large
        # capture would require many chunked invocations — this is cheaper and
        # semantically equivalent since all frames are selected anyway.
        detail_raw = runner.export_packets(
            capture_path,
            display_filter=display_filter,
            extra_args=extra_args,
            two_pass=two_pass,
        )

    _step(f"Normalize stage: normalizing {detail_label} packets…", 3)
    normalized, dropped = normalize_packets(
        detail_raw,
        resolver=resolver,
        profile=profile,
        privacy_modes=privacy_modes,
    )
    del detail_raw  # release pass-2 raw JSON before protection

    _step("Protect stage: reducing and privacy-filtering packets…", 4)
    reduced = reduce_packets(normalized, profile)
    protected_packets = protector.protect_packets(reduced)
    _step("Summarize stage: building deterministic sidecar summary…", 5)
    summary_payload = build_summary(
        inspect_result,
        protected_packets,
        profile=profile,
        privacy_modes=privacy_modes,
    )
    summary_payload = protector.protect_artifact_payload(summary_payload)
    if dropped:
        summary_payload["dropped_packets"] = dropped
    if selected_frames.truncated:
        summary_payload["detail_truncated"] = {
            "included": max_packets,
            "total_exported": selected_frames.total_exported,
            "note": selected_frames.truncation_note or (
                f"detail.json contains only the first {max_packets:,} of "
                f"{selected_frames.total_exported:,} packets. Use --all-packets to include all."
            ),
        }
    audit = protector.pseudonym_audit()
    if audit:
        summary_payload["privacy_audit"] = {"pseudonymized_unique_values": audit}

    try:
        sha256 = hashlib.sha256(capture_path.read_bytes()).hexdigest()
    except OSError:
        sha256 = None  # PCAP may not be accessible after export (e.g. stdin pipe)

    coverage = build_coverage(
        detail_packets_included=len(protected_packets),
        detail_packets_available=selected_frames.total_exported,
        summary_packet_count=inspect_result.metadata.packet_count,
    )

    _step("Serialize stage: validating public artifacts…", 6)
    summary = serialize_summary_artifact(
        inspect_result=inspect_result,
        profile=profile,
        summary_payload=summary_payload,
        coverage=coverage,
        privacy_policy=protector.policy_metadata(),
        capture_sha256=sha256,
        selection_start_packet=selected_frames.frame_numbers[0] if selected_frames.frame_numbers else None,
        selection_end_packet=selected_frames.frame_numbers[-1] if selected_frames.frame_numbers else None,
    )
    detail = serialize_detail_artifact(
        inspect_result=inspect_result,
        profile=profile,
        packets=protected_packets,
        coverage=coverage,
        capture_sha256=sha256,
        selection_start_packet=selected_frames.frame_numbers[0] if selected_frames.frame_numbers else None,
        selection_end_packet=selected_frames.frame_numbers[-1] if selected_frames.frame_numbers else None,
    )
    mapping_filename = "pseudonym_mapping.json" if protector.pseudonyms else None
    vault_filename = "vault.json" if protector.vault_metadata() else None
    markdown = build_markdown_summary(
        summary,
        detail_filename="detail.json",
        mapping_filename=mapping_filename,
        vault_filename=vault_filename,
    )
    flow: dict[str, object] | None = None
    flow_svg: str | None = None
    if render_flow_svg_artifact:
        flow = build_flow_model(
            protected_packets,
            capture_file=str(capture_path),
            profile=profile.name,
            privacy_profile=privacy_profile_name,
            max_events=flow_max_events,
            title=flow_title,
            collapse_repeats=collapse_repeats,
        )
        flow_svg = render_flow_svg(flow, width=flow_svg_width)

    return AnalyzeArtifacts(
        summary=summary,
        detail=detail,
        markdown=markdown,
        pseudonym_mapping=protector.pseudonyms,
        vault=protector.vault_metadata(),
        flow=flow,
        flow_svg=flow_svg,
    )


def _export_packets(
    capture_path: Path,
    *,
    runner: TSharkRunner,
    display_filter: str | None,
    extra_args: list[str] | None,
    two_pass: bool,
) -> list[dict]:
    return runner.export_packets(
        capture_path,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
    )


def _check_capture_size(capture_path: Path, *, max_capture_size_mb: int) -> None:
    if max_capture_size_mb <= 0:
        return
    try:
        size_bytes = capture_path.stat().st_size
    except OSError:
        return
    limit_bytes = max_capture_size_mb * 1024 * 1024
    if size_bytes > limit_bytes:
        actual_mib = size_bytes / (1024 * 1024)
        raise RuntimeError(
            f"capture file is {actual_mib:.1f} MiB, which exceeds --max-capture-size-mb "
            f"{max_capture_size_mb}. Narrow the trace first or rerun with a larger limit."
        )


def _check_oversize_ratio(
    total_exported: int,
    max_packets: int,
    *,
    oversize_factor: float,
) -> None:
    """Raise if total_exported exceeds max_packets by more than oversize_factor.

    Guards against accidentally expensive runs where the packet limit would
    silently discard most of the exported data.  Setting *oversize_factor* to
    0 (or any non-positive value) disables the guard entirely.
    """
    if oversize_factor <= 0 or max_packets <= 0:
        return
    if total_exported > max_packets * oversize_factor:
        ratio = total_exported / max_packets
        raise RuntimeError(
            f"capture exported {total_exported:,} packets but detail limit is "
            f"{max_packets:,} ({ratio:.0f}× oversize). "
            f"Narrow with -Y before analyzing, or set --oversize-factor 0 to bypass."
        )


def _select_packets(raw_packets: list[dict], *, max_packets: int) -> SelectedPackets:
    total_exported = len(raw_packets)
    truncated = max_packets > 0 and total_exported > max_packets
    detail_packets = raw_packets[:max_packets] if truncated else raw_packets
    return SelectedPackets(
        detail_packets=detail_packets,
        total_exported=total_exported,
        truncated=truncated,
    )


def write_artifacts(artifacts: AnalyzeArtifacts, out_dir: Path) -> dict[str, Path]:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Cannot create output directory '{out_dir}': {exc}") from exc

    outputs = _resolve_output_paths(
        out_dir,
        action=artifacts.summary.get("run", {}).get("action", "analyze"),
        capture_path=artifacts.summary.get("capture", {}).get("path")
        or artifacts.summary.get("capture_metadata", {}).get("capture_file", "capture"),
        start_packet_number=(
            artifacts.summary.get("selection", {}).get("start_packet_number")
            or artifacts.summary.get("capture", {}).get("first_packet_number")
        ),
        first_seen=artifacts.summary.get("capture", {}).get("first_seen"),
        include_mapping=bool(artifacts.pseudonym_mapping),
        include_vault=bool(artifacts.vault),
        include_flow_json=bool(artifacts.flow),
        include_flow_svg=bool(artifacts.flow_svg),
    )
    artifact_version = artifact_version_from_filename(outputs["summary"].name)
    artifacts.summary["artifact"] = build_artifact_metadata(artifact_version)
    artifacts.detail["artifact"] = build_artifact_metadata(artifact_version)
    markdown = build_markdown_summary(
        artifacts.summary,
        summary_filename=outputs["summary"].name,
        detail_filename=outputs["detail"].name,
        mapping_filename=outputs.get("mapping", None).name if outputs.get("mapping") else None,
        vault_filename=outputs.get("vault", None).name if outputs.get("vault") else None,
    )
    try:
        outputs["summary"].write_text(json.dumps(artifacts.summary, indent=2), encoding="utf-8")
        outputs["detail"].write_text(json.dumps(artifacts.detail, indent=2), encoding="utf-8")
        outputs["markdown"].write_text(markdown, encoding="utf-8")
        if artifacts.pseudonym_mapping:
            outputs["mapping"].write_text(
                json.dumps(artifacts.pseudonym_mapping, indent=2),
                encoding="utf-8",
            )
        if artifacts.vault:
            outputs["vault"].write_text(json.dumps(artifacts.vault, indent=2), encoding="utf-8")
        if artifacts.flow:
            outputs["flow_json"].write_text(json.dumps(artifacts.flow, indent=2), encoding="utf-8")
        if artifacts.flow_svg:
            outputs["flow_svg"].write_text(artifacts.flow_svg, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Failed to write artifacts to '{out_dir}': {exc}") from exc
    return outputs
