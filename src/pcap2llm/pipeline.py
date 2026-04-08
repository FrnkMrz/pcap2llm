from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pcap2llm.models import AnalyzeArtifacts, ProfileDefinition
from pcap2llm.normalizer import inspect_raw_packets, normalize_packets
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

# Signature: (description, current_step, total_steps)
OnStage = Callable[[str, int, int], None]

_ANALYZE_STEPS = 7
_DEFAULT_MAX_PACKETS = 1000


@dataclass(frozen=True)
class SelectedPackets:
    detail_packets: list[dict]
    total_exported: int
    truncated: bool


def _artifact_timestamp_prefix(first_seen_epoch: str | None) -> str | None:
    if not first_seen_epoch:
        return None

    try:
        packet_time = datetime.fromtimestamp(float(first_seen_epoch), tz=timezone.utc)
    except (OverflowError, ValueError):
        return None

    return packet_time.strftime("%Y%m%d_%H%M%S")


def _artifact_filename(prefix: str | None, stem: str, suffix: str, extension: str) -> str:
    parts = [part for part in (prefix, stem, suffix) if part]
    return "_".join(parts) + extension


def _resolve_output_paths(
    out_dir: Path,
    *,
    first_seen_epoch: str | None,
    include_mapping: bool,
    include_vault: bool,
) -> dict[str, Path]:
    prefix = _artifact_timestamp_prefix(first_seen_epoch)
    stems = {
        "summary": ("summary", ".json"),
        "detail": ("detail", ".json"),
        "markdown": ("summary", ".md"),
    }
    if include_mapping:
        stems["mapping"] = ("pseudonym_mapping", ".json")
    if include_vault:
        stems["vault"] = ("vault", ".json")

    version = 1
    while True:
        suffix = f"V_{version:02d}"
        outputs = {
            key: out_dir / _artifact_filename(prefix, stem, suffix, extension)
            for key, (stem, extension) in stems.items()
        }
        if not any(path.exists() for path in outputs.values()):
            return outputs
        version += 1


def describe_output_paths(outputs: dict[str, Path]) -> dict[str, str | int | None]:
    summary_name = outputs["summary"].name
    match = re.fullmatch(
        r"(?:(?P<prefix>\d{8}_\d{6})_)?summary_V_(?P<version>\d+)\.json",
        summary_name,
    )
    if not match:
        return {"artifact_prefix": None, "artifact_version": None}

    return {
        "artifact_prefix": match.group("prefix"),
        "artifact_version": int(match.group("version")),
    }


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
    extra_args: list[str] | None = None,
    two_pass: bool = False,
    max_packets: int = _DEFAULT_MAX_PACKETS,
    fail_on_truncation: bool = False,
    max_capture_size_mb: int = 250,
    on_stage: OnStage | None = None,
) -> AnalyzeArtifacts:
    """Run the full analysis pipeline.

    *max_packets* controls how many packets end up in ``detail.json``.
    Inspection (metadata, anomaly detection) always runs on the full capture
    so that ``summary.json`` remains accurate.  Pass ``max_packets=0`` to
    include every exported packet in the detail output.
    """
    def _step(msg: str, i: int) -> None:
        if on_stage:
            on_stage(msg, i, _ANALYZE_STEPS)

    _check_capture_size(capture_path, max_capture_size_mb=max_capture_size_mb)

    _step("Inspect stage: exporting packets via TShark…", 0)
    raw_packets = _export_packets(
        capture_path,
        runner=runner,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
    )

    _step(f"Inspect stage: inspecting {len(raw_packets):,} packets…", 1)
    inspect_result = inspect_raw_packets(
        raw_packets,
        capture_path=capture_path,
        display_filter=display_filter,
        profile=profile,
    )
    resolver = EndpointResolver(hosts_file=hosts_file, mapping_file=mapping_file)

    # Normalise privacy_modes so the rest of the pipeline always sees a dict.
    privacy_modes = privacy_modes or {}

    # Validate the vault key before starting expensive packet processing so
    # the user gets a clear error rather than a crash mid-pipeline.
    protector = Protector(privacy_modes)
    protector.validate_vault_key()

    _step("Select stage: applying bounded detail export policy…", 2)
    selected = _select_packets(raw_packets, max_packets=max_packets)
    if selected.truncated and fail_on_truncation:
        raise RuntimeError(
            f"detail export would be truncated at {max_packets:,} of "
            f"{selected.total_exported:,} packets"
        )

    detail_label = (
        f"{len(selected.detail_packets):,}"
        if not selected.truncated
        else f"{len(selected.detail_packets):,}/{selected.total_exported:,}"
    )
    _step(f"Normalize stage: normalizing {detail_label} packets…", 3)
    normalized, dropped = normalize_packets(
        selected.detail_packets,
        resolver=resolver,
        profile=profile,
        privacy_modes=privacy_modes,
    )
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
    if dropped:
        summary_payload["dropped_packets"] = dropped
    if selected.truncated:
        summary_payload["detail_truncated"] = {
            "included": max_packets,
            "total_exported": selected.total_exported,
            "note": (
                f"detail.json contains only the first {max_packets:,} of "
                f"{selected.total_exported:,} packets. Use --all-packets to include all."
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
        detail_packets_available=selected.total_exported,
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
    )
    detail = serialize_detail_artifact(
        profile=profile,
        packets=protected_packets,
        coverage=coverage,
        capture_sha256=sha256,
    )
    mapping_filename = "pseudonym_mapping.json" if protector.pseudonyms else None
    vault_filename = "vault.json" if protector.vault_metadata() else None
    markdown = build_markdown_summary(
        summary,
        detail_filename="detail.json",
        mapping_filename=mapping_filename,
        vault_filename=vault_filename,
    )
    return AnalyzeArtifacts(
        summary=summary,
        detail=detail,
        markdown=markdown,
        pseudonym_mapping=protector.pseudonyms,
        vault=protector.vault_metadata(),
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
        first_seen_epoch=artifacts.summary.get("capture_metadata", {}).get("first_seen_epoch"),
        include_mapping=bool(artifacts.pseudonym_mapping),
        include_vault=bool(artifacts.vault),
    )
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
    except OSError as exc:
        raise RuntimeError(f"Failed to write artifacts to '{out_dir}': {exc}") from exc
    return outputs
