from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from pcap2llm.models import AnalyzeArtifacts, ProfileDefinition

# Signature: (description, current_step, total_steps)
OnStage = Callable[[str, int, int], None]

_ANALYZE_STEPS = 5
from pcap2llm.normalizer import inspect_raw_packets, normalize_packets
from pcap2llm.protector import Protector
from pcap2llm.reducer import reduce_packets
from pcap2llm.resolver import EndpointResolver
from pcap2llm.summarizer import build_markdown_summary, build_summary
from pcap2llm.tshark_runner import TSharkRunner


_DEFAULT_MAX_PACKETS = 1000


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

    _step("Exporting packets via TShark…", 0)
    raw_packets = runner.export_packets(
        capture_path,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
    )
    total_exported = len(raw_packets)

    _step(f"Inspecting {total_exported:,} packets…", 1)
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

    # Apply the packet limit *after* inspection so summary stats stay accurate.
    truncated = max_packets > 0 and total_exported > max_packets
    detail_packets = raw_packets[:max_packets] if truncated else raw_packets

    detail_label = f"{len(detail_packets):,}" if not truncated else f"{max_packets:,}/{total_exported:,}"
    _step(f"Normalizing {detail_label} packets…", 2)
    normalized, dropped = normalize_packets(
        detail_packets,
        resolver=resolver,
        profile=profile,
        privacy_modes=privacy_modes,
    )
    _step("Reducing & protecting packets…", 3)
    reduced = reduce_packets(normalized, profile)
    protected_packets = protector.protect_packets(reduced)
    _step("Building summary…", 4)
    summary = build_summary(
        inspect_result,
        protected_packets,
        profile=profile,
        privacy_modes=privacy_modes,
    )
    if dropped:
        summary["dropped_packets"] = dropped
    if truncated:
        summary["detail_truncated"] = {
            "included": max_packets,
            "total_exported": total_exported,
            "note": (
                f"detail.json contains only the first {max_packets:,} of "
                f"{total_exported:,} packets. Use --all-packets to include all."
            ),
        }
    audit = protector.pseudonym_audit()
    if audit:
        summary["privacy_audit"] = {"pseudonymized_unique_values": audit}

    # Processing fingerprint – aids reproducibility and audit
    summary["schema_version"] = "0.1"
    summary["generated_at"] = datetime.now(timezone.utc).isoformat()
    try:
        sha256 = hashlib.sha256(capture_path.read_bytes()).hexdigest()
        summary["capture_sha256"] = sha256
    except OSError:
        pass  # PCAP may not be accessible after export (e.g. stdin pipe)

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
        detail={
            "schema_version": "0.1",
            "profile": profile.name,
            "selected_packets": protected_packets,
        },
        markdown=markdown,
        pseudonym_mapping=protector.pseudonyms,
        vault=protector.vault_metadata(),
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
