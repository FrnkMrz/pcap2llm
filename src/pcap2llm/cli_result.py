from __future__ import annotations

from pathlib import Path
from typing import Any


def build_warning(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def build_dry_run_payload(
    *,
    capture: Path,
    profile: str,
    privacy_profile: str | None,
    display_filter: str | None,
    max_packets: int,
    all_packets: bool,
    fail_on_truncation: bool,
    max_capture_size_mb: int,
    oversize_factor: float,
    privacy_modes: dict[str, str],
    hosts_file: Path | None,
    mapping_file: Path | None,
    subnets_file: Path | None,
    ss7pcs_file: Path | None,
    command: list[str],
    llm_mode: bool,
    effective_verbatim_protocols: list[str],
    effective_profile_overrides: dict[str, Any],
    render_flow_svg: bool,
    flow_max_events: int,
    flow_svg_width: int,
    flow_title: str | None,
    collapse_repeats: bool,
) -> dict[str, Any]:
    return {
        "status": "ok",
        "mode": "llm" if llm_mode else "default",
        "dry_run": True,
        "capture": {"path": str(capture)},
        "profile": profile,
        "privacy_profile": privacy_profile,
        "display_filter": display_filter,
        "limits": {
            "max_packets": max_packets,
            "all_packets": all_packets,
            "fail_on_truncation": fail_on_truncation,
            "max_capture_size_mb": max_capture_size_mb,
            "oversize_factor": oversize_factor,
            "render_flow_svg": render_flow_svg,
            "flow_max_events": flow_max_events,
            "flow_svg_width": flow_svg_width,
            "collapse_repeats": collapse_repeats,
        },
        "flow_title": flow_title,
        "privacy_modes": privacy_modes,
        "effective_verbatim_protocols": effective_verbatim_protocols,
        "effective_profile_overrides": effective_profile_overrides,
        "files_would_be_written": True,
        "hosts_file": str(hosts_file) if hosts_file else None,
        "mapping_file": str(mapping_file) if mapping_file else None,
        "subnets_file": str(subnets_file) if subnets_file else None,
        "ss7pcs_file": str(ss7pcs_file) if ss7pcs_file else None,
        "command": command,
    }


def build_success_payload(
    *,
    capture: Path,
    capture_sha256: str | None,
    profile: str,
    privacy_profile: str | None,
    outputs: dict[str, Path],
    artifact_identity: dict[str, str | int | None],
    coverage: dict[str, Any],
    limits: dict[str, Any],
    warnings: list[dict[str, str]],
    schema_versions: dict[str, str],
    effective_verbatim_protocols: list[str],
    effective_profile_overrides: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": "ok",
        "mode": "llm",
        "profile": profile,
        "privacy_profile": privacy_profile,
        "capture": {
            "path": str(capture),
            "sha256": capture_sha256,
        },
        "artifact_prefix": artifact_identity.get("artifact_prefix"),
        "artifact_version": artifact_identity.get("artifact_version"),
        "files": {
            "summary": str(outputs["summary"]),
            "detail": str(outputs["detail"]),
            "markdown": str(outputs["markdown"]),
            "mapping": str(outputs["mapping"]) if outputs.get("mapping") else None,
            "vault": str(outputs["vault"]) if outputs.get("vault") else None,
            "flow_json": str(outputs["flow_json"]) if outputs.get("flow_json") else None,
            "flow_svg": str(outputs["flow_svg"]) if outputs.get("flow_svg") else None,
        },
        "coverage": coverage,
        "warnings": warnings,
        "limits": limits,
        "effective_verbatim_protocols": effective_verbatim_protocols,
        "effective_profile_overrides": effective_profile_overrides,
        "schema_versions": schema_versions,
    }


def build_error_payload(
    *,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    warnings: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "error",
        "mode": "llm",
        "error": {
            "code": code,
            "message": message,
        },
    }
    if details:
        payload["error"]["details"] = details
    if warnings:
        payload["warnings"] = warnings
    return payload
