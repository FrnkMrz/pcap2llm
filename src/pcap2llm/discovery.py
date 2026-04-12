from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pcap2llm.inspector import inspect_capture
from pcap2llm.models import InspectResult, ProfileDefinition
from pcap2llm.output_metadata import (
    semantic_artifact_filename,
    build_artifact_metadata,
    build_capture_metadata,
    build_run_metadata,
)
from pcap2llm.profiles import load_all_profiles
from pcap2llm.recommendation import recommend_profiles_from_inspect
from pcap2llm.signaling import capture_context, discovery_relevant_protocols, dominant_signaling_protocols
from pcap2llm.tshark_runner import TSharkRunner


def build_discovery_profile() -> ProfileDefinition:
    profiles = load_all_profiles()
    relevant: list[str] = []
    priority: list[str] = []
    aliases: dict[str, list[str]] = {}
    for profile in profiles:
        for proto in profile.relevant_protocols:
            if proto not in relevant:
                relevant.append(proto)
        for proto in profile.top_protocol_priority:
            if proto not in priority:
                priority.append(proto)
        for key, values in profile.protocol_aliases.items():
            merged = aliases.setdefault(key, [])
            for value in values:
                if value not in merged:
                    merged.append(value)

    for fallback in ("sip", "diameter", "gtpv2", "ngap", "nas-5gs", "http", "json", "dns", "map", "cap", "isup", "sctp", "tcp", "udp", "ip"):
        if fallback not in priority:
            priority.append(fallback)
        if fallback not in relevant:
            relevant.append(fallback)

    return ProfileDefinition.model_validate(
        {
            "name": "discovery",
            "description": "Broad discovery profile for agent-ready orchestration.",
            "relevant_protocols": relevant,
            "top_protocol_priority": priority,
            "protocol_aliases": aliases,
            "full_detail_fields": {},
            "verbatim_protocols": [],
            "reduced_transport_fields": ["proto", "src_port", "dst_port", "stream", "sctp_stream", "anomaly", "notes"],
            "tshark": {"two_pass": False, "extra_args": []},
            "summary_heuristics": ["Discovery mode is broad and cheap; use it to choose focused follow-up profiles."],
            "max_conversations": 50,
        }
    )


def _capture_sha256(capture_path: Path) -> str | None:
    try:
        return hashlib.sha256(capture_path.read_bytes()).hexdigest()
    except OSError:
        return None


def build_discovery_payload(
    *,
    capture_path: Path,
    inspect_result: InspectResult,
    candidate_profiles: dict[str, Any],
) -> dict[str, Any]:
    primary_domain = candidate_profiles["suspected_domains"][0]["domain"] if candidate_profiles["suspected_domains"] else None
    top_protocols = [
        {"name": name, "count": count}
        for name, count in sorted(
            inspect_result.protocol_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]
    ]
    dominant = dominant_signaling_protocols(inspect_result, primary_domain=primary_domain)
    relevant_protocols = discovery_relevant_protocols(inspect_result, primary_domain=primary_domain)
    context = capture_context(inspect_result)
    resolved_peers = inspect_result.metadata.resolved_peers[:10]
    name_resolution = {
        "hosts_file_used": inspect_result.metadata.hosts_file_used,
        "mapping_file_used": inspect_result.metadata.mapping_file_used,
        "resolved_peer_count": len(inspect_result.metadata.resolved_peers),
    }
    capture = build_capture_metadata(
        path=capture_path,
        first_packet_number=inspect_result.metadata.first_packet_number,
        first_seen=inspect_result.metadata.first_seen_epoch,
        last_seen=inspect_result.metadata.last_seen_epoch,
    )
    capture["sha256"] = _capture_sha256(capture_path)
    capture["packet_count"] = inspect_result.metadata.packet_count
    return {
        "run": build_run_metadata("discover"),
        "capture": capture,
        "artifact": build_artifact_metadata(None),
        "status": "ok",
        "mode": "discovery",
        "transport_summary": inspect_result.transport_counts,
        "name_resolution": name_resolution,
        "resolved_peers": resolved_peers,
        "capture_context": context,
        "protocol_summary": {
            "top_protocols": top_protocols,
            "dominant_signaling_protocols": dominant,
            "relevant_protocols": relevant_protocols,
            "raw_protocols": inspect_result.metadata.raw_protocols,
        },
        "conversations": inspect_result.conversations[:10],
        "anomalies": inspect_result.anomalies[:20],
        "suspected_domains": candidate_profiles["suspected_domains"],
        "candidate_profiles": candidate_profiles["recommended_profiles"],
        "suppressed_profiles": candidate_profiles["suppressed_profiles"],
    }


def build_discovery_markdown(discovery: dict[str, Any]) -> str:
    run = discovery.get("run", {"action": "discover"})
    capture = dict(discovery.get("capture", {}))
    if "filename" not in capture and capture.get("path"):
        capture["filename"] = Path(capture["path"]).name
    artifact = discovery.get("artifact", {})
    lines = [
        "# Discovery Report",
        "",
        f"- Action: `{run.get('action', 'discover')}`",
        f"- Capture file: `{capture.get('filename', 'unknown')}`",
        f"- Start packet: `{capture.get('first_packet_number') or 'unknown'}`",
        f"- Artifact version: `{artifact.get('version') or 'unknown'}`",
        f"- Capture path: `{capture.get('path', 'unknown')}`",
        f"- Packet count: `{capture.get('packet_count', 'unknown')}`",
        "",
        "## Dominant Signaling Protocols",
    ]
    dominant = discovery["protocol_summary"].get("dominant_signaling_protocols", [])
    if dominant:
        for item in dominant:
            if item.get("count", 0) > 0:
                lines.append(f"- `{item['name']}` [{item['strength']}]: {item['count']}")
            else:
                lines.append(f"- `{item['name']}` [raw signal]")
    else:
        lines.append("- No dominant signaling protocols detected.")

    lines.extend([
        "",
        "## Capture Context",
    ])
    name_resolution = discovery.get("name_resolution", {})
    if name_resolution.get("hosts_file_used") or name_resolution.get("mapping_file_used"):
        lines.append(f"- Hosts file used: `{'yes' if name_resolution.get('hosts_file_used') else 'no'}`")
        lines.append(f"- Mapping file used: `{'yes' if name_resolution.get('mapping_file_used') else 'no'}`")
        lines.append(f"- Resolved peers: `{name_resolution.get('resolved_peer_count', 0)}`")
        examples = discovery.get("resolved_peers", [])[:3]
        if examples:
            rendered = ", ".join(f"`{item['ip']} -> {item['name']}`" for item in examples)
            lines.append(f"- Example mappings: {rendered}")
    context = discovery.get("capture_context", {})
    link_context = context.get("link_or_envelope_protocols", [])
    transport_context = context.get("transport_support_protocols", [])
    if link_context:
        lines.append(f"- Link/envelope context: {', '.join(f'`{item}`' for item in link_context)}")
    if transport_context:
        lines.append(f"- Transport support: {', '.join(f'`{item}`' for item in transport_context)}")
    if not link_context and not transport_context:
        lines.append("- No notable low-level capture context detected.")

    lines.extend([
        "",
        "## Top Protocols",
        "",
        "- Raw top-protocol count view; use the dominant signaling section above for the fachliche reading.",
    ])
    for item in discovery["protocol_summary"]["top_protocols"]:
        lines.append(f"- `{item['name']}`: {item['count']}")
    lines.extend(["", "## Suspected Domains"])
    if discovery["suspected_domains"]:
        for item in discovery["suspected_domains"]:
            lines.append(f"- `{item['domain']}` ({item['score']:.2f}): {', '.join(item['reason'])}")
    else:
        lines.append("- No strong domain signal detected.")
    lines.extend(["", "## Candidate Profiles"])
    if discovery["candidate_profiles"]:
        for item in discovery["candidate_profiles"][:8]:
            confidence = item.get("confidence")
            evidence_class = item.get("evidence_class")
            qualifier = ""
            if confidence and evidence_class:
                qualifier = f" [{confidence}/{evidence_class}]"
            elif confidence:
                qualifier = f" [{confidence}]"
            lines.append(f"- `{item['profile']}`{qualifier} ({item['score']:.2f}): {', '.join(item['reason'])}")
    else:
        lines.append("- No profile recommendations were produced.")
    return "\n".join(lines) + "\n"


def discover_capture(
    capture_path: Path,
    *,
    runner: TSharkRunner,
    display_filter: str | None = None,
    extra_args: list[str] | None = None,
    two_pass: bool = False,
    on_stage=None,
    hosts_file: Path | None = None,
    mapping_file: Path | None = None,
) -> tuple[dict[str, Any], str]:
    profile = build_discovery_profile()
    inspect_result = inspect_capture(
        capture_path,
        runner=runner,
        profile=profile,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
        on_stage=on_stage,
        enrich=True,
        hosts_file=hosts_file,
        mapping_file=mapping_file,
    )
    recommendations = recommend_profiles_from_inspect(inspect_result, load_all_profiles())
    discovery = build_discovery_payload(
        capture_path=capture_path,
        inspect_result=inspect_result,
        candidate_profiles=recommendations,
    )
    return discovery, build_discovery_markdown(discovery)


def write_discovery_artifacts(out_dir: Path, discovery: dict[str, Any], markdown: str) -> dict[str, Path]:
    """Write discovery artifacts directly into *out_dir* with semantic filenames.

    Output layout (flat, no subdirectory)::

        {out_dir}/
          discover_<capture>_start_<n>_V_01.json
          discover_<capture>_start_<n>_V_01.md

    The semantic order is action, capture filename, start packet, and version.
    The ``_V_NN`` suffix auto-increments on filename collision.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = dict(discovery.get("capture", {}))
    if "filename" not in capture and capture.get("path"):
        capture["filename"] = Path(capture["path"]).name
    discovery["run"] = discovery.get("run") or build_run_metadata("discover")
    discovery["capture"] = capture

    version = 1
    while True:
        v = f"V_{version:02d}"
        json_path = out_dir / semantic_artifact_filename(
            action="discover",
            capture_path=capture.get("path", capture.get("filename", "capture")),
            start_packet_number=capture.get("first_packet_number"),
            version=v,
            extension=".json",
        )
        md_path = out_dir / semantic_artifact_filename(
            action="discover",
            capture_path=capture.get("path", capture.get("filename", "capture")),
            start_packet_number=capture.get("first_packet_number"),
            version=v,
            extension=".md",
        )
        if not json_path.exists() and not md_path.exists():
            break
        version += 1

    discovery["artifact"] = build_artifact_metadata(v)
    markdown = build_discovery_markdown(discovery)
    json_path.write_text(json.dumps(discovery, indent=2), encoding="utf-8")
    md_path.write_text(markdown, encoding="utf-8")
    return {
        "discovery_json": json_path,
        "discovery_md": md_path,
    }
