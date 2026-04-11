from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pcap2llm.inspector import inspect_capture
from pcap2llm.models import InspectResult, ProfileDefinition
from pcap2llm.pipeline import artifact_timestamp_prefix
from pcap2llm.profiles import load_all_profiles
from pcap2llm.recommendation import recommend_profiles_from_inspect
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
    top_protocols = [
        {"name": name, "count": count}
        for name, count in sorted(
            inspect_result.protocol_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]
    ]
    return {
        "status": "ok",
        "mode": "discovery",
        "capture": {
            "path": str(capture_path),
            "sha256": _capture_sha256(capture_path),
            "packet_count": inspect_result.metadata.packet_count,
            "first_seen": inspect_result.metadata.first_seen_epoch,
            "last_seen": inspect_result.metadata.last_seen_epoch,
        },
        "transport_summary": inspect_result.transport_counts,
        "protocol_summary": {
            "top_protocols": top_protocols,
            "relevant_protocols": inspect_result.metadata.relevant_protocols,
            "raw_protocols": inspect_result.metadata.raw_protocols,
        },
        "conversations": inspect_result.conversations[:10],
        "anomalies": inspect_result.anomalies[:20],
        "suspected_domains": candidate_profiles["suspected_domains"],
        "candidate_profiles": candidate_profiles["recommended_profiles"],
        "suppressed_profiles": candidate_profiles["suppressed_profiles"],
    }


def build_discovery_markdown(discovery: dict[str, Any]) -> str:
    lines = [
        "# Discovery Report",
        "",
        f"- Capture: `{discovery['capture']['path']}`",
        f"- Packet count: `{discovery['capture']['packet_count']}`",
        "",
        "## Top Protocols",
    ]
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
            lines.append(f"- `{item['profile']}` ({item['score']:.2f}): {', '.join(item['reason'])}")
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
        enrich=False,
    )
    recommendations = recommend_profiles_from_inspect(inspect_result, load_all_profiles())
    discovery = build_discovery_payload(
        capture_path=capture_path,
        inspect_result=inspect_result,
        candidate_profiles=recommendations,
    )
    return discovery, build_discovery_markdown(discovery)


def write_discovery_artifacts(out_dir: Path, discovery: dict[str, Any], markdown: str) -> dict[str, Path]:
    """Write discovery artifacts directly into *out_dir* with a shared timestamp prefix.

    Output layout (flat, no subdirectory)::

        {out_dir}/
          YYYYMMDD_HHMMSS_discovery.json
          YYYYMMDD_HHMMSS_discovery.md

    The timestamp prefix is derived from ``capture.first_seen`` in the discovery
    payload using the same :func:`~pcap2llm.pipeline.artifact_timestamp_prefix`
    helper used by ``analyze`` runs.  Falls back to the current wall-clock time
    when the epoch cannot be parsed.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    first_seen = discovery.get("capture", {}).get("first_seen") or ""
    ts = artifact_timestamp_prefix(first_seen) or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    discovery_json = out_dir / f"{ts}_discovery.json"
    discovery_md = out_dir / f"{ts}_discovery.md"
    discovery_json.write_text(json.dumps(discovery, indent=2), encoding="utf-8")
    discovery_md.write_text(markdown, encoding="utf-8")
    return {
        "discovery_json": discovery_json,
        "discovery_md": discovery_md,
    }
