from __future__ import annotations

import json
from pathlib import Path

from pcap2llm.models import AnalyzeArtifacts, ProfileDefinition
from pcap2llm.normalizer import inspect_raw_packets, normalize_packets
from pcap2llm.protector import Protector
from pcap2llm.reducer import reduce_packets
from pcap2llm.resolver import EndpointResolver
from pcap2llm.summarizer import build_markdown_summary, build_summary
from pcap2llm.tshark_runner import TSharkRunner


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
) -> AnalyzeArtifacts:
    raw_packets = runner.export_packets(
        capture_path,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
    )
    inspect_result = inspect_raw_packets(
        raw_packets,
        capture_path=capture_path,
        display_filter=display_filter,
        profile=profile,
    )
    resolver = EndpointResolver(hosts_file=hosts_file, mapping_file=mapping_file)
    normalized = normalize_packets(
        raw_packets,
        resolver=resolver,
        profile=profile,
        privacy_modes=privacy_modes,
    )
    reduced = reduce_packets(normalized, profile)
    protector = Protector(privacy_modes)
    protected_packets = protector.protect_packets(reduced)
    summary = build_summary(
        inspect_result,
        protected_packets,
        profile=profile,
        privacy_modes=privacy_modes,
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
        detail={
            "profile": profile.name,
            "selected_packets": protected_packets,
        },
        markdown=markdown,
        pseudonym_mapping=protector.pseudonyms,
        vault=protector.vault_metadata(),
    )


def write_artifacts(artifacts: AnalyzeArtifacts, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "summary": out_dir / "summary.json",
        "detail": out_dir / "detail.json",
        "markdown": out_dir / "summary.md",
    }
    outputs["summary"].write_text(json.dumps(artifacts.summary, indent=2), encoding="utf-8")
    outputs["detail"].write_text(json.dumps(artifacts.detail, indent=2), encoding="utf-8")
    outputs["markdown"].write_text(artifacts.markdown, encoding="utf-8")
    if artifacts.pseudonym_mapping:
        mapping_path = out_dir / "pseudonym_mapping.json"
        mapping_path.write_text(
            json.dumps(artifacts.pseudonym_mapping, indent=2),
            encoding="utf-8",
        )
        outputs["mapping"] = mapping_path
    if artifacts.vault:
        vault_path = out_dir / "vault.json"
        vault_path.write_text(json.dumps(artifacts.vault, indent=2), encoding="utf-8")
        outputs["vault"] = vault_path
    return outputs
