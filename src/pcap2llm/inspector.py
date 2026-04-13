from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pcap2llm.inspect_enrichment import enrich_inspect_result
from pcap2llm.models import InspectResult, ProfileDefinition
from pcap2llm.normalizer import inspect_raw_packets
from pcap2llm.profiles import load_all_profiles
from pcap2llm.resolver import EndpointResolver
from pcap2llm.tshark_runner import TSharkRunner

# Signature: (description, current_step, total_steps)
OnStage = Callable[[str, int, int], None]

_INSPECT_STEPS = 2


def inspect_capture(
    capture_path: Path,
    *,
    runner: TSharkRunner,
    profile: ProfileDefinition,
    display_filter: str | None = None,
    extra_args: list[str] | None = None,
    two_pass: bool = False,
    on_stage: OnStage | None = None,
    enrich: bool = True,
    hosts_file: Path | None = None,
    mapping_file: Path | None = None,
    subnets_file: Path | None = None,
    ss7pcs_file: Path | None = None,
) -> InspectResult:
    def _step(msg: str, i: int) -> None:
        if on_stage:
            on_stage(msg, i, _INSPECT_STEPS)

    _step("Exporting packets via TShark…", 0)
    raw_packets = runner.export_packets(
        capture_path,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
    )
    _step(f"Inspecting {len(raw_packets):,} packets…", 1)
    resolver = EndpointResolver(
        hosts_file=hosts_file,
        mapping_file=mapping_file,
        subnets_file=subnets_file,
        ss7pcs_file=ss7pcs_file,
    )
    result = inspect_raw_packets(
        raw_packets,
        capture_path=capture_path,
        display_filter=display_filter,
        profile=profile,
        resolver=resolver,
        hosts_file_used=hosts_file is not None,
        mapping_file_used=mapping_file is not None,
        subnets_file_used=subnets_file is not None,
        ss7pcs_file_used=ss7pcs_file is not None,
    )
    if enrich:
        result = enrich_inspect_result(result, load_all_profiles())
    return result
