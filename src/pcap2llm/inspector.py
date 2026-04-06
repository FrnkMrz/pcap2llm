from __future__ import annotations

from pathlib import Path

from pcap2llm.models import InspectResult, ProfileDefinition
from pcap2llm.normalizer import inspect_raw_packets
from pcap2llm.tshark_runner import TSharkRunner


def inspect_capture(
    capture_path: Path,
    *,
    runner: TSharkRunner,
    profile: ProfileDefinition,
    display_filter: str | None = None,
    extra_args: list[str] | None = None,
    two_pass: bool = False,
) -> InspectResult:
    raw_packets = runner.export_packets(
        capture_path,
        display_filter=display_filter,
        extra_args=extra_args,
        two_pass=two_pass,
    )
    return inspect_raw_packets(
        raw_packets,
        capture_path=capture_path,
        display_filter=display_filter,
        profile=profile,
    )
