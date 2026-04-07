from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pcap2llm.models import InspectResult, ProfileDefinition
from pcap2llm.normalizer import inspect_raw_packets
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
    return inspect_raw_packets(
        raw_packets,
        capture_path=capture_path,
        display_filter=display_filter,
        profile=profile,
    )
