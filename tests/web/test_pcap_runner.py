from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from pcap2llm.web.models import AnalyzeOptions
from pcap2llm.web.pcap_runner import Pcap2LlmRunner
from pcap2llm.web.security import WebValidationError


def test_build_analyze_command_selected_flags(tmp_path: Path) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)
    capture = tmp_path / "sample.pcapng"
    out_dir = tmp_path / "artifacts"

    cmd = runner.build_analyze_command(
        capture,
        AnalyzeOptions(
            profile="lte-s11",
            privacy_profile="share",
            display_filter="gtpv2",
            verbatim_protocols_add=["pfcp", "ngap"],
            verbatim_protocols_remove=["diameter"],
            keep_raw_avps=True,
            max_packets=500,
            all_packets=False,
            fail_on_truncation=True,
            max_capture_size_mb=250,
            oversize_factor=12.5,
            render_flow_svg=True,
            flow_title="Flow",
            flow_max_events=50,
            flow_svg_width=1800,
            collapse_repeats=False,
            hosts_file="hosts.txt",
            mapping_file="mapping.yaml",
            subnets_file="subnets.txt",
            ss7pcs_file="ss7pcs.txt",
            network_element_mapping_file="network_element_mapping.csv",
            tshark_path="tshark",
            two_pass=True,
        ),
        out_dir,
    )

    assert cmd[:4] == [sys.executable, "-m", "pcap2llm", "analyze"]
    assert str(capture) in cmd
    assert "--profile" in cmd and "lte-s11" in cmd
    assert "--privacy-profile" in cmd and "share" in cmd
    assert "--display-filter" in cmd and "gtpv2" in cmd
    assert cmd.count("--verbatim-protocol") == 2
    assert "pfcp" in cmd and "ngap" in cmd
    assert "--no-verbatim-protocol" in cmd and "diameter" in cmd
    assert "--keep-raw-avps" in cmd
    assert "--max-packets" in cmd and "500" in cmd
    assert "--all-packets" not in cmd
    assert "--fail-on-truncation" in cmd
    assert "--max-capture-size-mb" in cmd and "250" in cmd
    assert "--oversize-factor" in cmd and "12.5" in cmd
    assert "--render-flow-svg" in cmd
    assert "--flow-title" in cmd and "Flow" in cmd
    assert "--flow-max-events" in cmd and "50" in cmd
    assert "--flow-svg-width" in cmd and "1800" in cmd
    assert "--no-collapse-repeats" in cmd
    assert "--hosts-file" in cmd and "hosts.txt" in cmd
    assert "--mapping-file" in cmd and "mapping.yaml" in cmd
    assert "--subnets-file" in cmd and "subnets.txt" in cmd
    assert "--ss7pcs-file" in cmd and "ss7pcs.txt" in cmd
    assert "--network-element-mapping-file" in cmd and "network_element_mapping.csv" in cmd
    assert "--tshark-path" in cmd and "tshark" in cmd
    assert "--two-pass" in cmd


def test_build_analyze_command_omits_unset_optional_flags(tmp_path: Path) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)
    capture = tmp_path / "sample.pcapng"
    out_dir = tmp_path / "artifacts"

    cmd = runner.build_analyze_command(
        capture,
        AnalyzeOptions(
            profile="lte-core",
            privacy_profile="share",
            two_pass=False,
            collapse_repeats=True,
        ),
        out_dir,
    )

    assert "--two-pass" not in cmd
    assert "--no-two-pass" not in cmd
    assert "--max-capture-size-mb" not in cmd
    assert "--oversize-factor" not in cmd
    assert "--verbatim-protocol" not in cmd
    assert "--no-verbatim-protocol" not in cmd
    assert "--keep-raw-avps" not in cmd
    assert "--no-keep-raw-avps" not in cmd
    assert "--hosts-file" not in cmd
    assert "--mapping-file" not in cmd
    assert "--subnets-file" not in cmd
    assert "--ss7pcs-file" not in cmd
    assert "--network-element-mapping-file" not in cmd
    assert "--no-collapse-repeats" not in cmd


def test_run_uses_no_shell_and_maps_failures(tmp_path: Path, monkeypatch) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)
    logs_dir = tmp_path / "logs"
    out_dir = tmp_path / "artifacts"
    out_dir.mkdir()

    captured: dict[str, object] = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=2, stdout="", stderr="boom")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = runner.analyze(
        capture_path=tmp_path / "trace.pcapng",
        options=AnalyzeOptions(profile="lte-core"),
        out_dir=out_dir,
        logs_dir=logs_dir,
    )

    assert result.ok is False
    assert result.returncode == 2
    assert captured["kwargs"]["shell"] is False
    assert (logs_dir / "analyze_stdout.log").exists()
    assert (logs_dir / "analyze_stderr.log").read_text(encoding="utf-8") == "boom"
    assert (logs_dir / "analyze_command.json").exists()


def test_build_command_preview_shell_quotes_paths_with_spaces(tmp_path: Path) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)
    capture = tmp_path / "input dir" / "sample trace.pcapng"
    out_dir = tmp_path / "output dir"

    preview = runner.build_command_preview(
        capture,
        AnalyzeOptions(profile="lte-core", privacy_profile="share"),
        out_dir,
    )

    assert f"'{capture}'" in preview
    assert f"'{out_dir}'" in preview


def test_build_analyze_command_rejects_dash_prefixed_display_filter(tmp_path: Path) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)

    try:
        runner.build_analyze_command(
            tmp_path / "sample.pcapng",
            AnalyzeOptions(profile="lte-core", privacy_profile="share", display_filter="--help"),
            tmp_path / "artifacts",
        )
    except WebValidationError:
        return

    raise AssertionError("dash-prefixed display filter should be rejected")


def test_build_analyze_command_rejects_dash_prefixed_support_file(tmp_path: Path) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)

    try:
        runner.build_analyze_command(
            tmp_path / "sample.pcapng",
            AnalyzeOptions(profile="lte-core", privacy_profile="share", hosts_file="--help"),
            tmp_path / "artifacts",
        )
    except WebValidationError:
        return

    raise AssertionError("dash-prefixed support file should be rejected")


def test_build_analyze_command_rejects_invalid_verbatim_protocol_name(tmp_path: Path) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)

    try:
        runner.build_analyze_command(
            tmp_path / "sample.pcapng",
            AnalyzeOptions(profile="lte-core", privacy_profile="share", verbatim_protocols_add=["gtpv2;"]),
            tmp_path / "artifacts",
        )
    except WebValidationError:
        return

    raise AssertionError("invalid verbatim protocol should be rejected")


def test_build_analyze_command_supports_disabling_raw_avps(tmp_path: Path) -> None:
    runner = Pcap2LlmRunner(command_timeout_seconds=30)
    cmd = runner.build_analyze_command(
        tmp_path / "sample.pcapng",
        AnalyzeOptions(profile="lte-core", privacy_profile="share", keep_raw_avps=False),
        tmp_path / "artifacts",
    )

    assert "--no-keep-raw-avps" in cmd
