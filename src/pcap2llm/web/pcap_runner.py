from __future__ import annotations

import json
import re
import shlex
import subprocess
from pathlib import Path

from .models import AnalyzeOptions, RunResult
from .security import WebValidationError


_DISPLAY_FILTER_PATTERN = re.compile(r"^[A-Za-z0-9._=!&|()<>\x22' \-+:/]+$")


def _safe_argv_value(value: str, *, allow_dash: bool = False) -> str:
    text = value.strip()
    if text.startswith("-") and not allow_dash:
        raise WebValidationError("Command option values must not start with '-'.")
    return text


def _safe_display_filter(value: str) -> str:
    text = _safe_argv_value(value)
    if not _DISPLAY_FILTER_PATTERN.fullmatch(text):
        raise WebValidationError("Invalid display filter.")
    return text


class Pcap2LlmRunner:
    def __init__(self, *, command_timeout_seconds: int, default_tshark_path: str = "") -> None:
        self.command_timeout_seconds = command_timeout_seconds
        self.default_tshark_path = default_tshark_path.strip()

    def discover(
        self,
        capture_path: Path,
        out_dir: Path,
        logs_dir: Path,
        *,
        hosts_file: str | None = None,
        mapping_file: str | None = None,
        subnets_file: str | None = None,
        ss7pcs_file: str | None = None,
    ) -> RunResult:
        cmd = ["pcap2llm", "discover", str(capture_path), "--out", str(out_dir)]
        if hosts_file:
            cmd.extend(["--hosts-file", _safe_argv_value(hosts_file)])
        if mapping_file:
            cmd.extend(["--mapping-file", _safe_argv_value(mapping_file)])
        if subnets_file:
            cmd.extend(["--subnets-file", _safe_argv_value(subnets_file)])
        if ss7pcs_file:
            cmd.extend(["--ss7pcs-file", _safe_argv_value(ss7pcs_file)])
        if self.default_tshark_path:
            cmd.extend(["--tshark-path", _safe_argv_value(self.default_tshark_path)])
        return self._run(cmd, logs_dir=logs_dir, artifacts_dir=out_dir, log_prefix="discovery")

    def recommend_profiles(self, source_path: Path, logs_dir: Path) -> RunResult:
        cmd = ["pcap2llm", "recommend-profiles", str(source_path)]
        if self.default_tshark_path:
            cmd.extend(["--tshark-path", _safe_argv_value(self.default_tshark_path)])
        return self._run(cmd, logs_dir=logs_dir, artifacts_dir=source_path.parent, log_prefix="recommend")

    def analyze(self, capture_path: Path, options: AnalyzeOptions, out_dir: Path, logs_dir: Path) -> RunResult:
        cmd = self.build_analyze_command(capture_path, options, out_dir)
        return self._run(cmd, logs_dir=logs_dir, artifacts_dir=out_dir, log_prefix="analyze")

    def build_analyze_command(self, capture_path: Path, options: AnalyzeOptions, out_dir: Path) -> list[str]:
        cmd = [
            "pcap2llm",
            "analyze",
            str(capture_path),
            "--profile",
            _safe_argv_value(options.profile),
            "--privacy-profile",
            _safe_argv_value(options.privacy_profile),
            "--out",
            str(out_dir),
        ]

        if options.display_filter:
            cmd.extend(["--display-filter", _safe_display_filter(options.display_filter)])

        if options.max_packets is not None and not options.all_packets:
            cmd.extend(["--max-packets", str(options.max_packets)])

        if options.all_packets:
            cmd.append("--all-packets")

        if options.fail_on_truncation:
            cmd.append("--fail-on-truncation")

        if options.max_capture_size_mb is not None:
            cmd.extend(["--max-capture-size-mb", str(options.max_capture_size_mb)])

        if options.oversize_factor is not None:
            cmd.extend(["--oversize-factor", str(options.oversize_factor)])

        if options.render_flow_svg:
            cmd.append("--render-flow-svg")

        if options.flow_title:
            cmd.extend(["--flow-title", _safe_argv_value(options.flow_title)])

        if options.flow_max_events is not None:
            cmd.extend(["--flow-max-events", str(options.flow_max_events)])

        if options.flow_svg_width is not None:
            cmd.extend(["--flow-svg-width", str(options.flow_svg_width)])

        if not options.collapse_repeats:
            cmd.append("--no-collapse-repeats")

        if options.hosts_file:
            cmd.extend(["--hosts-file", _safe_argv_value(options.hosts_file)])

        if options.mapping_file:
            cmd.extend(["--mapping-file", _safe_argv_value(options.mapping_file)])

        if options.subnets_file:
            cmd.extend(["--subnets-file", _safe_argv_value(options.subnets_file)])

        if options.ss7pcs_file:
            cmd.extend(["--ss7pcs-file", _safe_argv_value(options.ss7pcs_file)])

        if options.network_element_mapping_file:
            cmd.extend(["--network-element-mapping-file", _safe_argv_value(options.network_element_mapping_file)])

        tshark_path = (options.tshark_path or self.default_tshark_path).strip()
        if tshark_path:
            cmd.extend(["--tshark-path", _safe_argv_value(tshark_path)])

        if options.two_pass:
            cmd.append("--two-pass")
        return cmd

    def build_command_preview(self, capture_path: Path, options: AnalyzeOptions, out_dir: Path) -> str:
        return shlex.join(self.build_analyze_command(capture_path, options, out_dir))

    def _run(self, cmd: list[str], *, logs_dir: Path, artifacts_dir: Path, log_prefix: str) -> RunResult:
        logs_dir.mkdir(parents=True, exist_ok=True)
        before = {p.resolve() for p in artifacts_dir.glob("*") if p.is_file()} if artifacts_dir.exists() else set()

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.command_timeout_seconds,
                check=False,
                shell=False,
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            returncode = completed.returncode
        except FileNotFoundError as exc:
            stdout = ""
            stderr = str(exc)
            returncode = 127
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            stderr = (stderr + "\n" if stderr else "") + "Command timed out."
            returncode = 124

        (logs_dir / f"{log_prefix}_stdout.log").write_text(stdout, encoding="utf-8")
        (logs_dir / f"{log_prefix}_stderr.log").write_text(stderr, encoding="utf-8")
        (logs_dir / f"{log_prefix}_command.json").write_text(json.dumps({"command": cmd}, indent=2), encoding="utf-8")

        after = {p.resolve() for p in artifacts_dir.glob("*") if p.is_file()} if artifacts_dir.exists() else set()
        artifacts = sorted(after - before)

        return RunResult(
            ok=returncode == 0,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            command=cmd,
            artifacts=artifacts,
        )
