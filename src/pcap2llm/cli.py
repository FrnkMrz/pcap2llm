from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Generator

import typer

from pcap2llm.cli_result import build_dry_run_payload, build_error_payload, build_success_payload, build_warning
from pcap2llm.config import build_privacy_modes, load_config_file, normalize_mode, sample_config_text
from pcap2llm.error_codes import map_error
from pcap2llm.inspector import inspect_capture
from pcap2llm.pipeline import analyze_capture, describe_output_paths, write_artifacts
from pcap2llm.profiles import load_profile
from pcap2llm.tshark_runner import TSharkError, TSharkRunner

app = typer.Typer(help="Convert PCAP/PCAPNG captures into LLM-friendly artifacts.")
logger = logging.getLogger("pcap2llm")

# ---------------------------------------------------------------------------
# Progress display
# ---------------------------------------------------------------------------

@contextmanager
def _progress(total_steps: int) -> Generator[Callable[[str, int, int], None], None, None]:
    """Yield an ``on_stage`` callback that drives a rich progress bar on stderr.

    Falls back to plain-text status lines when the output is not a TTY or
    when *rich* is unavailable.  The progress bar is always written to stderr
    so it does not interfere with JSON output on stdout.
    """
    if not sys.stderr.isatty():
        # Non-interactive: emit plain status lines instead.
        def _plain(description: str, step: int, total: int) -> None:
            print(f"[{step}/{total}] {description}", file=sys.stderr)

        yield _plain
        return

    from rich.console import Console
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    console = Console(stderr=True)
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description:<45}"),
        BarColumn(bar_width=20),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Starting…", total=total_steps, completed=0)

        def _on_stage(description: str, step: int, total: int) -> None:
            progress.update(task_id, description=description, completed=step)

        yield _on_stage
        # Mark as fully complete when the caller's block exits normally.
        progress.update(task_id, description="[green]Done ✓", completed=total_steps)


def _configure_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", help="Enable info logging."),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging."),
) -> None:
    _configure_logging(verbose, debug)


_MODE_HELP = (
    "Privacy mode: keep | mask | pseudonymize | encrypt | remove  "
    "(alias: off=keep, redact=mask). "
    "encrypt requires PCAP2LLM_VAULT_KEY; vault.json stores metadata only."
)


def _privacy_overrides(
    ip_mode: str | None,
    hostname_mode: str | None,
    subscriber_id_mode: str | None,
    msisdn_mode: str | None,
    imsi_mode: str | None,
    imei_mode: str | None,
    email_mode: str | None,
    dn_mode: str | None,
    token_mode: str | None,
    uri_mode: str | None,
    apn_dnn_mode: str | None,
    diameter_identity_mode: str | None,
    payload_text_mode: str | None,
) -> dict[str, str | None]:
    return {
        "ip": ip_mode,
        "hostname": hostname_mode,
        "subscriber_id": subscriber_id_mode,
        "msisdn": msisdn_mode,
        "imsi": imsi_mode,
        "imei": imei_mode,
        "email": email_mode,
        "distinguished_name": dn_mode,
        "token": token_mode,
        "uri": uri_mode,
        "apn_dnn": apn_dnn_mode,
        "diameter_identity": diameter_identity_mode,
        "payload_text": payload_text_mode,
    }


def _build_modes(
    base: dict[str, str],
    config_overrides: dict[str, str | None],
    cli_overrides: dict[str, str | None],
) -> dict[str, str]:
    """Merge base → config overrides → CLI flags (highest priority wins)."""
    combined_overrides: dict[str, str | None] = {}
    combined_overrides.update({k: v for k, v in config_overrides.items() if v is not None})
    combined_overrides.update({k: v for k, v in cli_overrides.items() if v is not None})
    return build_privacy_modes(base, combined_overrides)


def _resolve_privacy_base(
    cli_privacy_profile: str | None,
    config_data: dict,
    analysis_profile,  # ProfileDefinition
) -> dict[str, str]:
    """Return the base privacy modes from the highest-priority source available."""
    name = cli_privacy_profile or config_data.get("privacy_profile")
    if name:
        from pcap2llm.privacy_profiles import load_privacy_profile
        return load_privacy_profile(name).modes
    if analysis_profile.default_privacy_modes:
        typer.echo(
            f"Warning: analysis profile '{analysis_profile.name}' contains deprecated "
            "'default_privacy_modes'. Migrate to --privacy-profile (e.g. --privacy-profile share).",
            err=True,
        )
        return analysis_profile.default_privacy_modes
    return {}


@app.command("init-config")
def init_config(
    path: Path = typer.Argument(Path("pcap2llm.config.yaml")),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    if path.exists() and not force:
        raise typer.BadParameter(f"{path} already exists. Use --force to overwrite it.")
    path.write_text(sample_config_text(), encoding="utf-8")
    typer.echo(f"Wrote sample configuration to {path}")


@app.command("inspect")
def inspect_command(
    capture: Path = typer.Argument(..., exists=True, readable=True, help="Input .pcap or .pcapng file."),
    profile_name: str = typer.Option("lte-core", "--profile", help="Protocol profile name."),
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="TShark display filter."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config file."),
    out: Path | None = typer.Option(None, "--out", help="Optional path for inspect JSON output."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show the planned tshark command without executing."),
    two_pass: bool | None = typer.Option(None, "--two-pass/--no-two-pass", help="Override tshark two-pass mode."),
    tshark_path: str = typer.Option("tshark", "--tshark-path", help="TShark executable path."),
    tshark_arg: list[str] = typer.Option(None, "--tshark-arg", help="Extra argument passed to tshark."),
) -> None:
    config_data = load_config_file(config_path)
    profile = load_profile(profile_name)
    runner = TSharkRunner(binary=tshark_path)
    effective_two_pass = profile.tshark.get("two_pass", False) if two_pass is None else two_pass
    extra_args = list(config_data.get("tshark_extra_args", [])) + list(tshark_arg or [])
    if dry_run:
        command = runner.build_export_command(
            capture,
            display_filter=display_filter or config_data.get("display_filter"),
            extra_args=extra_args,
            two_pass=effective_two_pass,
        )
        typer.echo(json.dumps({"command": command, "profile": profile.name}, indent=2))
        return
    try:
        from pcap2llm.inspector import _INSPECT_STEPS
        with _progress(_INSPECT_STEPS) as on_stage:
            result = inspect_capture(
                capture,
                runner=runner,
                profile=profile,
                display_filter=display_filter or config_data.get("display_filter"),
                extra_args=extra_args,
                two_pass=effective_two_pass,
                on_stage=on_stage,
            )
    except TSharkError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    payload = json.dumps(result.model_dump(), indent=2)
    if out:
        out.write_text(payload, encoding="utf-8")
        typer.echo(f"Wrote inspect output to {out}")
        return
    typer.echo(payload)


@app.command("analyze")
def analyze_command(
    capture: Path = typer.Argument(..., exists=True, readable=True, help="Input .pcap or .pcapng file."),
    profile_name: str = typer.Option("lte-core", "--profile", help="Protocol profile name."),
    privacy_profile_name: str | None = typer.Option(
        None,
        "--privacy-profile",
        help="Privacy profile name (built-in: internal, share, lab, prod-safe) or path to a YAML file.",
    ),
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="TShark display filter."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config file."),
    mapping_file: Path | None = typer.Option(None, "--mapping-file", help="Custom YAML/JSON alias mapping."),
    hosts_file: Path | None = typer.Option(None, "--hosts-file", help="Wireshark hosts-style mapping file."),
    out_dir: Path = typer.Option(Path("artifacts"), "--out", help="Artifact output directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate options and print the plan only."),
    two_pass: bool | None = typer.Option(None, "--two-pass/--no-two-pass", help="Override tshark two-pass mode."),
    tshark_path: str = typer.Option("tshark", "--tshark-path", help="TShark executable path."),
    tshark_arg: list[str] = typer.Option(None, "--tshark-arg", help="Extra argument passed to tshark."),
    max_packets: int = typer.Option(
        1000,
        "--max-packets",
        help=(
            "Maximum number of packets written to detail.json (default: 1000). "
            "Inspection and summary always use the full capture. "
            "Use --all-packets to remove the limit entirely."
        ),
    ),
    all_packets: bool = typer.Option(
        False,
        "--all-packets",
        help="Include every exported packet in detail.json, ignoring --max-packets.",
    ),
    fail_on_truncation: bool = typer.Option(
        False,
        "--fail-on-truncation",
        help="Exit with an error instead of writing a truncated detail artifact.",
    ),
    max_capture_size_mb: int = typer.Option(
        250,
        "--max-capture-size-mb",
        help=(
            "Fail fast when the input capture exceeds this size in MiB before tshark JSON export. "
            "Use 0 to disable the guard for intentionally large captures."
        ),
    ),
    llm_mode: bool = typer.Option(
        False,
        "--llm-mode",
        help="Return a strict machine-readable JSON result on stdout for orchestrators and LLM workflows.",
    ),
    ip_mode: str | None = typer.Option(None, "--ip-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    hostname_mode: str | None = typer.Option(None, "--hostname-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    subscriber_id_mode: str | None = typer.Option(None, "--subscriber-id-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    msisdn_mode: str | None = typer.Option(None, "--msisdn-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    imsi_mode: str | None = typer.Option(None, "--imsi-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    imei_mode: str | None = typer.Option(None, "--imei-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    email_mode: str | None = typer.Option(None, "--email-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    dn_mode: str | None = typer.Option(None, "--dn-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    token_mode: str | None = typer.Option(None, "--token-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    uri_mode: str | None = typer.Option(None, "--uri-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    apn_dnn_mode: str | None = typer.Option(None, "--apn-dnn-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    diameter_identity_mode: str | None = typer.Option(None, "--diameter-identity-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
    payload_text_mode: str | None = typer.Option(None, "--payload-text-mode", help=_MODE_HELP, callback=lambda value: normalize_mode(value) if value else None),
) -> None:
    config_data = load_config_file(config_path)
    profile = load_profile(profile_name)
    runner = TSharkRunner(binary=tshark_path)
    extra_args = list(config_data.get("tshark_extra_args", [])) + list(tshark_arg or [])
    effective_two_pass = profile.tshark.get("two_pass", False) if two_pass is None else two_pass
    overrides = _privacy_overrides(
        ip_mode,
        hostname_mode,
        subscriber_id_mode,
        msisdn_mode,
        imsi_mode,
        imei_mode,
        email_mode,
        dn_mode,
        token_mode,
        uri_mode,
        apn_dnn_mode,
        diameter_identity_mode,
        payload_text_mode,
    )
    base_modes = _resolve_privacy_base(privacy_profile_name, config_data, profile)
    privacy_modes = _build_modes(base_modes, config_data.get("privacy_modes", {}), overrides)
    effective_hosts = hosts_file or (Path(config_data["hosts_file"]) if config_data.get("hosts_file") else None)
    effective_mapping = mapping_file or (Path(config_data["mapping_file"]) if config_data.get("mapping_file") else None)
    effective_filter = display_filter or config_data.get("display_filter")
    effective_max_packets = 0 if all_packets else max_packets

    if dry_run:
        if llm_mode:
            payload = build_dry_run_payload(
                capture=capture,
                profile=profile.name,
                privacy_profile=privacy_profile_name or config_data.get("privacy_profile"),
                display_filter=effective_filter,
                max_packets=effective_max_packets,
                all_packets=all_packets,
                fail_on_truncation=fail_on_truncation,
                max_capture_size_mb=max_capture_size_mb,
                privacy_modes=privacy_modes,
                hosts_file=effective_hosts,
                mapping_file=effective_mapping,
                command=runner.build_export_command(
                    capture,
                    display_filter=effective_filter,
                    extra_args=extra_args,
                    two_pass=effective_two_pass,
                ),
                llm_mode=llm_mode,
            )
        else:
            payload = {
                "capture": str(capture),
                "profile": profile.name,
                "privacy_profile": privacy_profile_name or config_data.get("privacy_profile") or "(none — using defaults)",
                "display_filter": effective_filter,
                "max_packets": effective_max_packets if effective_max_packets > 0 else "unlimited",
                "fail_on_truncation": fail_on_truncation,
                "max_capture_size_mb": max_capture_size_mb,
                "privacy_modes": privacy_modes,
                "hosts_file": str(effective_hosts) if effective_hosts else None,
                "mapping_file": str(effective_mapping) if effective_mapping else None,
                "command": runner.build_export_command(
                    capture,
                    display_filter=effective_filter,
                    extra_args=extra_args,
                    two_pass=effective_two_pass,
                ),
            }
        typer.echo(json.dumps(payload, indent=2))
        return

    try:
        from pcap2llm.pipeline import _ANALYZE_STEPS
        with _progress(_ANALYZE_STEPS) as on_stage:
            artifacts = analyze_capture(
                capture,
                out_dir=out_dir,
                runner=runner,
                profile=profile,
                privacy_modes=privacy_modes,
                display_filter=effective_filter,
                hosts_file=effective_hosts,
                mapping_file=effective_mapping,
                extra_args=extra_args,
                two_pass=effective_two_pass,
                max_packets=effective_max_packets,
                fail_on_truncation=fail_on_truncation,
                max_capture_size_mb=max_capture_size_mb,
                on_stage=on_stage,
            )
    except Exception as exc:  # noqa: BLE001
        if llm_mode:
            code, details = map_error(exc)
            typer.echo(json.dumps(build_error_payload(code=code, message=str(exc), details=details), indent=2))
            raise typer.Exit(code=1) from exc
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    try:
        outputs = write_artifacts(artifacts, out_dir)
    except Exception as exc:  # noqa: BLE001
        if llm_mode:
            code, details = map_error(exc)
            typer.echo(json.dumps(build_error_payload(code=code, message=str(exc), details=details), indent=2))
            raise typer.Exit(code=1) from exc
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not llm_mode:
        payload = {key: str(value) for key, value in outputs.items()}
        payload.update(describe_output_paths(outputs))
        typer.echo(json.dumps(payload, indent=2))
        return

    coverage = artifacts.summary.get("coverage", {})
    warnings: list[dict[str, str]] = []
    if coverage.get("detail_truncated"):
        warnings.append(
            build_warning(
                "detail_truncated",
                coverage.get("truncation_note")
                or "detail artifact was truncated by the configured packet limit.",
            )
        )
    if max_capture_size_mb == 0:
        warnings.append(
            build_warning(
                "capture_size_guard_disabled",
                "pre-export capture size guard was disabled explicitly.",
            )
        )
    if not artifacts.summary.get("relevant_protocols"):
        warnings.append(
            build_warning(
                "no_relevant_protocols_detected",
                "no relevant protocols were detected in the inspected capture.",
            )
        )
    if outputs.get("mapping"):
        warnings.append(
            build_warning(
                "pseudonym_mapping_created",
                "a pseudonym mapping sidecar was created and should be handled separately.",
            )
        )
    if outputs.get("vault"):
        warnings.append(
            build_warning(
                "encrypted_output_requires_key_handling",
                "encrypted output requires separate handling of PCAP2LLM_VAULT_KEY.",
            )
        )
    warnings.append(
        build_warning(
            "full_load_ingestion_applies",
            "the current tshark JSON ingestion path still loads the exported packet JSON before selection.",
        )
    )

    capture_hash = None
    try:
        capture_hash = sha256(capture.read_bytes()).hexdigest()
    except OSError:
        pass

    payload = build_success_payload(
        capture=capture,
        capture_sha256=capture_hash,
        profile=profile.name,
        privacy_profile=privacy_profile_name or config_data.get("privacy_profile"),
        outputs=outputs,
        artifact_identity=describe_output_paths(outputs),
        coverage=coverage,
        limits={
            "max_packets": effective_max_packets,
            "all_packets": all_packets,
            "max_capture_size_mb": max_capture_size_mb,
            "fail_on_truncation": fail_on_truncation,
        },
        warnings=warnings,
        schema_versions={
            "summary": artifacts.summary.get("schema_version"),
            "detail": artifacts.detail.get("schema_version"),
        },
    )
    typer.echo(json.dumps(payload, indent=2))
