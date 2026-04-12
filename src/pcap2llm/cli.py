from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Generator

import typer

from pcap2llm.cli_result import build_dry_run_payload, build_error_payload, build_success_payload, build_warning
from pcap2llm.config import build_privacy_modes, load_config_file, normalize_mode, sample_config_text
from pcap2llm.discovery import discover_capture, write_discovery_artifacts
from pcap2llm.error_codes import map_error
from pcap2llm.inspector import inspect_capture
from pcap2llm.output_metadata import semantic_artifact_filename
from pcap2llm.pipeline import analyze_capture, describe_output_paths, write_artifacts
from pcap2llm.profiles import load_profile
from pcap2llm.sessions import (
    append_run,
    build_session_report,
    load_session_manifest,
    next_run_id,
    session_manifest_path,
    start_session,
    write_session_manifest,
)
from pcap2llm.tshark_runner import TSharkError, TSharkRunner

app = typer.Typer(help="Convert PCAP/PCAPNG captures into LLM-friendly artifacts.")
session_app = typer.Typer(help="Structured multi-run session helpers for external orchestrators.")
logger = logging.getLogger("pcap2llm")


def _resolve_inspect_output_path(
    out: Path,
    *,
    capture: Path,
    first_packet_number: int | None,
    use_markdown: bool,
) -> Path:
    if out.suffix.lower() in {".json", ".md"}:
        return out

    out.mkdir(parents=True, exist_ok=True)
    extension = ".md" if use_markdown else ".json"
    version = 1
    while True:
        candidate = out / semantic_artifact_filename(
            action="inspect",
            capture_path=capture,
            start_packet_number=first_packet_number,
            version=f"V_{version:02d}",
            extension=extension,
        )
        if not candidate.exists():
            return candidate
        version += 1

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
    from rich.logging import RichHandler
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    console = Console(stderr=True)

    # Route all log records through the same rich Console so WARNING messages
    # are printed cleanly above the progress bar instead of tearing through it.
    # Temporarily remove existing StreamHandlers that write to stderr so they
    # don't produce a duplicate plain-text line alongside the rich-formatted one.
    rich_handler = RichHandler(console=console, show_path=False, markup=False)
    rich_handler.setLevel(logging.WARNING)
    root_logger = logging.getLogger()
    displaced: list[logging.Handler] = [
        h for h in root_logger.handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, RichHandler)
        and getattr(h, "stream", None) is sys.stderr
    ]
    for h in displaced:
        root_logger.removeHandler(h)
    root_logger.addHandler(rich_handler)

    try:
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
    finally:
        root_logger.removeHandler(rich_handler)
        for h in displaced:
            root_logger.addHandler(h)


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


def _normalize_protocol_name(name: str) -> str:
    normalized = name.strip().lower()
    if not normalized:
        raise typer.BadParameter("Protocol name must not be empty.")
    return normalized


def _merge_verbatim_protocols(
    base: list[str],
    additions: list[str] | None,
    removals: list[str] | None,
) -> tuple[list[str], dict[str, list[str]]]:
    base_norm: list[str] = []
    seen: set[str] = set()
    for item in base:
        normalized = _normalize_protocol_name(item)
        if normalized not in seen:
            base_norm.append(normalized)
            seen.add(normalized)

    added_norm: list[str] = []
    seen_added: set[str] = set()
    for item in additions or []:
        normalized = _normalize_protocol_name(item)
        if normalized not in seen_added:
            added_norm.append(normalized)
            seen_added.add(normalized)

    removed_norm: list[str] = []
    seen_removed: set[str] = set()
    for item in removals or []:
        normalized = _normalize_protocol_name(item)
        if normalized not in seen_removed:
            removed_norm.append(normalized)
            seen_removed.add(normalized)

    effective = list(base_norm)
    for item in added_norm:
        if item not in effective:
            effective.append(item)
    effective = [item for item in effective if item not in seen_removed]

    return effective, {
        "profile_default": base_norm,
        "added": added_norm,
        "removed": removed_norm,
    }


_LOCAL_HOSTS_DEFAULT = Path(".local/hosts")


def _resolve_hosts_file(
    cli_arg: Path | None,
    config_data: dict,
) -> Path | None:
    """Return the effective hosts file path.

    Lookup order (first match wins):
    1. Explicit CLI ``--hosts-file`` argument
    2. ``hosts_file`` key in config file
    3. Auto-discovered default at ``.local/hosts/wireshark_hosts.txt``
    4. None — no hosts file, continue without mapping
    """
    if cli_arg is not None:
        return cli_arg
    if config_data.get("hosts_file"):
        return Path(config_data["hosts_file"])
    if _LOCAL_HOSTS_DEFAULT.exists():
        logger.info("Using local hosts file from %s", _LOCAL_HOSTS_DEFAULT)
        return _LOCAL_HOSTS_DEFAULT
    logger.debug("No local hosts file found at default path %s; continuing without hosts mapping", _LOCAL_HOSTS_DEFAULT)
    return None


def _capture_sha256(capture: Path) -> str | None:
    try:
        return sha256(capture.read_bytes()).hexdigest()
    except OSError:
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()



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
    out: Path | None = typer.Option(None, "--out", help="Optional file path or output directory for inspect artifacts."),
    format: str = typer.Option("json", "--format", help="Output format: json or markdown."),
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
    use_markdown = format == "markdown" or (out is not None and str(out).endswith(".md"))
    if use_markdown:
        from pcap2llm.inspect_enrichment import build_inspect_markdown
        text = build_inspect_markdown(result)
    else:
        from pcap2llm.inspect_enrichment import serialize_inspect_result

        text = json.dumps(serialize_inspect_result(result), indent=2)
    if out:
        output_path = _resolve_inspect_output_path(
            out,
            capture=capture,
            first_packet_number=result.metadata.first_packet_number,
            use_markdown=use_markdown,
        )
        output_path.write_text(text, encoding="utf-8")
        typer.echo(f"Wrote inspect output to {output_path}")
        return
    typer.echo(text)


@app.command("discover")
def discover_command(
    capture: Path = typer.Argument(..., exists=True, readable=True, help="Input .pcap or .pcapng file."),
    out_dir: Path = typer.Option(Path("artifacts"), "--out", help="Output directory for discovery artifacts."),
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="Optional TShark display filter."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config file."),
    mapping_file: Path | None = typer.Option(None, "--mapping-file", help="Custom YAML/JSON alias mapping."),
    hosts_file: Path | None = typer.Option(None, "--hosts-file", help="Wireshark hosts-style mapping file."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate options and print the discovery plan only."),
    two_pass: bool = typer.Option(False, "--two-pass/--no-two-pass", help="Override TShark two-pass mode for discovery."),
    tshark_path: str = typer.Option("tshark", "--tshark-path", help="TShark executable path."),
    tshark_arg: list[str] = typer.Option(None, "--tshark-arg", help="Extra argument passed to tshark."),
) -> None:
    config_data = load_config_file(config_path)
    effective_hosts = _resolve_hosts_file(hosts_file, config_data)
    runner = TSharkRunner(binary=tshark_path)
    extra_args = list(config_data.get("tshark_extra_args", [])) + list(tshark_arg or [])
    if dry_run:
        typer.echo(
            json.dumps(
                {
                    "capture": str(capture),
                    "mode": "discovery",
                    "out_dir": str(out_dir),
                    "display_filter": display_filter or config_data.get("display_filter"),
                    "hosts_file": str(effective_hosts) if effective_hosts else None,
                    "mapping_file": str(mapping_file) if mapping_file else None,
                    "two_pass": two_pass,
                    "command": runner.build_export_command(
                        capture,
                        display_filter=display_filter or config_data.get("display_filter"),
                        extra_args=extra_args,
                        two_pass=two_pass,
                    ),
                },
                indent=2,
            )
        )
        return
    with _progress(2) as on_stage:
        discovery, markdown = discover_capture(
            capture,
            runner=runner,
            display_filter=display_filter or config_data.get("display_filter"),
            extra_args=extra_args,
            two_pass=two_pass,
            on_stage=on_stage,
            hosts_file=effective_hosts,
            mapping_file=mapping_file,
        )
    # write_discovery_artifacts handles semantic filenames and flat file layout
    outputs = write_discovery_artifacts(out_dir, discovery, markdown)
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "mode": "discovery",
                "discovery_json": str(outputs["discovery_json"]),
                "discovery_md": str(outputs["discovery_md"]),
            },
            indent=2,
        )
    )


@app.command("recommend-profiles")
def recommend_profiles_command(
    source: Path = typer.Argument(..., exists=True, readable=True, help="Discovery JSON file or input capture."),
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="Optional TShark display filter when source is a capture."),
    tshark_path: str = typer.Option("tshark", "--tshark-path", help="TShark executable path."),
    tshark_arg: list[str] = typer.Option(None, "--tshark-arg", help="Extra argument passed to tshark."),
) -> None:
    if source.suffix == ".json":
        payload = json.loads(source.read_text(encoding="utf-8"))
        typer.echo(
            json.dumps(
                {
                    "status": "ok",
                    "recommended_profiles": payload.get("candidate_profiles", []),
                    "suppressed_profiles": payload.get("suppressed_profiles", []),
                    "suspected_domains": payload.get("suspected_domains", []),
                },
                indent=2,
            )
        )
        return

    runner = TSharkRunner(binary=tshark_path)
    discovery, _ = discover_capture(
        source,
        runner=runner,
        display_filter=display_filter,
        extra_args=list(tshark_arg or []),
        two_pass=False,
    )
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "recommended_profiles": discovery["candidate_profiles"],
                "suppressed_profiles": discovery["suppressed_profiles"],
                "suspected_domains": discovery["suspected_domains"],
            },
            indent=2,
        )
    )


@app.command("analyze")
def analyze_command(
    capture: Path = typer.Argument(..., exists=True, readable=True, help="Input .pcap or .pcapng file."),
    profile_name: str = typer.Option("lte-core", "--profile", help="Protocol profile name."),
    privacy_profile_name: str | None = typer.Option(
        None,
        "--privacy-profile",
        help="Privacy profile name (built-in: internal, share, lab, prod-safe, llm-telecom-safe) or path to a YAML file.",
    ),
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="TShark display filter."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config file."),
    mapping_file: Path | None = typer.Option(None, "--mapping-file", help="Custom YAML/JSON alias mapping."),
    hosts_file: Path | None = typer.Option(None, "--hosts-file", help="Wireshark hosts-style mapping file."),
    out_dir: Path = typer.Option(Path("artifacts"), "--out", help="Artifact output directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate options and print the plan only."),
    two_pass: bool | None = typer.Option(None, "--two-pass/--no-two-pass", help="Override tshark two-pass mode."),
    verbatim_protocol: list[str] = typer.Option(
        None,
        "--verbatim-protocol",
        help=(
            "Temporarily add a protocol to verbatim_protocols for this run only. "
            "Does not replace missing TShark dissection and does not change the profile file."
        ),
    ),
    no_verbatim_protocol: list[str] = typer.Option(
        None,
        "--no-verbatim-protocol",
        help=(
            "Temporarily remove a protocol from the profile's verbatim_protocols for this run only. "
            "If the same protocol is also passed via --verbatim-protocol, removal wins."
        ),
    ),
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
    oversize_factor: float = typer.Option(
        10.0,
        "--oversize-factor",
        help=(
            "Fail if the exported packet count exceeds max-packets by this factor (default: 10×). "
            "Fires after inspection so summary.json stays accurate. "
            "Use 0 to disable."
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
    effective_verbatim_protocols, verbatim_overlay = _merge_verbatim_protocols(
        profile.verbatim_protocols,
        verbatim_protocol,
        no_verbatim_protocol,
    )
    effective_profile = profile.model_copy(update={"verbatim_protocols": effective_verbatim_protocols})
    runner = TSharkRunner(binary=tshark_path)
    extra_args = list(config_data.get("tshark_extra_args", [])) + list(tshark_arg or [])
    effective_two_pass = profile.tshark.get("two_pass", False) if two_pass is None else two_pass
    effective_profile_overrides = {
        "verbatim_protocols": {
            **verbatim_overlay,
            "effective": effective_verbatim_protocols,
        }
    }
    if verbatim_overlay["added"] or verbatim_overlay["removed"]:
        typer.echo(
            "verbatim override active: "
            f"added={verbatim_overlay['added']}, removed={verbatim_overlay['removed']}, "
            f"effective={effective_verbatim_protocols}",
            err=True,
        )
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
    effective_hosts = _resolve_hosts_file(hosts_file, config_data)
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
                oversize_factor=oversize_factor,
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
                effective_verbatim_protocols=effective_verbatim_protocols,
                effective_profile_overrides=effective_profile_overrides,
            )
        else:
            payload = {
                "capture": str(capture),
                "profile": profile.name,
                "profile_default_verbatim_protocols": profile.verbatim_protocols,
                "privacy_profile": privacy_profile_name or config_data.get("privacy_profile") or "(none — using defaults)",
                "display_filter": effective_filter,
                "max_packets": effective_max_packets if effective_max_packets > 0 else "unlimited",
                "fail_on_truncation": fail_on_truncation,
                "max_capture_size_mb": max_capture_size_mb,
                "privacy_modes": privacy_modes,
                "effective_verbatim_protocols": effective_verbatim_protocols,
                "effective_profile_overrides": effective_profile_overrides,
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
                profile=effective_profile,
                privacy_modes=privacy_modes,
                display_filter=effective_filter,
                hosts_file=effective_hosts,
                mapping_file=effective_mapping,
                extra_args=extra_args,
                two_pass=effective_two_pass,
                max_packets=effective_max_packets,
                fail_on_truncation=fail_on_truncation,
                max_capture_size_mb=max_capture_size_mb,
                oversize_factor=oversize_factor,
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
    if oversize_factor <= 0:
        warnings.append(
            build_warning(
                "oversize_guard_disabled",
                "packet-count oversize guard was disabled explicitly (--oversize-factor 0).",
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
            "pass 1 scans all packets as lightweight field data; pass 2 exports full JSON only for selected packets. For large captures, use a -Y display filter to narrow the input.",
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
            "oversize_factor": oversize_factor,
        },
        warnings=warnings,
        schema_versions={
            "summary": artifacts.summary.get("schema_version"),
            "detail": artifacts.detail.get("schema_version"),
        },
        effective_verbatim_protocols=effective_verbatim_protocols,
        effective_profile_overrides=effective_profile_overrides,
    )
    typer.echo(json.dumps(payload, indent=2))


@session_app.command("start")
def session_start_command(
    capture: Path = typer.Argument(..., exists=True, readable=True, help="Input .pcap or .pcapng file."),
    out_dir: Path = typer.Option(Path("artifacts"), "--out", help="Parent directory for the session."),
) -> None:
    session_dir, manifest = start_session(out_dir, capture, _capture_sha256(capture))
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "session": str(session_dir),
                "manifest": str(session_manifest_path(session_dir)),
                "session_id": manifest["session_id"],
            },
            indent=2,
        )
    )


@session_app.command("run-discovery")
def session_run_discovery_command(
    session: Path = typer.Option(..., "--session", exists=True, file_okay=False, dir_okay=True, readable=True, help="Existing session directory."),
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="Optional TShark display filter."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config file."),
    mapping_file: Path | None = typer.Option(None, "--mapping-file", help="Custom YAML/JSON alias mapping."),
    hosts_file: Path | None = typer.Option(None, "--hosts-file", help="Wireshark hosts-style mapping file."),
    tshark_path: str = typer.Option("tshark", "--tshark-path", help="TShark executable path."),
    tshark_arg: list[str] = typer.Option(None, "--tshark-arg", help="Extra argument passed to tshark."),
) -> None:
    manifest = load_session_manifest(session)
    capture = Path(manifest["input_capture"]["path"])
    run_id = next_run_id(manifest, "discovery")
    run_dir = session / run_id
    config_data = load_config_file(config_path)
    effective_hosts = _resolve_hosts_file(hosts_file, config_data)
    runner = TSharkRunner(binary=tshark_path)
    run = {
        "run_id": run_id,
        "mode": "discovery",
        "status": "in_progress",
        "started_at": _now_iso(),
        "warnings": [],
        "error": None,
    }
    try:
        discovery, markdown = discover_capture(
            capture,
            runner=runner,
            display_filter=display_filter or config_data.get("display_filter"),
            extra_args=list(config_data.get("tshark_extra_args", [])) + list(tshark_arg or []),
            two_pass=False,
            hosts_file=effective_hosts,
            mapping_file=mapping_file,
        )
        outputs = write_discovery_artifacts(run_dir, discovery, markdown)
        run.update(
            {
                "status": "completed",
                "finished_at": _now_iso(),
                "outputs": {k: str(v) for k, v in outputs.items()},
            }
        )
    except Exception as exc:  # noqa: BLE001
        run.update(
            {
                "status": "failed",
                "finished_at": _now_iso(),
                "error": str(exc),
            }
        )
        append_run(session, run)
        raise
    append_run(session, run)
    typer.echo(json.dumps(run, indent=2))


@session_app.command("run-profile")
def session_run_profile_command(
    session: Path = typer.Option(..., "--session", exists=True, file_okay=False, dir_okay=True, readable=True, help="Existing session directory."),
    profile_name: str = typer.Option(..., "--profile", help="Profile to run inside the session."),
    triggered_by: str | None = typer.Option(None, "--triggered-by", help="Optional parent run id."),
    reason: list[str] = typer.Option(None, "--reason", help="Reason(s) for this run; repeat the flag for multiple reasons."),
    tag: str | None = typer.Option(None, "--tag", help="Optional short tag for the run."),
    notes: str | None = typer.Option(None, "--notes", help="Optional free-text notes."),
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="Optional TShark display filter."),
    two_pass: bool | None = typer.Option(None, "--two-pass/--no-two-pass", help="Override tshark two-pass mode."),
    verbatim_protocol: list[str] = typer.Option(None, "--verbatim-protocol", help="Temporarily add a protocol to verbatim for this run."),
    no_verbatim_protocol: list[str] = typer.Option(None, "--no-verbatim-protocol", help="Temporarily remove a protocol from verbatim for this run."),
    tshark_path: str = typer.Option("tshark", "--tshark-path", help="TShark executable path."),
    tshark_arg: list[str] = typer.Option(None, "--tshark-arg", help="Extra argument passed to tshark."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show the planned session run without executing it."),
) -> None:
    manifest = load_session_manifest(session)
    capture = Path(manifest["input_capture"]["path"])
    profile = load_profile(profile_name)
    effective_verbatim_protocols, verbatim_overlay = _merge_verbatim_protocols(
        profile.verbatim_protocols,
        verbatim_protocol,
        no_verbatim_protocol,
    )
    effective_profile = profile.model_copy(update={"verbatim_protocols": effective_verbatim_protocols})
    run_id = next_run_id(manifest, profile.name)
    run_dir = session / run_id
    runner = TSharkRunner(binary=tshark_path)
    effective_two_pass = profile.tshark.get("two_pass", False) if two_pass is None else two_pass
    overrides = {
        "two_pass": effective_two_pass,
        "verbatim_protocols_added": verbatim_overlay["added"],
        "verbatim_protocols_removed": verbatim_overlay["removed"],
        "effective_verbatim_protocols": effective_verbatim_protocols,
    }
    if dry_run:
        typer.echo(
            json.dumps(
                {
                    "status": "ok",
                    "dry_run": True,
                    "session": str(session),
                    "run_id": run_id,
                    "profile": profile.name,
                    "triggered_by": triggered_by,
                    "reason": list(reason or []),
                    "tag": tag,
                    "notes": notes,
                    "overrides": overrides,
                    "command": runner.build_export_command(
                        capture,
                        display_filter=display_filter,
                        extra_args=list(tshark_arg or []),
                        two_pass=effective_two_pass,
                    ),
                },
                indent=2,
            )
        )
        return

    run = {
        "run_id": run_id,
        "mode": "profile_analysis",
        "profile": profile.name,
        "status": "in_progress",
        "started_at": _now_iso(),
        "triggered_by": triggered_by,
        "reason": list(reason or []),
        "tag": tag,
        "notes": notes,
        "overrides": overrides,
        "warnings": [],
        "error": None,
    }
    try:
        artifacts = analyze_capture(
            capture,
            out_dir=run_dir,
            runner=runner,
            profile=effective_profile,
            privacy_modes={},
            display_filter=display_filter,
            extra_args=list(tshark_arg or []),
            two_pass=effective_two_pass,
        )
        outputs = write_artifacts(artifacts, run_dir)
        run.update(
            {
                "status": "completed",
                "finished_at": _now_iso(),
                "outputs": {k: str(v) for k, v in outputs.items()},
            }
        )
    except Exception as exc:  # noqa: BLE001
        run.update(
            {
                "status": "failed",
                "finished_at": _now_iso(),
                "error": str(exc),
            }
        )
        append_run(session, run)
        raise
    append_run(session, run)
    typer.echo(json.dumps(run, indent=2))


@session_app.command("finalize")
def session_finalize_command(
    session: Path = typer.Option(..., "--session", exists=True, file_okay=False, dir_okay=True, readable=True, help="Existing session directory."),
    status: str = typer.Option("completed", "--status", help="Final session status, usually completed or failed."),
) -> None:
    manifest = load_session_manifest(session)
    manifest["status"] = status
    manifest["finished_at"] = _now_iso()
    write_session_manifest(session, manifest)
    report_path = session / "session_report.md"
    report_path.write_text(build_session_report(manifest), encoding="utf-8")
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "session": str(session),
                "manifest": str(session_manifest_path(session)),
                "report": str(report_path),
                "final_status": status,
            },
            indent=2,
        )
    )


app.add_typer(session_app, name="session")
