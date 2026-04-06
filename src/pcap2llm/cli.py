from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

from pcap2llm.config import build_privacy_modes, load_config_file, normalize_mode, sample_config_text
from pcap2llm.inspector import inspect_capture
from pcap2llm.pipeline import analyze_capture, write_artifacts
from pcap2llm.profiles import load_profile
from pcap2llm.tshark_runner import TSharkError, TSharkRunner

app = typer.Typer(help="Convert PCAP/PCAPNG captures into LLM-friendly artifacts.")
logger = logging.getLogger("pcap2llm")


def _configure_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(message)s")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", help="Enable info logging."),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging."),
) -> None:
    _configure_logging(verbose, debug)


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


def _build_modes(config_data: dict, profile_defaults: dict[str, str], overrides: dict[str, str | None]) -> dict[str, str]:
    merged = dict(config_data.get("privacy_modes", {}))
    merged.update({key: value for key, value in overrides.items() if value is not None})
    return build_privacy_modes(profile_defaults, merged)


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
        result = inspect_capture(
            capture,
            runner=runner,
            profile=profile,
            display_filter=display_filter or config_data.get("display_filter"),
            extra_args=extra_args,
            two_pass=effective_two_pass,
        )
    except TSharkError as exc:
        raise typer.Exit(str(exc)) from exc
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
    display_filter: str | None = typer.Option(None, "--display-filter", "-Y", help="TShark display filter."),
    config_path: Path | None = typer.Option(None, "--config", help="Optional YAML config file."),
    mapping_file: Path | None = typer.Option(None, "--mapping-file", help="Custom YAML/JSON alias mapping."),
    hosts_file: Path | None = typer.Option(None, "--hosts-file", help="Wireshark hosts-style mapping file."),
    out_dir: Path = typer.Option(Path("artifacts"), "--out", help="Artifact output directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate options and print the plan only."),
    two_pass: bool | None = typer.Option(None, "--two-pass/--no-two-pass", help="Override tshark two-pass mode."),
    tshark_path: str = typer.Option("tshark", "--tshark-path", help="TShark executable path."),
    tshark_arg: list[str] = typer.Option(None, "--tshark-arg", help="Extra argument passed to tshark."),
    ip_mode: str | None = typer.Option(None, "--ip-mode", callback=lambda value: normalize_mode(value) if value else None),
    hostname_mode: str | None = typer.Option(None, "--hostname-mode", callback=lambda value: normalize_mode(value) if value else None),
    subscriber_id_mode: str | None = typer.Option(None, "--subscriber-id-mode", callback=lambda value: normalize_mode(value) if value else None),
    msisdn_mode: str | None = typer.Option(None, "--msisdn-mode", callback=lambda value: normalize_mode(value) if value else None),
    imsi_mode: str | None = typer.Option(None, "--imsi-mode", callback=lambda value: normalize_mode(value) if value else None),
    imei_mode: str | None = typer.Option(None, "--imei-mode", callback=lambda value: normalize_mode(value) if value else None),
    email_mode: str | None = typer.Option(None, "--email-mode", callback=lambda value: normalize_mode(value) if value else None),
    dn_mode: str | None = typer.Option(None, "--dn-mode", callback=lambda value: normalize_mode(value) if value else None),
    token_mode: str | None = typer.Option(None, "--token-mode", callback=lambda value: normalize_mode(value) if value else None),
    uri_mode: str | None = typer.Option(None, "--uri-mode", callback=lambda value: normalize_mode(value) if value else None),
    apn_dnn_mode: str | None = typer.Option(None, "--apn-dnn-mode", callback=lambda value: normalize_mode(value) if value else None),
    diameter_identity_mode: str | None = typer.Option(None, "--diameter-identity-mode", callback=lambda value: normalize_mode(value) if value else None),
    payload_text_mode: str | None = typer.Option(None, "--payload-text-mode", callback=lambda value: normalize_mode(value) if value else None),
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
    privacy_modes = _build_modes(config_data, profile.default_privacy_modes, overrides)
    effective_hosts = hosts_file or (Path(config_data["hosts_file"]) if config_data.get("hosts_file") else None)
    effective_mapping = mapping_file or (Path(config_data["mapping_file"]) if config_data.get("mapping_file") else None)
    effective_filter = display_filter or config_data.get("display_filter")

    if dry_run:
        typer.echo(
            json.dumps(
                {
                    "capture": str(capture),
                    "profile": profile.name,
                    "display_filter": effective_filter,
                    "privacy_modes": privacy_modes,
                    "hosts_file": str(effective_hosts) if effective_hosts else None,
                    "mapping_file": str(effective_mapping) if effective_mapping else None,
                    "command": runner.build_export_command(
                        capture,
                        display_filter=effective_filter,
                        extra_args=extra_args,
                        two_pass=effective_two_pass,
                    ),
                },
                indent=2,
            )
        )
        return

    try:
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
        )
    except TSharkError as exc:
        raise typer.Exit(str(exc)) from exc

    outputs = write_artifacts(artifacts, out_dir)
    typer.echo(json.dumps({key: str(value) for key, value in outputs.items()}, indent=2))
