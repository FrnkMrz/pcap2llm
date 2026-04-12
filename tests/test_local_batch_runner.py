from __future__ import annotations

from pathlib import Path

import pytest

from pcap2llm.local_batch_runner import (
    BatchDefinition,
    BatchCase,
    build_case_command,
    load_batch_definition,
    resolve_case_output_dir,
    run_case,
)


def test_load_batch_definition_resolves_repo_relative_paths(tmp_path: Path) -> None:
    batch_path = tmp_path / "local_examples.toml"
    batch_path.write_text(
        """
[batch]
name = "demo"
default_output_root = ".local/results/demo"
continue_on_error = true

[[cases]]
name = "discover_one"
action = "discover"
capture = ".local/PCAPs/sample.pcapng"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    batch = load_batch_definition(batch_path, tmp_path)

    assert batch.name == "demo"
    assert batch.default_output_root == tmp_path / ".local/results/demo"
    assert batch.cases[0].capture == tmp_path / ".local/PCAPs/sample.pcapng"


def test_build_case_command_keeps_runner_managed_output_dir(tmp_path: Path) -> None:
    case = BatchCase(
        name="analyze_one",
        action="analyze",
        capture=tmp_path / "trace.pcapng",
        profile="lte-s6a",
        args=("--privacy-profile", "internal", "--max-packets", "500"),
        hosts_file=tmp_path / "hosts.txt",
        mapping_file=tmp_path / "mapping.yaml",
    )

    command = build_case_command(tmp_path / "pcap2llm", case, tmp_path / "out")

    assert command == [
        str(tmp_path / "pcap2llm"),
        "analyze",
        str(tmp_path / "trace.pcapng"),
        "--profile",
        "lte-s6a",
        "--hosts-file",
        str(tmp_path / "hosts.txt"),
        "--mapping-file",
        str(tmp_path / "mapping.yaml"),
        "--privacy-profile",
        "internal",
        "--max-packets",
        "500",
        "--out",
        str(tmp_path / "out"),
    ]


def test_resolve_case_output_dir_prefers_case_override(tmp_path: Path) -> None:
    batch = BatchDefinition(
        name="demo",
        path=tmp_path / "batch.toml",
        default_output_root=tmp_path / ".local/results/default",
        continue_on_error=True,
        cases=(),
    )
    case = BatchCase(
        name="inspect_one",
        action="inspect",
        capture=tmp_path / "trace.pcapng",
        output_dir=tmp_path / ".local/custom_output",
    )

    resolved = resolve_case_output_dir(batch, case, tmp_path / ".local/results/override")
    assert resolved == tmp_path / ".local/custom_output"


def test_run_case_skips_missing_capture(tmp_path: Path) -> None:
    batch_path = tmp_path / "batch.toml"
    batch_path.write_text(
        """
[batch]
name = "demo"
default_output_root = ".local/results/demo"

[[cases]]
name = "discover_missing"
action = "discover"
capture = ".local/PCAPs/missing.pcapng"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    batch = load_batch_definition(batch_path, tmp_path)
    case = batch.cases[0]

    result = run_case(
        binary=tmp_path / "pcap2llm",
        batch=batch,
        case=case,
        output_root_override=None,
        repo_root=tmp_path,
        dry_run=False,
    )

    assert result.status == "skipped"
    assert "capture missing" in result.detail


def test_load_batch_definition_rejects_discover_profile(tmp_path: Path) -> None:
    batch_path = tmp_path / "invalid.toml"
    batch_path.write_text(
        """
[batch]
name = "demo"

[[cases]]
name = "bad_discover"
action = "discover"
capture = ".local/PCAPs/sample.pcapng"
profile = "lte-core"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must not set profile"):
        load_batch_definition(batch_path, tmp_path)
