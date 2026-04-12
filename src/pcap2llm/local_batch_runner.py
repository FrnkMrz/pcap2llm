from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path


VALID_ACTIONS = {"discover", "inspect", "analyze"}


@dataclass(frozen=True)
class BatchCase:
    name: str
    action: str
    capture: Path
    profile: str | None = None
    args: tuple[str, ...] = ()
    output_dir: Path | None = None
    hosts_file: Path | None = None
    mapping_file: Path | None = None


@dataclass(frozen=True)
class BatchDefinition:
    name: str
    path: Path
    default_output_root: Path
    continue_on_error: bool
    cases: tuple[BatchCase, ...]


@dataclass(frozen=True)
class CaseResult:
    name: str
    action: str
    capture: Path
    output_dir: Path
    status: str
    returncode: int
    detail: str = ""


def repo_root_from(path: Path | None = None) -> Path:
    candidate = path or Path(__file__).resolve()
    return candidate.parents[2]


def _resolve_local_path(value: str, repo_root: Path) -> Path:
    expanded = Path(os.path.expandvars(os.path.expanduser(value)))
    if expanded.is_absolute():
        return expanded
    return repo_root / expanded


def load_batch_definition(path: Path, repo_root: Path) -> BatchDefinition:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    batch_cfg = payload.get("batch", {})
    case_entries = payload.get("cases", [])
    if not isinstance(case_entries, list) or not case_entries:
        raise ValueError(f"{path} does not define any [[cases]] entries")

    default_output_root = _resolve_local_path(
        str(batch_cfg.get("default_output_root", ".local/results/local_batches")),
        repo_root,
    )
    continue_on_error = bool(batch_cfg.get("continue_on_error", True))
    name = str(batch_cfg.get("name", path.stem))

    cases: list[BatchCase] = []
    for index, raw_case in enumerate(case_entries, start=1):
        if not isinstance(raw_case, dict):
            raise ValueError(f"{path}: case #{index} must be a table")
        case_name = str(raw_case.get("name", "")).strip()
        action = str(raw_case.get("action", "")).strip()
        capture = str(raw_case.get("capture", "")).strip()
        if not case_name:
            raise ValueError(f"{path}: case #{index} is missing name")
        if action not in VALID_ACTIONS:
            raise ValueError(f"{path}: case {case_name!r} has unsupported action {action!r}")
        if not capture:
            raise ValueError(f"{path}: case {case_name!r} is missing capture")
        profile = raw_case.get("profile")
        if action == "discover" and profile:
            raise ValueError(f"{path}: case {case_name!r} must not set profile for discover")
        args = tuple(str(item) for item in raw_case.get("args", []))
        if "--out" in args:
            raise ValueError(f"{path}: case {case_name!r} must use output_dir, not --out inside args")
        output_dir = raw_case.get("output_dir")
        hosts_file = raw_case.get("hosts_file")
        mapping_file = raw_case.get("mapping_file")
        cases.append(
            BatchCase(
                name=case_name,
                action=action,
                capture=_resolve_local_path(capture, repo_root),
                profile=str(profile) if profile is not None else None,
                args=args,
                output_dir=_resolve_local_path(str(output_dir), repo_root) if output_dir else None,
                hosts_file=_resolve_local_path(str(hosts_file), repo_root) if hosts_file else None,
                mapping_file=_resolve_local_path(str(mapping_file), repo_root) if mapping_file else None,
            )
        )

    return BatchDefinition(
        name=name,
        path=path,
        default_output_root=default_output_root,
        continue_on_error=continue_on_error,
        cases=tuple(cases),
    )


def select_cases(batch: BatchDefinition, selected_names: set[str]) -> list[BatchCase]:
    if not selected_names:
        return list(batch.cases)
    selected = [case for case in batch.cases if case.name in selected_names]
    missing = sorted(selected_names - {case.name for case in selected})
    if missing:
        raise ValueError(f"Unknown case name(s): {', '.join(missing)}")
    return selected


def resolve_case_output_dir(
    batch: BatchDefinition,
    case: BatchCase,
    output_root_override: Path | None,
) -> Path:
    if case.output_dir is not None:
        return case.output_dir
    root = output_root_override or batch.default_output_root
    return root / case.name


def resolve_pcap2llm_binary(repo_root: Path) -> Path:
    local_bin = repo_root / ".venv" / "bin" / "pcap2llm"
    local_python = repo_root / ".venv" / "bin" / "python"
    if local_bin.exists() and local_python.exists():
        check = subprocess.run(
            [str(local_python), "-c", "import pcap2llm"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if check.returncode == 0:
            return local_bin
    binary = shutil.which("pcap2llm")
    if binary:
        return Path(binary)
    raise FileNotFoundError("pcap2llm not found in PATH and repo .venv is not usable")


def build_case_command(binary: Path, case: BatchCase, output_dir: Path) -> list[str]:
    command = [str(binary), case.action, str(case.capture)]
    if case.profile:
        command.extend(["--profile", case.profile])
    if case.action in {"discover", "analyze"} and case.hosts_file is not None:
        command.extend(["--hosts-file", str(case.hosts_file)])
    if case.action in {"discover", "analyze"} and case.mapping_file is not None:
        command.extend(["--mapping-file", str(case.mapping_file)])
    command.extend(case.args)
    command.extend(["--out", str(output_dir)])
    return command


def format_command(command: list[str]) -> str:
    return " ".join(shlex_quote(part) for part in command)


def shlex_quote(value: str) -> str:
    if not value:
        return "''"
    safe = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")
    if all(char in safe for char in value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_case(
    *,
    binary: Path,
    batch: BatchDefinition,
    case: BatchCase,
    output_root_override: Path | None,
    repo_root: Path,
    dry_run: bool,
) -> CaseResult:
    output_dir = resolve_case_output_dir(batch, case, output_root_override)
    command = build_case_command(binary, case, output_dir)

    if not case.capture.exists():
        return CaseResult(
            name=case.name,
            action=case.action,
            capture=case.capture,
            output_dir=output_dir,
            status="skipped",
            returncode=0,
            detail=f"capture missing: {case.capture}",
        )
    for label, helper_path in (("hosts file", case.hosts_file), ("mapping file", case.mapping_file)):
        if helper_path is not None and not helper_path.exists():
            return CaseResult(
                name=case.name,
                action=case.action,
                capture=case.capture,
                output_dir=output_dir,
                status="failed",
                returncode=2,
                detail=f"{label} missing: {helper_path}",
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    if dry_run:
        return CaseResult(
            name=case.name,
            action=case.action,
            capture=case.capture,
            output_dir=output_dir,
            status="dry-run",
            returncode=0,
            detail=format_command(command),
        )

    proc = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode == 0:
        return CaseResult(
            name=case.name,
            action=case.action,
            capture=case.capture,
            output_dir=output_dir,
            status="ok",
            returncode=0,
            detail=proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "",
        )

    last_error_line = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "command failed"
    return CaseResult(
        name=case.name,
        action=case.action,
        capture=case.capture,
        output_dir=output_dir,
        status="failed",
        returncode=proc.returncode,
        detail=last_error_line,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run repo-owned local PCAP batches without committing inputs or outputs.")
    parser.add_argument(
        "--batch",
        default="batches/local_examples.toml",
        help="Batch definition file relative to the repo root or as an absolute path.",
    )
    parser.add_argument(
        "--case",
        action="append",
        dest="cases",
        default=[],
        help="Run only the named case. Repeat to select multiple cases.",
    )
    parser.add_argument(
        "--output-root",
        help="Override the batch default output root. Each case writes into a subdirectory there unless it defines output_dir.",
    )
    parser.add_argument("--list", action="store_true", help="List available cases and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Print the resolved commands without executing them.")
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first failure even if the batch file would normally continue.",
    )
    return parser


def print_case_listing(batch: BatchDefinition) -> None:
    print(f"Batch: {batch.name}")
    print(f"Definition: {batch.path}")
    print(f"Default output root: {batch.default_output_root}")
    print("")
    for case in batch.cases:
        profile = f" profile={case.profile}" if case.profile else ""
        print(f"- {case.name}: {case.action} {case.capture}{profile}")


def print_case_result(index: int, total: int, result: CaseResult) -> None:
    print(f"[{index}/{total}] {result.name}")
    print(f"  action : {result.action}")
    print(f"  capture: {result.capture}")
    print(f"  output : {result.output_dir}")
    print(f"  status : {result.status}")
    if result.detail:
        print(f"  detail : {result.detail}")


def summarize_results(results: list[CaseResult]) -> int:
    counts = {
        "ok": sum(result.status == "ok" for result in results),
        "failed": sum(result.status == "failed" for result in results),
        "skipped": sum(result.status == "skipped" for result in results),
        "dry-run": sum(result.status == "dry-run" for result in results),
    }
    print("")
    print("Summary")
    print(f"  total   : {len(results)}")
    print(f"  ok      : {counts['ok']}")
    print(f"  failed  : {counts['failed']}")
    print(f"  skipped : {counts['skipped']}")
    if counts["dry-run"]:
        print(f"  dry-run : {counts['dry-run']}")
    return 1 if counts["failed"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    repo_root = repo_root_from()
    batch_path = _resolve_local_path(args.batch, repo_root)
    batch = load_batch_definition(batch_path, repo_root)

    if args.list:
        print_case_listing(batch)
        return 0

    output_root_override = (
        _resolve_local_path(args.output_root, repo_root) if args.output_root else None
    )
    cases = select_cases(batch, set(args.cases))
    binary = resolve_pcap2llm_binary(repo_root)
    stop_on_error = args.fail_fast or not batch.continue_on_error

    results: list[CaseResult] = []
    for index, case in enumerate(cases, start=1):
        result = run_case(
            binary=binary,
            batch=batch,
            case=case,
            output_root_override=output_root_override,
            repo_root=repo_root,
            dry_run=args.dry_run,
        )
        results.append(result)
        print_case_result(index, len(cases), result)
        print("")
        if result.status == "failed" and stop_on_error:
            break

    return summarize_results(results)


if __name__ == "__main__":
    raise SystemExit(main())
