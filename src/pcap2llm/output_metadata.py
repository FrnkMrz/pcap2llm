from __future__ import annotations

import re
from pathlib import Path


def capture_filename(capture_path: str | Path) -> str:
    return Path(str(capture_path)).name


def capture_stem(capture_path: str | Path) -> str:
    return Path(str(capture_path)).stem


def sanitize_filename_segment(value: str) -> str:
    sanitized = re.sub(r"\s+", "_", value.strip())
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", sanitized)
    sanitized = re.sub(r"_+", "_", sanitized)
    sanitized = sanitized.strip("._-")
    return sanitized or "capture"


def semantic_artifact_prefix(
    *,
    action: str,
    capture_path: str | Path,
    start_packet_number: int | None,
) -> str:
    capture_segment = sanitize_filename_segment(capture_stem(capture_path))
    start_segment = str(start_packet_number) if start_packet_number is not None else "unknown"
    return f"{action}_{capture_segment}_start_{start_segment}"


def semantic_artifact_filename(
    *,
    action: str,
    capture_path: str | Path,
    start_packet_number: int | None,
    version: str,
    extension: str,
    artifact_kind: str | None = None,
) -> str:
    prefix = semantic_artifact_prefix(
        action=action,
        capture_path=capture_path,
        start_packet_number=start_packet_number,
    )
    if artifact_kind:
        return f"{prefix}_{version}_{artifact_kind}{extension}"
    return f"{prefix}_{version}{extension}"


def artifact_version_from_filename(filename: str) -> str | None:
    match = re.search(r"_(V_\d+)(?:_[^.]+)?\.[^.]+$", filename)
    if not match:
        return None
    return match.group(1)


def artifact_identity_from_filename(filename: str) -> dict[str, str | int | None]:
    match = re.fullmatch(
        r"(?P<prefix>.+)_V_(?P<version>\d+)(?:_[^.]+)?\.json",
        filename,
    )
    if not match:
        return {"artifact_prefix": None, "artifact_version": None}
    return {
        "artifact_prefix": match.group("prefix"),
        "artifact_version": int(match.group("version")),
    }


def build_run_metadata(action: str) -> dict[str, str]:
    return {"action": action}


def build_capture_metadata(
    *,
    path: str | Path,
    first_packet_number: int | None,
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> dict[str, str | int | None]:
    capture: dict[str, str | int | None] = {
        "filename": capture_filename(path),
        "path": str(path),
        "first_packet_number": first_packet_number,
    }
    if first_seen is not None:
        capture["first_seen"] = first_seen
    if last_seen is not None:
        capture["last_seen"] = last_seen
    return capture


def build_artifact_metadata(version: str | None) -> dict[str, str | None]:
    return {"version": version}


def build_selection_metadata(
    *,
    start_packet_number: int | None,
    end_packet_number: int | None,
) -> dict[str, int] | None:
    if start_packet_number is None and end_packet_number is None:
        return None
    selection: dict[str, int] = {}
    if start_packet_number is not None:
        selection["start_packet_number"] = start_packet_number
    if end_packet_number is not None:
        selection["end_packet_number"] = end_packet_number
    return selection
