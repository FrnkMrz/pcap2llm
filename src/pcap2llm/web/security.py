from __future__ import annotations

import os
import re
from pathlib import Path
from uuid import UUID

_ALLOWED_SUFFIXES = {".pcap", ".pcapng"}
_PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-\s\.]{1,255}$")
_DISPLAY_FILTER_PATTERN = re.compile(r"^[A-Za-z0-9._=!&|()<>\x22' \-+:/]+$")


class WebValidationError(ValueError):
    pass



def sanitize_filename(filename: str) -> str:
    base = Path(filename or "capture.pcapng").name
    safe = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")
    if not safe:
        safe = "capture.pcapng"
    return safe



def validate_capture_filename(filename: str) -> None:
    suffix = Path(filename).suffix.lower()
    if suffix not in _ALLOWED_SUFFIXES:
        raise WebValidationError("Unsupported file type. Please upload .pcap or .pcapng.")



def ensure_within(base_dir: Path, candidate: Path) -> Path:
    base_resolved = base_dir.resolve()
    target_resolved = candidate.resolve()
    try:
        common = Path(os.path.commonpath([str(base_resolved), str(target_resolved)]))
    except ValueError as exc:
        raise WebValidationError("Invalid path.") from exc
    if common != base_resolved:
        raise WebValidationError("Requested path is outside the job workspace.")
    return target_resolved



def reject_nested_filename(filename: str) -> None:
    if "/" in filename or "\\" in filename:
        raise WebValidationError("Invalid filename.")


def validate_id(value: str) -> None:
    try:
        parsed = UUID(value, version=4)
    except ValueError as exc:
        raise WebValidationError("Invalid identifier.") from exc
    if str(parsed) != value:
        raise WebValidationError("Invalid identifier.")


def validate_display_filter(value: str) -> None:
    if not value:
        return
    if value.startswith("-") or not _DISPLAY_FILTER_PATTERN.fullmatch(value):
        raise WebValidationError("Invalid display filter.")


def validate_profile_name(name: str) -> None:
    """Validate profile name against allowed pattern (alphanumeric, _, -, spaces, dots)."""
    if not name or not _PROFILE_NAME_PATTERN.match(name):
        raise WebValidationError(
            "Profile name must contain only letters, numbers, spaces, dots, underscores, and hyphens (1-255 chars)."
        )


def validate_string_length(value: str | None, max_length: int, field_name: str) -> None:
    """Validate string doesn't exceed max length."""
    if value and len(value) > max_length:
        raise WebValidationError(f"{field_name} exceeds maximum length of {max_length} characters.")
