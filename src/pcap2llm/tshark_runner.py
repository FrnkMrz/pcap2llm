from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from pcap2llm.index_models import (
    INDEX_FIELDS,
    INDEX_SEPARATOR,
    PacketIndexRecord,
    parse_index_row,
)

logger = logging.getLogger(__name__)

# Maximum number of frame numbers per TShark invocation in pass-2 export.
# TShark display-filter strings have no hard-coded length limit but very large
# filters (>10 000 chars) can cause parser slowdowns.  500 frame numbers
# produce a filter string of ~3 000 characters — comfortably within limits.
_FRAME_CHUNK_SIZE = 500


def _tshark_executable_name() -> str:
    return "tshark.exe" if os.name == "nt" else "tshark"


def _looks_like_path(value: str) -> bool:
    return any(sep and sep in value for sep in (os.sep, os.altsep)) or ":" in value or value.startswith(".") or value.startswith("~")


def _standard_tshark_locations() -> list[Path]:
    executable = _tshark_executable_name()
    if os.name == "nt":
        candidates: list[Path] = []
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.getenv(env_name)
            if base:
                candidates.append(Path(base) / "Wireshark" / executable)
        return candidates
    return [
        Path("/Applications/Wireshark.app/Contents/MacOS") / executable,
        Path("/opt/homebrew/bin") / executable,
        Path("/usr/local/bin") / executable,
        Path("/usr/bin") / executable,
        Path("/snap/bin") / executable,
    ]


def _resolve_path_candidate(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.exists() and candidate.is_dir():
        candidate = candidate / _tshark_executable_name()
    return candidate


def _format_probe_failure(stderr: str, *, binary: str) -> str:
    detail = stderr.strip()
    if detail:
        return f"TShark at '{binary}' could not be started: {detail}"
    return f"TShark at '{binary}' could not be started."


def _supports_output_format(help_text: str, output_format: str) -> bool:
    return re.search(rf"\b{re.escape(output_format)}\b", help_text, flags=re.IGNORECASE) is not None


def _merge_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Preserve duplicate object keys emitted by TShark as lists.

    TShark's JSON output can contain repeated keys such as ``diameter.avp_tree``
    for repeated AVPs. Standard ``json.loads`` keeps only the last occurrence,
    which drops earlier AVPs. This hook retains all occurrences by converting
    duplicate keys into lists while leaving unique keys unchanged.
    """
    merged: dict[str, Any] = {}
    for key, value in pairs:
        if key in merged:
            existing = merged[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                merged[key] = [existing, value]
        else:
            merged[key] = value
    return merged


def _decode_tshark_json(payload: str, *, context: str) -> list[dict[str, Any]]:
    try:
        decoded = json.loads(payload, object_pairs_hook=_merge_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise TSharkError(f"{context} tshark output is not valid JSON: {exc}") from exc
    if not isinstance(decoded, list):
        raise TSharkError(f"Unexpected {context} tshark JSON structure (expected a list)")
    return decoded


class TSharkError(RuntimeError):
    """Raised when tshark execution fails."""


class TSharkRunner:
    def __init__(self, binary: str = "tshark") -> None:
        self.binary = (binary or "tshark").strip() or "tshark"
        self._resolved_binary: str | None = None
        self._validated_binary: str | None = None
        self._version_banner: str = ""

    def _command_binary(self) -> str:
        return self._resolved_binary or self.binary

    def _resolve_binary(self) -> str:
        if self._resolved_binary:
            return self._resolved_binary

        requested = self.binary
        if _looks_like_path(requested):
            candidate = _resolve_path_candidate(requested)
            if candidate.exists() and candidate.is_file():
                self._resolved_binary = str(candidate.resolve())
                return self._resolved_binary
            raise TSharkError(
                f"TShark executable was not found at configured path: {candidate}"
            )

        resolved = shutil.which(requested)
        if resolved:
            self._resolved_binary = resolved
            return resolved

        if requested != "tshark":
            raise TSharkError(
                f"TShark executable '{requested}' was not found in PATH."
            )

        env_candidate = os.getenv("PCAP2LLM_TSHARK_PATH", "").strip()
        if env_candidate:
            candidate = _resolve_path_candidate(env_candidate)
            if candidate.exists() and candidate.is_file():
                self._resolved_binary = str(candidate.resolve())
                return self._resolved_binary

        for candidate in _standard_tshark_locations():
            if candidate.exists() and candidate.is_file():
                self._resolved_binary = str(candidate.resolve())
                return self._resolved_binary

        raise TSharkError(
            "tshark was not found. Install Wireshark/TShark, add it to PATH, or set --tshark-path / PCAP2LLM_TSHARK_PATH."
        )

    def _probe_capabilities(self, resolved_binary: str) -> None:
        version = subprocess.run(
            [resolved_binary, "-v"],
            capture_output=True,
            text=True,
            check=False,
        )
        if version.returncode != 0:
            raise TSharkError(_format_probe_failure(version.stderr or version.stdout, binary=resolved_binary))
        lines = [line.strip() for line in (version.stdout or version.stderr or "").splitlines() if line.strip()]
        self._version_banner = lines[0] if lines else ""

        help_result = subprocess.run(
            [resolved_binary, "-h"],
            capture_output=True,
            text=True,
            check=False,
        )
        help_text = "\n".join(part for part in (help_result.stdout, help_result.stderr) if part)
        if help_result.returncode != 0 and not help_text.strip():
            raise TSharkError(_format_probe_failure(help_result.stderr or help_result.stdout, binary=resolved_binary))

        if not _supports_output_format(help_text, "json"):
            raise TSharkError(
                f"TShark at '{resolved_binary}' does not support '-T json'. Install a newer Wireshark/TShark version and retry."
            )
        if not _supports_output_format(help_text, "fields"):
            raise TSharkError(
                f"TShark at '{resolved_binary}' does not support '-T fields'. Install a compatible Wireshark/TShark version and retry."
            )

    def ensure_available(self) -> None:
        resolved_binary = self._resolve_binary()
        if self._validated_binary == resolved_binary:
            return
        self._probe_capabilities(resolved_binary)
        self._validated_binary = resolved_binary

    def runtime_info(self) -> dict[str, str]:
        return {
            "binary": self._resolved_binary or self.binary,
            "version": self._version_banner,
        }

    def build_export_command(
        self,
        capture_path: Path,
        *,
        display_filter: str | None = None,
        extra_args: list[str] | None = None,
        two_pass: bool = False,
    ) -> list[str]:
        command = [self._command_binary(), "-n", "-r", str(capture_path), "-T", "json"]
        if two_pass:
            command.append("-2")
        if display_filter:
            command.extend(["-Y", display_filter])
        command.extend(extra_args or [])
        return command

    def export_packets(
        self,
        capture_path: Path,
        *,
        display_filter: str | None = None,
        extra_args: list[str] | None = None,
        two_pass: bool = False,
    ) -> list[dict[str, Any]]:
        self.ensure_available()
        command = self.build_export_command(
            capture_path,
            display_filter=display_filter,
            extra_args=extra_args,
            two_pass=two_pass,
        )
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            stderr = result.stderr.strip() or "unknown tshark error"
            raise TSharkError(stderr)
        payload = result.stdout.strip()
        if not payload:
            return []
        return _decode_tshark_json(payload, context="")

    # ------------------------------------------------------------------
    # Pass-1: lightweight packet-index export
    # ------------------------------------------------------------------

    def build_index_command(
        self,
        capture_path: Path,
        *,
        fields: tuple[str, ...] = INDEX_FIELDS,
        display_filter: str | None = None,
        extra_args: list[str] | None = None,
        two_pass: bool = False,
    ) -> list[str]:
        """Build the TShark command for pass-1 lightweight field export.

        *fields* defaults to :data:`INDEX_FIELDS` but can be narrowed to a
        subset when some field names are not supported by the local TShark
        version (see :meth:`export_packet_index` for the retry logic).
        """
        command = [self._command_binary(), "-n", "-r", str(capture_path), "-T", "fields"]
        if two_pass:
            command.append("-2")
        if display_filter:
            command.extend(["-Y", display_filter])
        for field in fields:
            command.extend(["-e", field])
        command.extend(["-E", f"separator={INDEX_SEPARATOR}", "-E", "header=n"])
        command.extend(extra_args or [])
        return command

    @staticmethod
    def _parse_invalid_fields(stderr: str) -> set[str]:
        """Extract field names from a TShark 'Some fields aren't valid' error message.

        TShark formats this as::

            tshark: Some fields aren't valid:
            \\tfield.name.one
            \\tfield.name.two

        Returns the set of rejected field names, or an empty set if the stderr
        does not match this pattern.
        """
        invalid: set[str] = set()
        in_block = False
        for line in stderr.splitlines():
            if "fields aren't valid" in line:
                in_block = True
                continue
            if in_block:
                stripped = line.strip()
                if stripped:
                    invalid.add(stripped)
                else:
                    break  # blank line ends the block
        return invalid

    def export_packet_index(
        self,
        capture_path: Path,
        *,
        display_filter: str | None = None,
        extra_args: list[str] | None = None,
        two_pass: bool = False,
    ) -> list[PacketIndexRecord]:
        """Run pass-1 TShark export and return lightweight per-packet records.

        Uses ``tshark -T fields`` with the fields from :data:`INDEX_FIELDS`.
        Because ``INDEX_FIELDS`` includes alternative spellings for field names
        that differ across TShark versions, some names may be rejected on a
        given installation.  When TShark exits with a "Some fields aren't
        valid" error, those names are removed and the export is retried once
        with the reduced field list.  The active field list is then passed to
        :func:`~pcap2llm.index_models.parse_index_row` so the parser knows
        which column corresponds to which name.

        Malformed rows are logged and skipped silently.
        """
        self.ensure_available()
        active_fields = INDEX_FIELDS
        command = self.build_index_command(
            capture_path,
            fields=active_fields,
            display_filter=display_filter,
            extra_args=extra_args,
            two_pass=two_pass,
        )
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        # Retry once if TShark rejected some field names.
        if result.returncode != 0:
            stderr = result.stderr.strip() or ""
            invalid = self._parse_invalid_fields(stderr)
            if invalid:
                logger.warning(
                    "pass-1: TShark rejected %d field name(s) on this installation "
                    "(likely version-specific): %s. Falling back to the supported "
                    "subset and continuing analysis.",
                    len(invalid),
                    ", ".join(sorted(invalid)),
                )
                active_fields = tuple(f for f in INDEX_FIELDS if f not in invalid)
                command = self.build_index_command(
                    capture_path,
                    fields=active_fields,
                    display_filter=display_filter,
                    extra_args=extra_args,
                    two_pass=two_pass,
                )
                result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode != 0:
            stderr = result.stderr.strip() or "unknown tshark error"
            raise TSharkError(stderr)

        payload = result.stdout
        if not payload.strip():
            return []
        records: list[PacketIndexRecord] = []
        dropped = 0
        for line in payload.splitlines():
            if not line.strip():
                continue
            record = parse_index_row(line, active_fields)
            if record is None:
                dropped += 1
                logger.warning("pass-1: skipped malformed index row: %r", line[:120])
            else:
                records.append(record)
        if dropped:
            logger.warning(
                "pass-1: dropped %d malformed rows out of %d total",
                dropped, dropped + len(records),
            )
        return records

    # ------------------------------------------------------------------
    # Pass-2: full JSON export for selected frames only
    # ------------------------------------------------------------------

    def build_selected_export_command(
        self,
        capture_path: Path,
        *,
        frame_numbers: list[int],
        extra_args: list[str] | None = None,
        two_pass: bool = False,
    ) -> list[str]:
        """Build TShark command that exports only the given frame numbers as JSON."""
        numbers_str = ",".join(str(n) for n in frame_numbers)
        display_filter = f"frame.number in {{{numbers_str}}}"
        command = [self._command_binary(), "-n", "-r", str(capture_path), "-T", "json"]
        if two_pass:
            command.append("-2")
        command.extend(["-Y", display_filter])
        command.extend(extra_args or [])
        return command

    def export_selected_packets(
        self,
        capture_path: Path,
        *,
        frame_numbers: list[int],
        extra_args: list[str] | None = None,
        two_pass: bool = False,
    ) -> list[dict[str, Any]]:
        """Run pass-2 TShark export and return full JSON only for selected frames.

        If *frame_numbers* is empty, returns an empty list without calling TShark.
        For large frame sets the export is chunked into multiple TShark invocations
        (each of at most :data:`_FRAME_CHUNK_SIZE` frames) and results are merged
        in order.
        """
        self.ensure_available()
        if not frame_numbers:
            return []

        # Chunk large frame sets to keep TShark filter strings manageable.
        chunks = [
            frame_numbers[i : i + _FRAME_CHUNK_SIZE]
            for i in range(0, len(frame_numbers), _FRAME_CHUNK_SIZE)
        ]
        packets: list[dict[str, Any]] = []
        for chunk in chunks:
            command = self.build_selected_export_command(
                capture_path,
                frame_numbers=chunk,
                extra_args=extra_args,
                two_pass=two_pass,
            )
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                stderr = result.stderr.strip() or "unknown tshark error"
                raise TSharkError(f"pass-2 export failed: {stderr}")
            payload = result.stdout.strip()
            if not payload:
                continue
            decoded = _decode_tshark_json(payload, context="pass-2")
            packets.extend(decoded)
        return packets
