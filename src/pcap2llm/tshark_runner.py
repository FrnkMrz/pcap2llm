from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class TSharkError(RuntimeError):
    """Raised when tshark execution fails."""


class TSharkRunner:
    def __init__(self, binary: str = "tshark") -> None:
        self.binary = binary

    def ensure_available(self) -> None:
        if shutil.which(self.binary) is None:
            raise TSharkError(
                "tshark was not found in PATH. Install Wireshark/TShark and retry."
            )

    def build_export_command(
        self,
        capture_path: Path,
        *,
        display_filter: str | None = None,
        extra_args: list[str] | None = None,
        two_pass: bool = False,
    ) -> list[str]:
        command = [self.binary, "-n", "-r", str(capture_path), "-T", "json"]
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
        decoded = json.loads(payload)
        if not isinstance(decoded, list):
            raise TSharkError("Unexpected tshark JSON structure")
        return decoded
