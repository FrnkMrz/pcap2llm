from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_package_contents.py"
spec = importlib.util.spec_from_file_location("check_package_contents", SCRIPT_PATH)
assert spec is not None
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def _write_wheel(path: Path, *, omit: str | None = None, entry_points_text: str | None = None) -> Path:
    wheel = path / "pcap2llm-0.1.0-py3-none-any.whl"
    members = set(module.REQUIRED_WHEEL_MEMBERS)
    if omit is not None:
        members.remove(omit)
    with zipfile.ZipFile(wheel, "w") as zf:
        for member in members:
            zf.writestr(member, b"placeholder")
        zf.writestr(
            "pcap2llm-0.1.0.dist-info/entry_points.txt",
            entry_points_text
            if entry_points_text is not None
            else "\n".join(("[console_scripts]", *module.REQUIRED_ENTRY_POINTS)),
        )
    return wheel


def test_validate_wheel_accepts_required_package_files(tmp_path: Path) -> None:
    module.validate_wheel(_write_wheel(tmp_path))


def test_validate_wheel_rejects_missing_required_package_file(tmp_path: Path) -> None:
    missing = module.REQUIRED_WHEEL_MEMBERS[0]
    wheel = _write_wheel(tmp_path, omit=missing)

    with pytest.raises(SystemExit) as excinfo:
        module.validate_wheel(wheel)

    assert missing in str(excinfo.value)


def test_validate_wheel_rejects_missing_entry_point(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path, entry_points_text="[console_scripts]\n")

    with pytest.raises(SystemExit) as excinfo:
        module.validate_wheel(wheel)

    assert "pcap2llm = pcap2llm.cli:app" in str(excinfo.value)
