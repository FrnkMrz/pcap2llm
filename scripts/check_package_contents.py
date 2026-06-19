from __future__ import annotations

import sys
import zipfile
from pathlib import Path


REQUIRED_WHEEL_MEMBERS = (
    "pcap2llm/profiles/lte-core.yaml",
    "pcap2llm/privacy_profiles/share.yaml",
    "pcap2llm/web/templates/base.html",
    "pcap2llm/web/templates/job.html",
    "pcap2llm/web/static/styles.css",
    "pcap2llm/web/static/job.js",
    "pcap2llm/web/static/pcap2llm-logo_48.png",
    "pcap2llm/web/static/pcap2llm-logo_256.png",
)

REQUIRED_ENTRY_POINTS = (
    "pcap2llm = pcap2llm.cli:app",
    "pcap2llm-web = pcap2llm.web.app:main",
)


def _expand_paths(raw_paths: list[str]) -> list[Path]:
    paths: list[Path] = []
    for raw in raw_paths:
        matches = sorted(Path().glob(raw)) if any(char in raw for char in "*?[") else []
        if matches:
            paths.extend(matches)
        else:
            paths.append(Path(raw))
    return paths


def validate_wheel(path: Path) -> None:
    if path.suffix != ".whl":
        raise SystemExit(f"expected a wheel file, got {path}")

    with zipfile.ZipFile(path) as zf:
        members = set(zf.namelist())
        missing = [member for member in REQUIRED_WHEEL_MEMBERS if member not in members]

        entry_points_name = next(
            (name for name in members if name.endswith(".dist-info/entry_points.txt")),
            None,
        )
        if entry_points_name is None:
            missing.append("*.dist-info/entry_points.txt")
            entry_points_text = ""
        else:
            entry_points_text = zf.read(entry_points_name).decode("utf-8")

    errors = [f"missing wheel member: {member}" for member in missing]
    for entry_point in REQUIRED_ENTRY_POINTS:
        if entry_point not in entry_points_text:
            errors.append(f"missing console script entry point: {entry_point}")

    if errors:
        raise SystemExit("package content validation failed:\n- " + "\n- ".join(errors))


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        raise SystemExit("usage: python scripts/check_package_contents.py <wheel> [<wheel> ...]")
    for path in _expand_paths(argv[1:]):
        validate_wheel(path)
        print(f"validated package contents for {path}")


if __name__ == "__main__":
    main(sys.argv)
