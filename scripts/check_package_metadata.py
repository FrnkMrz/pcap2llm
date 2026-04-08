from __future__ import annotations

import email
import sys
import zipfile
from pathlib import Path


EXPECTED_LICENSE = "Apache-2.0"
EXPECTED_AUTHOR_HINT = "Frank"
FORBIDDEN_AUTHOR_HINT = "Codex"


def _read_metadata_text(path: Path) -> str:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as zf:
            metadata_name = next(name for name in zf.namelist() if name.endswith(".dist-info/METADATA"))
            return zf.read(metadata_name).decode("utf-8")
    if path.suffix.endswith("gz"):
        raise SystemExit("sdist metadata validation is handled via PKG-INFO extracted in the build tree or wheel metadata.")
    return path.read_text(encoding="utf-8")


def validate_metadata(path: Path) -> None:
    message = email.message_from_string(_read_metadata_text(path))
    license_expression = message.get("License-Expression")
    author_email = message.get("Author-email", "")
    project_urls = message.get_all("Project-URL", [])

    errors: list[str] = []
    if license_expression != EXPECTED_LICENSE:
        errors.append(f"expected License-Expression {EXPECTED_LICENSE!r}, got {license_expression!r}")
    if EXPECTED_AUTHOR_HINT not in author_email:
        errors.append(f"expected author metadata to contain {EXPECTED_AUTHOR_HINT!r}, got {author_email!r}")
    if FORBIDDEN_AUTHOR_HINT in author_email:
        errors.append("author metadata still contains forbidden machine-generated name 'Codex'")
    if not any("Repository" in url for url in project_urls):
        errors.append("expected Project-URL metadata to include Repository")
    if errors:
        raise SystemExit("metadata validation failed:\n- " + "\n- ".join(errors))


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        raise SystemExit("usage: python scripts/check_package_metadata.py <wheel-metadata-path-or-wheel>")
    for raw in argv[1:]:
        validate_metadata(Path(raw))
        print(f"validated {raw}")


if __name__ == "__main__":
    main(sys.argv)
