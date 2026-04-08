from __future__ import annotations

import email
import re
import sys
import tarfile
import zipfile
from pathlib import Path


EXPECTED_LICENSE = "Apache-2.0"
EXPECTED_AUTHOR_HINT = "Frank"
FORBIDDEN_AUTHOR_HINT = "Codex"
EXPECTED_NAME = "pcap2llm"
REQUIRED_PROJECT_URL_LABELS = ("Homepage", "Repository", "Issues")
EXPECTED_DESCRIPTION_CONTENT_TYPE = "text/markdown"


def _read_metadata_text(path: Path) -> str:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as zf:
            metadata_name = next(name for name in zf.namelist() if name.endswith(".dist-info/METADATA"))
            return zf.read(metadata_name).decode("utf-8")
    if path.suffixes[-2:] == [".tar", ".gz"]:
        with tarfile.open(path, "r:gz") as tf:
            pkg_info = next(member for member in tf.getmembers() if member.name.endswith("/PKG-INFO"))
            extracted = tf.extractfile(pkg_info)
            if extracted is None:
                raise SystemExit(f"failed to extract PKG-INFO from {path}")
            return extracted.read().decode("utf-8")
    return path.read_text(encoding="utf-8")


def validate_metadata(path: Path) -> None:
    message = email.message_from_string(_read_metadata_text(path))
    license_expression = message.get("License-Expression")
    author_email = message.get("Author-email", "")
    project_urls = message.get_all("Project-URL", [])
    description_content_type = message.get("Description-Content-Type")
    package_name = message.get("Name")
    version = message.get("Version", "")

    errors: list[str] = []
    if license_expression != EXPECTED_LICENSE:
        errors.append(f"expected License-Expression {EXPECTED_LICENSE!r}, got {license_expression!r}")
    if package_name != EXPECTED_NAME:
        errors.append(f"expected package name {EXPECTED_NAME!r}, got {package_name!r}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        errors.append(f"expected semantic version like '0.1.0', got {version!r}")
    if EXPECTED_AUTHOR_HINT not in author_email:
        errors.append(f"expected author metadata to contain {EXPECTED_AUTHOR_HINT!r}, got {author_email!r}")
    if FORBIDDEN_AUTHOR_HINT in author_email:
        errors.append("author metadata still contains forbidden machine-generated name 'Codex'")
    for label in REQUIRED_PROJECT_URL_LABELS:
        if not any(url.startswith(f"{label}, ") for url in project_urls):
            errors.append(f"expected Project-URL metadata to include {label}")
    if description_content_type != EXPECTED_DESCRIPTION_CONTENT_TYPE:
        errors.append(
            f"expected Description-Content-Type {EXPECTED_DESCRIPTION_CONTENT_TYPE!r}, "
            f"got {description_content_type!r}"
        )
    # With modern setuptools + PEP 639, the SPDX license expression is the
    # authoritative source and Apache Trove classifiers are rejected. Keep this
    # explicit so future maintainers do not re-introduce a broken config.
    if any(value == "License :: OSI Approved :: Apache Software License" for value in message.get_all("Classifier", [])):
        errors.append("unexpected Apache Trove classifier present; setuptools with SPDX license expression should omit it")
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
