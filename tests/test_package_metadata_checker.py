from __future__ import annotations

import importlib.util
import tarfile
import textwrap
import zipfile
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_package_metadata.py"
spec = importlib.util.spec_from_file_location("check_package_metadata", SCRIPT_PATH)
module = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
spec.loader.exec_module(module)


def _metadata_text() -> str:
    return textwrap.dedent(
        """\
        Metadata-Version: 2.4
        Name: pcap2llm
        Version: 0.1.0
        License-Expression: Apache-2.0
        Author-email: Frank März <github@rollhofen.de>
        Description-Content-Type: text/markdown
        Project-URL: Homepage, https://github.com/FrnkMrz/pcap2llm
        Project-URL: Repository, https://github.com/FrnkMrz/pcap2llm
        Project-URL: Issues, https://github.com/FrnkMrz/pcap2llm/issues
        """
    )


def _write_wheel(path: Path, metadata_text: str) -> Path:
    wheel = path / "pcap2llm-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("pcap2llm-0.1.0.dist-info/METADATA", metadata_text)
    return wheel


def _write_sdist(path: Path, metadata_text: str) -> Path:
    sdist = path / "pcap2llm-0.1.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as tf:
        pkg_info = metadata_text.encode("utf-8")
        info = tarfile.TarInfo("pcap2llm-0.1.0/PKG-INFO")
        info.size = len(pkg_info)
        tf.addfile(info, fileobj=__import__("io").BytesIO(pkg_info))
    return sdist


def test_validate_metadata_accepts_wheel_and_sdist(tmp_path: Path) -> None:
    wheel = _write_wheel(tmp_path, _metadata_text())
    sdist = _write_sdist(tmp_path, _metadata_text())

    module.validate_metadata(wheel)
    module.validate_metadata(sdist)


def test_validate_metadata_rejects_missing_project_url(tmp_path: Path) -> None:
    bad = _metadata_text().replace("Project-URL: Issues, https://github.com/FrnkMrz/pcap2llm/issues\n", "")
    wheel = _write_wheel(tmp_path, bad)

    with pytest.raises(SystemExit, match="include Issues"):
        module.validate_metadata(wheel)


def test_validate_metadata_rejects_forbidden_author_hint(tmp_path: Path) -> None:
    bad = _metadata_text().replace("Frank März <github@rollhofen.de>", "Codex <bot@example.com>")
    wheel = _write_wheel(tmp_path, bad)

    with pytest.raises(SystemExit, match="Codex"):
        module.validate_metadata(wheel)
