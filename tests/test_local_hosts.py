"""Tests for automatic local helper file discovery.

Covers the _resolve_hosts_file() helper in cli.py:
- hosts file found at default .local path
- hosts file absent at default path
- explicit CLI argument overrides default path
- config file entry overrides default path
- CLI argument wins over config file
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


from pcap2llm.cli import (
    _LOCAL_HOSTS_DEFAULT,
    _LOCAL_SS7PCS_DEFAULT,
    _LOCAL_SUBNETS_DEFAULT,
    _resolve_hosts_file,
    _resolve_ss7pcs_file,
    _resolve_subnets_file,
)

_MODULE = "pcap2llm.cli"


# ---------------------------------------------------------------------------
# _resolve_hosts_file
# ---------------------------------------------------------------------------

def test_cli_arg_wins_when_file_exists(tmp_path: Path) -> None:
    """Explicit --hosts-file always wins, even when default path exists."""
    explicit = tmp_path / "explicit_hosts.txt"
    explicit.write_text("10.0.0.1 node-a\n")
    fake_default = tmp_path / "default_hosts.txt"
    fake_default.write_text("10.0.0.2 node-b\n")
    with patch(f"{_MODULE}._LOCAL_HOSTS_DEFAULT", fake_default):
        result = _resolve_hosts_file(explicit, {})
    assert result == explicit


def test_config_file_wins_over_default(tmp_path: Path) -> None:
    """Config-file hosts_file entry wins over auto-discovery."""
    config_path = str(tmp_path / "config_hosts.txt")
    fake_default = tmp_path / "nonexistent_default.txt"
    with patch(f"{_MODULE}._LOCAL_HOSTS_DEFAULT", fake_default):
        result = _resolve_hosts_file(None, {"hosts_file": config_path})
    assert result == Path(config_path)


def test_default_path_used_when_present(tmp_path: Path) -> None:
    """Auto-discovers default path when the file exists there."""
    fake_default = tmp_path / "hosts"
    fake_default.write_text("10.0.0.1 mme\n")
    with patch(f"{_MODULE}._LOCAL_HOSTS_DEFAULT", fake_default):
        result = _resolve_hosts_file(None, {})
    assert result == fake_default


def test_returns_none_when_nothing_available(tmp_path: Path) -> None:
    """Returns None and does not fail when no hosts file is found anywhere."""
    fake_default = tmp_path / "does_not_exist.txt"
    # file is not created — .exists() returns False
    with patch(f"{_MODULE}._LOCAL_HOSTS_DEFAULT", fake_default):
        result = _resolve_hosts_file(None, {})
    assert result is None


def test_cli_arg_none_and_no_config_no_default(tmp_path: Path) -> None:
    """No CLI arg, no config entry, default path absent — graceful None."""
    fake_default = tmp_path / "does_not_exist.txt"
    with patch(f"{_MODULE}._LOCAL_HOSTS_DEFAULT", fake_default):
        result = _resolve_hosts_file(None, {})
    assert result is None


def test_cli_arg_overrides_config_and_default(tmp_path: Path) -> None:
    """CLI arg wins over both config and auto-discovery."""
    explicit = tmp_path / "my_hosts.txt"
    explicit.write_text("10.0.0.2 node-b\n")
    fake_default = tmp_path / "default_hosts.txt"
    fake_default.write_text("10.0.0.3 node-c\n")
    config = {"hosts_file": str(tmp_path / "config_hosts.txt")}
    with patch(f"{_MODULE}._LOCAL_HOSTS_DEFAULT", fake_default):
        result = _resolve_hosts_file(explicit, config)
    assert result == explicit


# ---------------------------------------------------------------------------
# Default constant sanity check
# ---------------------------------------------------------------------------

def test_default_constant_path() -> None:
    """The default path constant is exactly .local/hosts."""
    assert _LOCAL_HOSTS_DEFAULT == Path(".local/hosts")


def test_subnets_cli_arg_wins_when_file_exists(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit_subnets.txt"
    explicit.write_text("10.0.0.0/24 CORE_A\n", encoding="utf-8")
    fake_default = tmp_path / "default_subnets.txt"
    fake_default.write_text("10.0.1.0/24 CORE_B\n", encoding="utf-8")
    with patch(f"{_MODULE}._LOCAL_SUBNETS_DEFAULT", fake_default):
        result = _resolve_subnets_file(explicit, {})
    assert result == explicit


def test_subnets_config_file_wins_over_default(tmp_path: Path) -> None:
    config_path = str(tmp_path / "config_subnets.txt")
    fake_default = tmp_path / "nonexistent_default.txt"
    with patch(f"{_MODULE}._LOCAL_SUBNETS_DEFAULT", fake_default):
        result = _resolve_subnets_file(None, {"subnets_file": config_path})
    assert result == Path(config_path)


def test_subnets_default_path_used_when_present(tmp_path: Path) -> None:
    fake_default = tmp_path / "Subnets"
    fake_default.write_text("10.0.0.0/24 CORE_A\n", encoding="utf-8")
    with patch(f"{_MODULE}._LOCAL_SUBNETS_DEFAULT", fake_default):
        result = _resolve_subnets_file(None, {})
    assert result == fake_default


def test_subnets_returns_none_when_nothing_available(tmp_path: Path) -> None:
    fake_default = tmp_path / "does_not_exist.txt"
    with patch(f"{_MODULE}._LOCAL_SUBNETS_DEFAULT", fake_default):
        result = _resolve_subnets_file(None, {})
    assert result is None


def test_subnets_default_constant_path() -> None:
    assert _LOCAL_SUBNETS_DEFAULT == Path(".local/Subnets")


def test_ss7pcs_cli_arg_wins_when_file_exists(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit_ss7pcs.txt"
    explicit.write_text("0-5093 VZB\n", encoding="utf-8")
    fake_default = tmp_path / "default_ss7pcs.txt"
    fake_default.write_text("0-5094 VZC\n", encoding="utf-8")
    with patch(f"{_MODULE}._LOCAL_SS7PCS_DEFAULT", fake_default):
        result = _resolve_ss7pcs_file(explicit, {})
    assert result == explicit


def test_ss7pcs_config_file_wins_over_default(tmp_path: Path) -> None:
    config_path = str(tmp_path / "config_ss7pcs.txt")
    fake_default = tmp_path / "nonexistent_default.txt"
    with patch(f"{_MODULE}._LOCAL_SS7PCS_DEFAULT", fake_default):
        result = _resolve_ss7pcs_file(None, {"ss7pcs_file": config_path})
    assert result == Path(config_path)


def test_ss7pcs_default_path_used_when_present(tmp_path: Path) -> None:
    fake_default = tmp_path / "ss7pcs"
    fake_default.write_text("0-5093 VZB\n", encoding="utf-8")
    with patch(f"{_MODULE}._LOCAL_SS7PCS_DEFAULT", fake_default):
        result = _resolve_ss7pcs_file(None, {})
    assert result == fake_default


def test_ss7pcs_returns_none_when_nothing_available(tmp_path: Path) -> None:
    fake_default = tmp_path / "does_not_exist.txt"
    with patch(f"{_MODULE}._LOCAL_SS7PCS_DEFAULT", fake_default):
        result = _resolve_ss7pcs_file(None, {})
    assert result is None


def test_ss7pcs_default_constant_path() -> None:
    assert _LOCAL_SS7PCS_DEFAULT == Path(".local/ss7pcs")
