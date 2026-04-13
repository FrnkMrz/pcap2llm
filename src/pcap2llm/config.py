from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pcap2llm.models import DATA_CLASSES, ProtectionMode


DEFAULT_CONFIG_PATH = Path("pcap2llm.config.yaml")


def normalize_mode(value: str | None) -> str:
    if value is None:
        return ProtectionMode.KEEP.value
    normalized = value.strip().lower().replace("-", "_")
    aliases = {
        "off": ProtectionMode.KEEP.value,
        "keep": ProtectionMode.KEEP.value,
        "redact": ProtectionMode.MASK.value,
        "mask": ProtectionMode.MASK.value,
        "pseudonymize": ProtectionMode.PSEUDONYMIZE.value,
        "encrypt": ProtectionMode.ENCRYPT.value,
        "remove": ProtectionMode.REMOVE.value,
    }
    if normalized not in aliases:
        valid = ", ".join(mode.value for mode in ProtectionMode)
        raise ValueError(f"Unsupported protection mode '{value}'. Valid modes: {valid}, off")
    return aliases[normalized]


def load_yaml_or_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected an object at the root of {path}")
    return data


def load_config_file(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    return load_yaml_or_json(path)


def build_privacy_modes(base: dict[str, str], overrides: dict[str, str | None]) -> dict[str, str]:
    """Merge *base* modes with *overrides*, normalising every value."""
    modes: dict[str, str] = {}
    for data_class in DATA_CLASSES:
        candidate = overrides.get(data_class, base.get(data_class, ProtectionMode.KEEP.value))
        modes[data_class] = normalize_mode(candidate)
    return modes


def sample_config_text() -> str:
    lines = [
        "# pcap2llm configuration",
        "#",
        "# Analysis profile: which protocols to extract and how.",
        "# Built-in: lte-core | 5g-core | 2g3g-ss7-geran",
        "profile: lte-core",
        "",
        "# Privacy profile: how sensitive data classes are treated.",
        "# Built-in: internal | share | lab | prod-safe | llm-telecom-safe",
        "privacy_profile: share",
        "",
        "display_filter:",
        "hosts_file: examples/wireshark_hosts.sample",
        "mapping_file: examples/mapping.sample.yaml",
        "# subnets_file: .local/Subnets",
        "# ss7pcs_file: .local/ss7pcs",
        "two_pass: false",
        "tshark_extra_args: []",
        "",
        "# Optional per-run privacy overrides (supplement the privacy profile above).",
        "# Uncomment only the classes you want to override:",
        "# privacy_modes:",
        "#   imsi: remove",
        "#   token: remove",
    ]
    return "\n".join(lines) + "\n"
