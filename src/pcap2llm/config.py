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


def build_privacy_modes(profile_defaults: dict[str, str], overrides: dict[str, str | None]) -> dict[str, str]:
    modes: dict[str, str] = {}
    for data_class in DATA_CLASSES:
        candidate = overrides.get(data_class, profile_defaults.get(data_class, ProtectionMode.KEEP.value))
        modes[data_class] = normalize_mode(candidate)
    return modes


def sample_config_text() -> str:
    sample = {
        "profile": "lte-core",
        "display_filter": None,
        "hosts_file": "examples/wireshark_hosts.sample",
        "mapping_file": "examples/mapping.sample.yaml",
        "two_pass": False,
        "tshark_extra_args": [],
        "privacy_modes": {
            "ip": "keep",
            "hostname": "keep",
            "subscriber_id": "pseudonymize",
            "msisdn": "pseudonymize",
            "imsi": "pseudonymize",
            "imei": "mask",
            "email": "mask",
            "distinguished_name": "pseudonymize",
            "token": "remove",
            "uri": "mask",
            "apn_dnn": "keep",
            "diameter_identity": "pseudonymize",
            "payload_text": "mask",
        },
    }
    return yaml.safe_dump(sample, sort_keys=False)
