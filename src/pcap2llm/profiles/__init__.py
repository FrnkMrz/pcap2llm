from __future__ import annotations

import warnings
from importlib.resources import files

import yaml

from pcap2llm.models import ProfileDefinition


def _normalize_profile_name(profile_name: str) -> str:
    if profile_name.endswith(".yaml"):
        return profile_name[: -len(".yaml")]
    return profile_name


def load_profile(profile_name: str) -> ProfileDefinition:
    normalized_name = _normalize_profile_name(profile_name)
    resource = files("pcap2llm.profiles").joinpath(f"{normalized_name}.yaml")
    if not resource.is_file():
        raise FileNotFoundError(f"Unknown profile '{profile_name}'")
    data = yaml.safe_load(resource.read_text(encoding="utf-8")) or {}
    data.setdefault("name", normalized_name)
    if "default_privacy_modes" in data:
        warnings.warn(
            f"Analysis profile '{normalized_name}' contains 'default_privacy_modes' which is "
            "deprecated. Move privacy configuration to a dedicated privacy profile "
            "(e.g. --privacy-profile share) and remove 'default_privacy_modes' from "
            f"the analysis profile YAML.",
            DeprecationWarning,
            stacklevel=2,
        )
    return ProfileDefinition.model_validate(data)
