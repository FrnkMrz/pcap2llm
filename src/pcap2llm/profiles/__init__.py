from __future__ import annotations

import warnings
from importlib.resources import files
from typing import Iterable

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


def list_profile_names() -> list[str]:
    package = files("pcap2llm.profiles")
    names: list[str] = []
    for resource in package.iterdir():
        if resource.name.startswith("_"):
            continue
        if not resource.name.endswith(".yaml"):
            continue
        if resource.name == "__init__.py":
            continue
        names.append(resource.name[: -len(".yaml")])
    return sorted(names)


def load_all_profiles(names: Iterable[str] | None = None) -> list[ProfileDefinition]:
    selected = list(names) if names is not None else list_profile_names()
    return [load_profile(name) for name in selected]
