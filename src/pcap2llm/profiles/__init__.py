from __future__ import annotations

from importlib.resources import files

import yaml

from pcap2llm.models import ProfileDefinition


def load_profile(profile_name: str) -> ProfileDefinition:
    resource = files("pcap2llm.profiles").joinpath(f"{profile_name}.yaml")
    if not resource.is_file():
        raise FileNotFoundError(f"Unknown profile '{profile_name}'")
    data = yaml.safe_load(resource.read_text(encoding="utf-8")) or {}
    data.setdefault("name", profile_name)
    return ProfileDefinition.model_validate(data)
