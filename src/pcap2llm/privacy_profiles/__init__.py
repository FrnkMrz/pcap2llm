from __future__ import annotations
from importlib.resources import files
from pathlib import Path

import yaml

from pcap2llm.models import PrivacyProfileDefinition

_PACKAGE = "pcap2llm.privacy_profiles"
_BUILTIN = {"internal", "share", "lab", "prod-safe", "llm-telecom-safe", "telecom-context"}


def load_privacy_profile(name: str) -> PrivacyProfileDefinition:
    """Load a built-in or file-path privacy profile by name."""
    try:
        ref = files(_PACKAGE).joinpath(f"{name}.yaml")
        data = yaml.safe_load(ref.read_text(encoding="utf-8")) or {}
    except (FileNotFoundError, TypeError, AttributeError):
        path = Path(name)
        if not path.exists():
            raise FileNotFoundError(
                f"Privacy profile '{name}' not found. "
                f"Built-in profiles: {', '.join(sorted(_BUILTIN))}"
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    data.setdefault("name", name)
    return PrivacyProfileDefinition.model_validate(data)


def list_privacy_profiles() -> list[str]:
    """Return the names of all built-in privacy profiles."""
    return sorted(_BUILTIN)
