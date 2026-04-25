from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from pcap2llm.config import build_privacy_modes
from pcap2llm.privacy_profiles import list_privacy_profiles

from .models import SecurityProfile, now_utc_iso
from .security import ensure_within, validate_id


class ProfileStore:
    """Manages persistence of local editable privacy profiles."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.profiles_dir = self._resolve_profiles_dir(workdir)
        self.legacy_profiles_dir = self._resolve_legacy_profiles_dir(workdir)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_profiles()

    def create(self, name: str, description: str, modes: dict[str, str] | None = None) -> SecurityProfile:
        """Create a new local privacy profile."""
        profile_id = str(uuid4())
        profile = SecurityProfile(
            id=profile_id,
            name=name,
            description=description,
            modes=build_privacy_modes({}, modes or {}),
            created_at=now_utc_iso(),
            updated_at=now_utc_iso(),
        )
        self.save(profile)
        return profile

    def load(self, profile_id: str) -> SecurityProfile:
        """Load a profile by ID."""
        validate_id(profile_id)
        path = self._profile_path(profile_id)
        payload = json.loads(path.read_text(encoding="utf-8"))
        return SecurityProfile.from_dict(payload)

    def save(self, profile: SecurityProfile) -> None:
        """Save a profile to disk."""
        validate_id(profile.id)
        profile.updated_at = now_utc_iso()
        profile.modes = build_privacy_modes({}, profile.modes)
        path = self._profile_path(profile.id)
        path.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")

    def delete(self, profile_id: str) -> bool:
        """Delete a profile. Returns True if successful."""
        validate_id(profile_id)
        path = self._profile_path(profile_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_all(self) -> list[SecurityProfile]:
        """List all profiles sorted by name."""
        profiles: list[SecurityProfile] = []
        for profile_path in sorted(self.profiles_dir.iterdir()):
            if profile_path.is_file() and profile_path.suffix == ".json":
                try:
                    payload = json.loads(profile_path.read_text(encoding="utf-8"))
                    profiles.append(SecurityProfile.from_dict(payload))
                except Exception:
                    # Skip malformed profiles
                    continue
        return sorted(profiles, key=lambda p: p.name)

    def exists_by_name(self, name: str, exclude_id: str | None = None) -> bool:
        """Check if a profile with this name already exists."""
        for profile in self.list_all():
            if profile.name == name and profile.id != exclude_id:
                return True
        return False

    def profile_path(self, profile_id: str) -> Path:
        return self._profile_path(profile_id)

    def _profile_path(self, profile_id: str) -> Path:
        validate_id(profile_id)
        return ensure_within(self.profiles_dir, self.profiles_dir / f"{profile_id}.json")

    def get_stats(self) -> dict[str, int]:
        """Get privacy profile statistics for the dashboard."""
        profiles = self.list_all()
        return {
            "total_profiles": len(profiles),
            "local_profiles": len(profiles),
            "built_in_profiles": len(list_privacy_profiles()),
        }

    @staticmethod
    def _resolve_profiles_dir(workdir: Path) -> Path:
        if workdir.name == "web_runs":
            return workdir.parent / "profiles"
        return workdir / "profiles"

    @staticmethod
    def _resolve_legacy_profiles_dir(workdir: Path) -> Path | None:
        if workdir.name != "web_runs":
            return None
        legacy_dir = workdir / "profiles"
        target_dir = workdir.parent / "profiles"
        if legacy_dir == target_dir:
            return None
        return legacy_dir

    def _migrate_legacy_profiles(self) -> None:
        if self.legacy_profiles_dir is None or not self.legacy_profiles_dir.exists():
            return
        for legacy_path in sorted(self.legacy_profiles_dir.glob("*.json")):
            target_path = self.profiles_dir / legacy_path.name
            if target_path.exists():
                continue
            target_path.write_text(legacy_path.read_text(encoding="utf-8"), encoding="utf-8")
