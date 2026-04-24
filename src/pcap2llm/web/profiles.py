from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from .models import SecurityProfile, now_utc_iso


class ProfileStore:
    """Manages persistence of Security Profiles."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.profiles_dir = workdir / "profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)

    def create(self, name: str, description: str) -> SecurityProfile:
        """Create a new security profile."""
        profile_id = str(uuid4())
        profile = SecurityProfile(
            id=profile_id,
            name=name,
            description=description,
            created_at=now_utc_iso(),
            updated_at=now_utc_iso(),
        )
        self.save(profile)
        return profile

    def load(self, profile_id: str) -> SecurityProfile:
        """Load a profile by ID."""
        path = self._profile_path(profile_id)
        payload = json.loads(path.read_text(encoding="utf-8"))
        return SecurityProfile.from_dict(payload)

    def save(self, profile: SecurityProfile) -> None:
        """Save a profile to disk."""
        profile.updated_at = now_utc_iso()
        path = self._profile_path(profile.id)
        path.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")

    def delete(self, profile_id: str) -> bool:
        """Delete a profile. Returns True if successful."""
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

    def _profile_path(self, profile_id: str) -> Path:
        return self.profiles_dir / f"{profile_id}.json"

    def get_stats(self) -> dict[str, int]:
        """Get profile statistics."""
        profiles = self.list_all()
        active_count = sum(1 for p in profiles if p.status == "active")
        return {
            "total_profiles": len(profiles),
            "active_profiles": active_count,
            "inactive_profiles": len(profiles) - active_count,
        }
