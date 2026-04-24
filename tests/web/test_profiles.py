from __future__ import annotations

import json
from pathlib import Path

from pcap2llm.web.models import SecurityProfile
from pcap2llm.web.profiles import ProfileStore


def test_profile_store_create_and_load(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    profile = store.create("Test Profile", "A test profile", {"ip": "mask", "email": "remove"})

    assert profile.name == "Test Profile"
    assert profile.description == "A test profile"
    assert profile.modes["ip"] == "mask"
    assert profile.modes["email"] == "remove"
    assert profile.id

    loaded = store.load(profile.id)
    assert loaded.name == "Test Profile"
    assert loaded.modes["ip"] == "mask"


def test_profile_store_save_and_update_modes(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    profile = store.create("Original Name", "Original desc")

    profile.name = "Updated Name"
    profile.description = "Updated desc"
    profile.modes["imsi"] = "remove"
    store.save(profile)

    loaded = store.load(profile.id)
    assert loaded.name == "Updated Name"
    assert loaded.description == "Updated desc"
    assert loaded.modes["imsi"] == "remove"


def test_profile_store_list_all(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    store.create("Zebra Profile", "Last alphabetically")
    store.create("Alpha Profile", "First alphabetically")
    store.create("Beta Profile", "Middle alphabetically")

    all_profiles = store.list_all()
    assert len(all_profiles) == 3
    assert [p.name for p in all_profiles] == ["Alpha Profile", "Beta Profile", "Zebra Profile"]


def test_profile_store_delete(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    profile = store.create("To Delete", "Will be deleted")

    assert len(store.list_all()) == 1
    assert store.delete(profile.id) is True
    assert store.list_all() == []


def test_profile_store_exists_by_name(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    profile = store.create("Unique Name", "desc")

    assert store.exists_by_name("Unique Name") is True
    assert store.exists_by_name("Different Name") is False
    assert store.exists_by_name("Unique Name", exclude_id=profile.id) is False


def test_profile_to_dict_and_from_dict() -> None:
    profile = SecurityProfile(
        id="test-id",
        name="Test",
        description="Test profile",
        modes={"ip": "mask", "email": "remove"},
    )

    data = profile.to_dict()
    assert data["name"] == "Test"
    assert data["modes"]["ip"] == "mask"
    assert data["modes"]["email"] == "remove"

    restored = SecurityProfile.from_dict(data)
    assert restored.name == profile.name
    assert restored.modes == data["modes"]


def test_profile_store_uses_local_profiles_dir_for_web_runs(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "web_runs")
    profile = store.create("Local Profile", "stored next to web_runs")

    assert store.profiles_dir == tmp_path / "profiles"
    assert (tmp_path / "profiles" / f"{profile.id}.json").exists()


def test_profile_store_migrates_legacy_web_run_profiles(tmp_path: Path) -> None:
    legacy_dir = tmp_path / "web_runs" / "profiles"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    legacy_path = legacy_dir / "legacy-id.json"
    legacy_profile = SecurityProfile(id="legacy-id", name="Legacy", description="legacy profile")
    legacy_path.write_text(json.dumps(legacy_profile.to_dict()), encoding="utf-8")

    store = ProfileStore(tmp_path / "web_runs")

    assert (tmp_path / "profiles" / "legacy-id.json").exists()
    loaded = store.load("legacy-id")
    assert loaded.name == "Legacy"


def test_profile_store_stats_include_builtin_profiles(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    store.create("One", "first")

    stats = store.get_stats()
    assert stats["total_profiles"] == 1
    assert stats["local_profiles"] == 1
    assert stats["built_in_profiles"] >= 5
