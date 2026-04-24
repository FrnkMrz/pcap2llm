from __future__ import annotations

import json
from pathlib import Path

from pcap2llm.web.models import SecurityProfile
from pcap2llm.web.profiles import ProfileStore


def test_profile_store_create_and_load(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    profile = store.create("Test Profile", "A test profile")

    assert profile.name == "Test Profile"
    assert profile.description == "A test profile"
    assert profile.status == "active"
    assert profile.id is not None

    loaded = store.load(profile.id)
    assert loaded.name == "Test Profile"
    assert loaded.description == "A test profile"


def test_profile_store_save_and_update(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    profile = store.create("Original Name", "Original desc")

    profile.name = "Updated Name"
    profile.description = "Updated desc"
    profile.auth_mfa = True
    store.save(profile)

    loaded = store.load(profile.id)
    assert loaded.name == "Updated Name"
    assert loaded.description == "Updated desc"
    assert loaded.auth_mfa is True


def test_profile_store_list_all(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    p1 = store.create("Zebra Profile", "Last alphabetically")
    p2 = store.create("Alpha Profile", "First alphabetically")
    p3 = store.create("Beta Profile", "Middle alphabetically")

    all_profiles = store.list_all()
    assert len(all_profiles) == 3
    names = [p.name for p in all_profiles]
    assert names == ["Alpha Profile", "Beta Profile", "Zebra Profile"]


def test_profile_store_delete(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    profile = store.create("To Delete", "Will be deleted")

    all_before = store.list_all()
    assert len(all_before) == 1

    deleted = store.delete(profile.id)
    assert deleted is True

    all_after = store.list_all()
    assert len(all_after) == 0


def test_profile_store_exists_by_name(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path)
    p1 = store.create("Unique Name", "desc")

    assert store.exists_by_name("Unique Name") is True
    assert store.exists_by_name("Different Name") is False
    assert store.exists_by_name("Unique Name", exclude_id=p1.id) is False


def test_profile_to_dict_and_from_dict() -> None:
    profile = SecurityProfile(
        id="test-id",
        name="Test",
        description="Test profile",
        status="active",
        owner="Admin",
        auth_mfa=True,
        session_timeout_minutes=60,
    )

    data = profile.to_dict()
    assert data["name"] == "Test"
    assert data["auth_mfa"] is True
    assert data["session_timeout_minutes"] == 60

    restored = SecurityProfile.from_dict(data)
    assert restored.name == profile.name
    assert restored.auth_mfa == profile.auth_mfa
