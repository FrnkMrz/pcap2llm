from __future__ import annotations

import io
from pathlib import Path

from fastapi.testclient import TestClient

from pcap2llm.web.app import create_app
from pcap2llm.web.config import WebSettings
from pcap2llm.web.profiles import ProfileStore


def test_profiles_page_loads(tmp_path: Path) -> None:
    """Test that /profiles page loads successfully."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    response = client.get("/profiles")
    assert response.status_code == 200
    assert "Security Profiles" in response.text
    assert "New Profile" in response.text


def test_api_list_profiles_empty(tmp_path: Path) -> None:
    """Test /api/profiles returns empty list initially."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    response = client.get("/api/profiles")
    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_create_profile_form_submission(tmp_path: Path) -> None:
    """Test creating a profile via form."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    response = client.post(
        "/profiles",
        data={
            "name": "Standard Profile",
            "description": "Standard security profile",
            "owner": "Security Team",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    # Verify profile was created
    profiles_response = client.get("/api/profiles")
    profiles = profiles_response.json()
    assert len(profiles) == 1
    assert profiles[0]["name"] == "Standard Profile"


def test_create_profile_duplicate_name_fails(tmp_path: Path) -> None:
    """Test that creating profiles with duplicate names fails."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    # Create first profile
    client.post(
        "/profiles",
        data={"name": "Duplicate", "description": "First"},
        follow_redirects=True,
    )

    # Try to create profile with same name
    response = client.post(
        "/profiles",
        data={"name": "Duplicate", "description": "Second"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "already exists" in response.text


def test_update_profile_via_form(tmp_path: Path) -> None:
    """Test updating a profile."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    # Create profile
    create_resp = client.post(
        "/profiles",
        data={
            "name": "Original",
            "description": "Original description",
        },
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    # Update profile
    update_resp = client.post(
        f"/profiles/{profile_id}",
        data={
            "name": "Updated",
            "description": "Updated description",
            "status": "inactive",
            "auth_mfa": "on",
            "session_timeout_minutes": "60",
        },
        follow_redirects=False,
    )
    assert update_resp.status_code == 303

    # Verify changes
    store = ProfileStore(tmp_path / "web_runs")
    profile = store.load(profile_id)
    assert profile.name == "Updated"
    assert profile.description == "Updated description"
    assert profile.status == "inactive"
    assert profile.auth_mfa is True


def test_delete_profile_via_form(tmp_path: Path) -> None:
    """Test deleting a profile."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    # Create profile
    create_resp = client.post(
        "/profiles",
        data={"name": "To Delete", "description": "Will delete"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    # Verify it exists
    profiles = client.get("/api/profiles").json()
    assert len(profiles) == 1

    # Delete it
    delete_resp = client.post(
        f"/profiles/{profile_id}/delete",
        follow_redirects=False,
    )
    assert delete_resp.status_code == 303

    # Verify it's gone
    profiles_after = client.get("/api/profiles").json()
    assert len(profiles_after) == 0


def test_profile_settings_persist(tmp_path: Path) -> None:
    """Test that all security settings persist correctly."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    # Create profile with custom settings
    create_resp = client.post(
        "/profiles",
        data={
            "name": "Custom Settings",
            "description": "With custom settings",
        },
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    # Update with specific settings
    client.post(
        f"/profiles/{profile_id}",
        data={
            "name": "Custom Settings",
            "description": "With custom settings",
            "status": "active",
            "auth_password": "on",
            "auth_mfa": "on",
            "auth_certificate": "on",
            "auth_access_level": "admin",
            "session_timeout_minutes": "120",
            "network_access": "vpn",
            "logging_level": "detailed",
        },
        follow_redirects=False,
    )

    # Load and verify
    store = ProfileStore(tmp_path / "web_runs")
    profile = store.load(profile_id)
    assert profile.auth_password is True
    assert profile.auth_mfa is True
    assert profile.auth_certificate is True
    assert profile.auth_access_level == "admin"
    assert profile.session_timeout_minutes == 120
    assert profile.network_access == "vpn"
    assert profile.logging_level == "detailed"


def test_profile_name_validation_rejects_invalid_chars(tmp_path: Path) -> None:
    """Test that invalid characters in profile names are rejected."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    client = TestClient(create_app(settings))

    invalid_names = [
        "Profile@Name",
        "Profile#Name",
        "Profile/Name",
        "Profile$Name",
        "Profile&Name",
    ]

    for invalid_name in invalid_names:
        response = client.post(
            "/profiles",
            data={
                "name": invalid_name,
                "description": "Test",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert "only letters, numbers, spaces, dots, underscores, and hyphens" in response.text


def test_profile_string_length_limits(tmp_path: Path) -> None:
    """Test that string field length limits are enforced."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    client = TestClient(create_app(settings))

    # Description too long (>1000 chars)
    response = client.post(
        "/profiles",
        data={
            "name": "Valid Name",
            "description": "x" * 1001,  # 1001 chars, exceeds limit
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "exceeds maximum length" in response.text


def test_profile_enum_validation(tmp_path: Path) -> None:
    """Test that enum fields are validated."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    # Create profile first
    create_resp = client.post(
        "/profiles",
        data={"name": "Test", "description": "Test"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    # Try updating with invalid access level
    response = client.post(
        f"/profiles/{profile_id}",
        data={
            "name": "Test",
            "description": "Test",
            "auth_access_level": "invalid-level",  # Invalid enum value
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "Invalid access level" in response.text


def test_profile_session_timeout_limits(tmp_path: Path) -> None:
    """Test that session timeout has reasonable limits."""
    settings = WebSettings(workdir=tmp_path / "web_runs")
    app = create_app(settings)
    client = TestClient(app)

    # Create profile
    create_resp = client.post(
        "/profiles",
        data={"name": "Timeout Test", "description": "Test"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    # Try timeout too low (< 1 minute)
    response = client.post(
        f"/profiles/{profile_id}",
        data={
            "name": "Timeout Test",
            "description": "Test",
            "session_timeout_minutes": "0",  # Invalid: < 1
        },
        follow_redirects=False,
    )
    assert response.status_code == 400

    # Try timeout too high (> 1440 minutes / 24 hours)
    response = client.post(
        f"/profiles/{profile_id}",
        data={
            "name": "Timeout Test",
            "description": "Test",
            "session_timeout_minutes": "1441",  # Invalid: > 1440
        },
        follow_redirects=False,
    )
    assert response.status_code == 400
