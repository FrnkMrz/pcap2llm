from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from pcap2llm.web.app import create_app
from pcap2llm.web.config import WebSettings
from pcap2llm.web.profiles import ProfileStore


def _build_client(tmp_path: Path) -> TestClient:
    settings = WebSettings(workdir=tmp_path / "web_runs")
    return TestClient(create_app(settings))


def test_profiles_page_loads(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    response = client.get("/profiles")
    assert response.status_code == 200
    assert "Privacy Profiles" in response.text
    assert "Built-in Privacy Profiles" in response.text
    assert "llm-telecom-safe" in response.text
    assert "Built-in Profiles" in response.text
    assert "Save Local Override" in response.text
    assert "Edit" in response.text
    assert 'id="newProfileButton"' in response.text
    assert 'data-select-kind="built-in"' in response.text
    assert 'onclick="event.stopPropagation();' not in response.text
    assert "Export JSON" not in response.text
    assert "Bulk Delete" not in response.text


def test_profiles_page_explains_empty_local_profiles(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    response = client.get("/profiles")
    assert response.status_code == 200
    assert "No local profiles yet." in response.text


def test_api_list_profiles_empty(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    response = client.get("/api/profiles")
    assert response.status_code == 200
    assert response.json() == []


def test_create_profile_form_submission(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    response = client.post(
        "/profiles",
        data={"name": "Standard Profile", "description": "Standard privacy profile"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    profiles = client.get("/api/profiles").json()
    assert len(profiles) == 1
    assert profiles[0]["name"] == "Standard Profile"
    assert profiles[0]["modes"]["ip"] == "keep"


def test_create_profile_duplicate_name_fails(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    client.post("/profiles", data={"name": "Duplicate", "description": "First"}, follow_redirects=False)

    response = client.post(
        "/profiles",
        data={"name": "Duplicate", "description": "Second"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "already exists" in response.text


def test_update_profile_via_form_updates_modes(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    create_resp = client.post(
        "/profiles",
        data={"name": "Original", "description": "Original description"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    update_resp = client.post(
        f"/profiles/{profile_id}",
        data={
            "name": "Updated",
            "description": "Updated description",
            "mode_ip": "mask",
            "mode_imsi": "remove",
            "mode_email": "pseudonymize",
        },
        follow_redirects=False,
    )
    assert update_resp.status_code == 303

    store = ProfileStore(tmp_path / "web_runs")
    profile = store.load(profile_id)
    assert profile.name == "Updated"
    assert profile.description == "Updated description"
    assert profile.modes["ip"] == "mask"
    assert profile.modes["imsi"] == "remove"
    assert profile.modes["email"] == "pseudonymize"


def test_profiles_editor_shows_imei_tac_mode(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    create_resp = client.post(
        "/profiles",
        data={"name": "IMEI Profile", "description": "IMEI handling"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    response = client.get(f"/profiles?id={profile_id}")
    assert response.status_code == 200
    assert "keep_tac_mask_serial" in response.text


def test_update_profile_rejects_invalid_mode(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    create_resp = client.post(
        "/profiles",
        data={"name": "Original", "description": "Original description"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    response = client.post(
        f"/profiles/{profile_id}",
        data={"name": "Original", "description": "Original description", "mode_ip": "wildcard"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert "Unsupported protection mode" in response.text


def test_delete_profile_via_form(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    create_resp = client.post(
        "/profiles",
        data={"name": "To Delete", "description": "Will delete"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    delete_resp = client.post(
        f"/profiles/{profile_id}/delete",
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert delete_resp.status_code == 303
    assert client.get("/api/profiles").json() == []


def test_duplicate_profile_route_creates_copy(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    create_resp = client.post(
        "/profiles",
        data={"name": "Base Profile", "description": "Original profile"},
        follow_redirects=False,
    )
    profile_id = create_resp.headers["location"].split("id=")[1]

    client.post(
        f"/profiles/{profile_id}",
        data={
            "name": "Base Profile",
            "description": "Original profile",
            "mode_ip": "mask",
            "mode_email": "remove",
        },
        follow_redirects=False,
    )

    duplicate_resp = client.post(f"/profiles/{profile_id}/duplicate", follow_redirects=False)
    assert duplicate_resp.status_code == 303

    profiles = client.get("/api/profiles").json()
    assert len(profiles) == 2
    copied = next(profile for profile in profiles if profile["name"].startswith("Base Profile Copy"))
    assert copied["modes"]["ip"] == "mask"
    assert copied["modes"]["email"] == "remove"


def test_duplicate_builtin_privacy_profile_creates_local_copy(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    duplicate_resp = client.post("/profiles/privacy/share/duplicate", follow_redirects=False)
    assert duplicate_resp.status_code == 303

    profiles = client.get("/api/profiles").json()
    assert len(profiles) == 1
    assert profiles[0]["name"].startswith("share Copy")
    assert "Safe for sharing" in profiles[0]["description"]
    assert profiles[0]["modes"]["subscriber_id"] == "pseudonymize"
    assert profiles[0]["modes"]["token"] == "remove"


def test_builtin_override_save_and_reset(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    save_resp = client.post(
        "/profiles/privacy/share/override",
        data={
            "name": "share",
            "description": "override",
            "mode_subscriber_id": "encrypt",
        },
        follow_redirects=False,
    )
    assert save_resp.status_code == 303
    assert save_resp.headers["location"] == "/profiles?builtin=share"

    page = client.get("/profiles?builtin=share")
    assert page.status_code == 200
    assert "Local override active" in page.text
    assert "Reset to Built-in" in page.text

    reset_resp = client.post("/profiles/privacy/share/reset", follow_redirects=False)
    assert reset_resp.status_code == 303
    assert reset_resp.headers["location"] == "/profiles?builtin=share"

    page_after = client.get("/profiles?builtin=share")
    assert page_after.status_code == 200
    assert "Read-only base, save creates local override" in page_after.text


def test_builtin_profile_full_editor_flow_override_duplicate_reset(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    save_resp = client.post(
        "/profiles/privacy/share/override",
        data={
            "name": "share tuned",
            "description": "customized built-in override",
            "mode_subscriber_id": "encrypt",
            "mode_token": "mask",
        },
        follow_redirects=False,
    )
    assert save_resp.status_code == 303
    assert save_resp.headers["location"] == "/profiles?builtin=share"

    share_page = client.get("/profiles?builtin=share")
    assert share_page.status_code == 200
    assert "share tuned" in share_page.text
    assert "customized built-in override" in share_page.text
    assert "Local override active" in share_page.text

    duplicate_resp = client.post(
        "/profiles/privacy/share/duplicate",
        data={
            "name": "share tuned",
            "description": "customized built-in override",
            "mode_subscriber_id": "encrypt",
            "mode_token": "mask",
        },
        follow_redirects=False,
    )
    assert duplicate_resp.status_code == 303

    profiles = client.get("/api/profiles").json()
    assert len(profiles) == 1
    duplicated = profiles[0]
    assert duplicated["name"].startswith("share tuned Copy")
    assert duplicated["description"] == "customized built-in override"
    assert duplicated["modes"]["subscriber_id"] == "encrypt"
    assert duplicated["modes"]["token"] == "mask"

    duplicate_page = client.get(f"/profiles?id={duplicated['id']}")
    assert duplicate_page.status_code == 200
    assert duplicated["name"] in duplicate_page.text
    assert "Save Profile" in duplicate_page.text

    reset_resp = client.post("/profiles/privacy/share/reset", follow_redirects=False)
    assert reset_resp.status_code == 303
    assert reset_resp.headers["location"] == "/profiles?builtin=share"

    reset_page = client.get("/profiles?builtin=share")
    assert reset_page.status_code == 200
    assert "Read-only base, save creates local override" in reset_page.text
    assert 'action="/profiles/privacy/share/override"' in reset_page.text
    assert 'id="resetButton" type="button" class="btn-secondary" hidden' in reset_page.text


def test_export_profiles_json_and_csv(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    client.post(
        "/profiles",
        data={"name": "Exportable", "description": "Export me"},
        follow_redirects=False,
    )

    json_resp = client.get("/profiles/export?fmt=json")
    assert json_resp.status_code == 200
    assert "attachment; filename=\"privacy_profiles.json\"" in json_resp.headers.get("content-disposition", "")
    assert json_resp.json()[0]["name"] == "Exportable"

    csv_resp = client.get("/profiles/export?fmt=csv")
    assert csv_resp.status_code == 200
    assert "attachment; filename=\"privacy_profiles.csv\"" in csv_resp.headers.get("content-disposition", "")
    assert "name,description,ip,hostname" in csv_resp.text
    assert "Exportable" in csv_resp.text


def test_bulk_delete_profiles_route(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    first = client.post("/profiles", data={"name": "A", "description": "First"}, follow_redirects=False).headers["location"].split("id=")[1]
    second = client.post("/profiles", data={"name": "B", "description": "Second"}, follow_redirects=False).headers["location"].split("id=")[1]

    response = client.post(
        "/profiles/actions/bulk-delete",
        data={"profile_id": [first, second]},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.get("/api/profiles").json() == []
