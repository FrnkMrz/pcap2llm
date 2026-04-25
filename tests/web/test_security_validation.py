from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from pcap2llm.web.app import create_app
from pcap2llm.web.config import WebSettings
from pcap2llm.web.jobs import JobStore


def _client(tmp_path: Path, *, support_files_root: Path | None = None) -> TestClient:
    return TestClient(
        create_app(
            WebSettings(
                host="127.0.0.1",
                port=8765,
                workdir=tmp_path / "web_runs",
                max_upload_mb=10,
                command_timeout_seconds=30,
                support_files_root=support_files_root,
                default_privacy_profile="share",
            )
        )
    )


def _upload(client: TestClient) -> str:
    response = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return response.headers["location"].split("/")[-1]


def test_delete_job_rejects_path_traversal_identifier(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/jobs/..%2F..%2Ffoo/delete",
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    assert (tmp_path / "web_runs").exists()


def test_delete_profile_rejects_path_traversal_identifier(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.post(
        "/profiles/..%2F..%2Ffoo/delete",
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_analyze_rejects_dash_prefixed_display_filter(tmp_path: Path) -> None:
    client = _client(tmp_path)
    job_id = _upload(client)

    response = client.post(
        f"/jobs/{job_id}/analyze",
        data={"profile": "lte-core", "privacy_profile": "share", "display_filter": "--help"},
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_analyze_rejects_support_file_outside_workspace(tmp_path: Path) -> None:
    client = _client(tmp_path)
    job_id = _upload(client)

    response = client.post(
        f"/jobs/{job_id}/analyze",
        data={"profile": "lte-core", "privacy_profile": "share", "hosts_file": "/etc/passwd"},
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_analyze_allows_configured_support_files_root(tmp_path: Path) -> None:
    support_root = tmp_path / "support-files"
    support_root.mkdir()
    hosts = support_root / "hosts"
    hosts.write_text("10.0.0.1 mme\n", encoding="utf-8")
    client = _client(tmp_path, support_files_root=support_root)
    job_id = _upload(client)
    captured: dict[str, object] = {}

    def fake_analyze(capture_path, options, out_dir, logs_dir):
        captured["hosts_file"] = options.hosts_file
        return SimpleNamespace(ok=True, stderr="", stdout="", returncode=0)

    client.app.state.runner.analyze = fake_analyze

    response = client.post(
        f"/jobs/{job_id}/analyze",
        data={"profile": "lte-core", "privacy_profile": "share", "hosts_file": str(hosts)},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert captured["hosts_file"] == str(hosts.resolve())


def test_view_text_file_escapes_route_values(tmp_path: Path) -> None:
    client = _client(tmp_path)
    job_id = _upload(client)
    store = JobStore(tmp_path / "web_runs")
    (store.logs_dir(job_id) / "<script>alert(1)<script>.md").write_text("# ok", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}/view/logs/%3Cscript%3Ealert%281%29%3Cscript%3E.md")
    assert response.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;script&gt;.md" in response.text


def test_inline_svg_is_not_rendered_in_job_page(tmp_path: Path) -> None:
    client = _client(tmp_path)
    job_id = _upload(client)
    store = JobStore(tmp_path / "web_runs")
    (store.artifacts_dir(job_id) / "flow.svg").write_text('<svg onload="alert(1)"></svg>', encoding="utf-8")

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert '<svg onload="alert(1)">' not in response.text
    assert f'<img src="/jobs/{job_id}/files/artifacts/flow.svg"' in response.text


def test_destructive_post_without_origin_is_forbidden(tmp_path: Path) -> None:
    client = _client(tmp_path)
    job_id = _upload(client)

    response = client.post(f"/jobs/{job_id}/delete", follow_redirects=False)
    assert response.status_code == 403


def test_sensitive_sidecar_download_requires_confirmation(tmp_path: Path) -> None:
    client = _client(tmp_path)
    job_id = _upload(client)
    store = JobStore(tmp_path / "web_runs")
    (store.artifacts_dir(job_id) / "pseudonym_mapping.json").write_text("{}", encoding="utf-8")

    blocked = client.get(f"/jobs/{job_id}/files/artifacts/pseudonym_mapping.json")
    allowed = client.get(f"/jobs/{job_id}/files/artifacts/pseudonym_mapping.json?confirm=1")

    assert blocked.status_code == 403
    assert allowed.status_code == 200


def test_bulk_delete_reports_invalid_ids(tmp_path: Path) -> None:
    client = _client(tmp_path)
    job_id = _upload(client)

    response = client.post(
        "/jobs/bulk-delete",
        data={"job_id": [job_id, "not-a-uuid"]},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/?deleted=1&failed=1"
