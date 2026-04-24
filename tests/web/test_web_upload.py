from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from pcap2llm.web.app import create_app
from pcap2llm.web.config import WebSettings
from pcap2llm.web.jobs import JobStore


def _build_client(tmp_path: Path, *, max_upload_mb: int = 250) -> TestClient:
    settings = WebSettings(
        host="127.0.0.1",
        port=8765,
        workdir=tmp_path / "web_runs",
        max_upload_mb=max_upload_mb,
        command_timeout_seconds=30,
        default_privacy_profile="share",
    )
    app = create_app(settings)
    return TestClient(app)


def test_index_route_returns_200(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    response = client.get("/")
    assert response.status_code == 200
    assert "pcap2llm Web GUI" in response.text


def test_upload_accepts_pcapng_and_creates_job(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    response = client.post(
        "/jobs",
        files={"capture": ("trace.pcapng", io.BytesIO(b"pcap"), "application/octet-stream")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/jobs/")

    job_id = location.split("/")[-1]
    store = JobStore(tmp_path / "web_runs")
    record = store.load(job_id)
    assert record.status == "uploaded"
    assert store.capture_path(record).exists()


def test_upload_rejects_txt(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    response = client.post(
        "/jobs",
        files={"capture": ("trace.txt", io.BytesIO(b"x"), "text/plain")},
    )
    assert response.status_code == 400


def test_upload_sanitizes_traversal_filename(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    response = client.post(
        "/jobs",
        files={"capture": ("../../evil.pcapng", io.BytesIO(b"pcap"), "application/octet-stream")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    job_id = response.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    record = store.load(job_id)
    assert record.input_filename == "evil.pcapng"
    assert store.capture_path(record).name == "evil.pcapng"


def test_upload_rejects_size_limit(tmp_path: Path) -> None:
    client = _build_client(tmp_path, max_upload_mb=0)
    response = client.post(
        "/jobs",
        files={"capture": ("trace.pcapng", io.BytesIO(b"x"), "application/octet-stream")},
    )
    assert response.status_code == 413


def test_job_status_json(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    response = client.get(f"/jobs/{job_id}/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["job_id"] == job_id
    assert payload["status"] == "uploaded"


def test_job_page_renders_status(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert "Status" in response.text
    assert "uploaded" in response.text
    assert "data-job-id" in response.text
    assert "data-job-status" in response.text
    assert "/static/job.js" in response.text


def test_download_blocks_nested_filename(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    response = client.get(f"/jobs/{job_id}/files/../secrets.txt")
    assert response.status_code == 400


def test_auto_discover_uses_recommendation_fallback(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    def fake_discover(capture_path, out_dir, logs_dir):
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "candidate_profiles": [],
            "suspected_domains": ["lte"],
        }
        (out_dir / "discover_trace_V_01.json").write_text(json.dumps(payload), encoding="utf-8")
        return SimpleNamespace(ok=True, stderr="", stdout="", returncode=0)

    def fake_recommend(source_path, logs_dir):
        payload = {
            "status": "ok",
            "recommended_profiles": [
                {"profile": "lte-s11", "confidence": "high", "reason": ["gtpv2 detected"]}
            ],
            "suspected_domains": ["lte"],
        }
        return SimpleNamespace(ok=True, stderr="", stdout=json.dumps(payload), returncode=0)

    client.app.state.runner.discover = fake_discover
    client.app.state.runner.recommend_profiles = fake_recommend

    response = client.post(
        "/jobs",
        data={"auto_discover": "true"},
        files={"capture": ("trace.pcapng", io.BytesIO(b"pcap"), "application/octet-stream")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    job_id = response.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    record = store.load(job_id)
    assert record.status == "discovered"
    assert record.recommended_profiles
    assert record.recommended_profiles[0]["profile"] == "lte-s11"


def test_download_artifact_from_job_directory(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    record = store.load(job_id)
    artifact = store.artifacts_dir(record.job_id) / "sample_summary.json"
    artifact.write_text("{}", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}/files/{artifact.name}")
    assert response.status_code == 200


def test_scoped_download_handles_duplicate_filenames(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    shared_name = "same.json"
    (store.artifacts_dir(job_id) / shared_name).write_text('{"kind":"artifact"}', encoding="utf-8")
    (store.discovery_dir(job_id) / shared_name).write_text('{"kind":"discovery"}', encoding="utf-8")

    artifact_resp = client.get(f"/jobs/{job_id}/files/artifacts/{shared_name}")
    discovery_resp = client.get(f"/jobs/{job_id}/files/discovery/{shared_name}")

    assert artifact_resp.status_code == 200
    assert discovery_resp.status_code == 200
    assert artifact_resp.text != discovery_resp.text


def test_analyze_uses_uploaded_support_files(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    captured: dict[str, object] = {}

    def fake_analyze(capture_path, options, out_dir, logs_dir):
        captured["options"] = options
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "sample_summary.json").write_text("{}", encoding="utf-8")
        return SimpleNamespace(ok=True, stderr="", stdout="", returncode=0)

    client.app.state.runner.analyze = fake_analyze

    response = client.post(
        f"/jobs/{job_id}/analyze",
        data={
            "profile": "lte-core",
            "privacy_profile": "share",
            "collapse_repeats": "true",
        },
        files={
            "hosts_file_upload": ("hosts.txt", io.BytesIO(b"10.0.0.1 mme"), "text/plain"),
            "mapping_file_upload": ("mapping.yaml", io.BytesIO(b"aliases: {}"), "text/plain"),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    options = captured["options"]
    assert options.hosts_file is not None
    assert options.mapping_file is not None
    assert "input" in options.hosts_file
    assert "support" in options.hosts_file
    assert "input" in options.mapping_file
    assert "support" in options.mapping_file


def test_job_page_persists_last_analyze_form_values(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    def fake_analyze(capture_path, options, out_dir, logs_dir):
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "sample_summary.json").write_text("{}", encoding="utf-8")
        return SimpleNamespace(ok=True, stderr="", stdout="", returncode=0)

    client.app.state.runner.analyze = fake_analyze

    response = client.post(
        f"/jobs/{job_id}/analyze",
        data={
            "profile": "lte-s11",
            "privacy_profile": "lab",
            "display_filter": "gtpv2",
            "max_packets": "200",
            "collapse_repeats": "true",
            "two_pass": "true",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert 'value="gtpv2"' in page.text
    assert 'value="200"' in page.text
    assert 'value="lte-s11" selected' in page.text
    assert 'value="lab" selected' in page.text


def test_analyze_failure_exposes_error_code(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    def fake_analyze(capture_path, options, out_dir, logs_dir):
        return SimpleNamespace(ok=False, stderr="tshark was not found in PATH", stdout="", returncode=1)

    client.app.state.runner.analyze = fake_analyze

    response = client.post(
        f"/jobs/{job_id}/analyze",
        data={"profile": "lte-core", "privacy_profile": "share", "collapse_repeats": "true"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    store = JobStore(tmp_path / "web_runs")
    record = store.load(job_id)
    assert record.status == "failed"
    assert record.last_error == "TShark was not found in PATH."
    assert record.last_error_code == "tshark_missing"


def test_zip_download_contains_job_files(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    record = store.load(job_id)
    (store.artifacts_dir(job_id) / "sample_summary.json").write_text("{}", encoding="utf-8")
    (store.discovery_dir(job_id) / "discover_trace.json").write_text("{}", encoding="utf-8")
    (store.logs_dir(job_id) / "stderr.log").write_text("err", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}/files.zip")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/zip")

    with zipfile.ZipFile(io.BytesIO(response.content), "r") as zf:
        names = set(zf.namelist())

    assert "artifacts/sample_summary.json" in names
    assert "discovery/discover_trace.json" in names
    assert "logs/stderr.log" in names


def test_delete_job_removes_workspace(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    assert store.job_root(job_id).exists()

    response = client.post(f"/jobs/{job_id}/delete", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert not store.job_root(job_id).exists()
