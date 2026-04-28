from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from pcap2llm.web.app import create_app
from pcap2llm.web.config import WebSettings, load_settings
from pcap2llm.web.jobs import JobStore
from pcap2llm.web.profiles import ProfileStore


def _build_client(tmp_path: Path, *, max_upload_mb: int = 1) -> TestClient:
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


def test_index_page_uses_data_confirm_attribute_for_bulk_delete(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    client.post(
        "/jobs",
        files={"capture": ("trace.pcapng", io.BytesIO(b"pcap"), "application/octet-stream")},
        follow_redirects=False,
    )

    response = client.get("/")
    assert response.status_code == 200
    assert 'data-confirm-message="Delete selected jobs?"' in response.text
    assert 'onclick="return confirm(' not in response.text


def test_dashboard_route_returns_200(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "Dashboard" in response.text
    assert "with LLMs using an appropriate privacy profile." in response.text


def test_chrome_devtools_probe_returns_no_content(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    response = client.get("/.well-known/appspecific/com.chrome.devtools.json")
    assert response.status_code == 204
    assert response.text == ""


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
    assert 'data-confirm-message="Delete this job and all generated files?"' in response.text
    assert 'onsubmit="return confirm(' not in response.text


def test_bulk_delete_jobs_route(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    upload_a = client.post(
        "/jobs",
        files={"capture": ("trace_a.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    upload_b = client.post(
        "/jobs",
        files={"capture": ("trace_b.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )

    job_a = upload_a.headers["location"].split("/")[-1]
    job_b = upload_b.headers["location"].split("/")[-1]

    response = client.post(
        "/jobs/bulk-delete",
        data={"job_id": [job_a, job_b]},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    store = JobStore(tmp_path / "web_runs")
    assert not store.job_root(job_a).exists()
    assert not store.job_root(job_b).exists()


def test_download_blocks_nested_filename(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    response = client.get(f"/jobs/{job_id}/files/../secrets.txt")
    assert response.status_code in (400, 404)


def test_auto_discover_uses_recommendation_fallback(tmp_path: Path) -> None:
    client = _build_client(tmp_path)

    def fake_discover(capture_path, out_dir, logs_dir, **kwargs):
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


def test_markdown_artifact_can_be_viewed_inline(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    artifact = store.artifacts_dir(job_id) / "sample_summary.md"
    artifact.write_text("# Summary\nhello", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}/view/artifacts/{artifact.name}")
    assert response.status_code == 200
    assert "sample_summary.md" in response.text
    assert "Summary" in response.text
    assert "Zurueck zum Job" in response.text


def test_job_page_links_markdown_artifact_to_inline_view(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    (store.artifacts_dir(job_id) / "sample_summary.md").write_text("# Summary\nhello", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert f'/jobs/{job_id}/view/artifacts/sample_summary.md' in response.text
    assert f'/jobs/{job_id}/files/artifacts/sample_summary.md' in response.text


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
            "verbatim_protocols_add": "pfcp, ngap",
            "verbatim_protocols_remove": "diameter",
            "keep_raw_avps": "true",
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
    assert 'name="verbatim_protocols_add" value="pfcp, ngap"' in page.text
    assert 'name="verbatim_protocols_remove" value="diameter"' in page.text
    assert '<option value="true" selected>Force enabled</option>' in page.text
    assert 'value="200"' in page.text
    assert 'option value="lte-s11"' in page.text
    assert 'value="lte-s11"' in page.text and 'selected' in page.text
    assert 'type="radio" name="privacy_profile" value="lab" checked' in page.text
    assert "--verbatim-protocol pfcp" in page.text
    assert "--verbatim-protocol ngap" in page.text
    assert "--no-verbatim-protocol diameter" in page.text
    assert "--keep-raw-avps" in page.text


def test_analyze_passes_verbatim_protocol_overrides_to_runner(tmp_path: Path) -> None:
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
            "verbatim_protocols_add": "pfcp, ngap, pfcp",
            "verbatim_protocols_remove": "diameter",
            "keep_raw_avps": "false",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    options = captured["options"]
    assert options.verbatim_protocols_add == ["pfcp", "ngap"]
    assert options.verbatim_protocols_remove == ["diameter"]
    assert options.keep_raw_avps is False


def test_job_page_renders_privacy_profiles_as_visible_options(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert 'name="privacy_profile"' in page.text
    assert 'type="radio" name="privacy_profile" value="share" checked' in page.text
    assert 'data-tooltip="Safe for sharing with external parties or cross-team review.' in page.text
    assert '<select name="privacy_profile"' not in page.text


def test_job_page_includes_local_privacy_profiles(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    store = ProfileStore(tmp_path / "web_runs")
    local_profile = store.create("Custom Privacy", "Editable local profile", {"ip": "mask", "email": "remove"})

    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert f'value="local:{local_profile.id}"' in page.text
    assert "Custom Privacy" in page.text
    assert "mask 1" in page.text


def test_job_page_prefills_local_support_file_defaults(tmp_path: Path) -> None:
    local_root = tmp_path / ".local"
    local_root.mkdir()
    (local_root / "hosts").write_text("10.0.0.1 mme\n", encoding="utf-8")
    (local_root / "Subnets").write_text("10.0.0.0/24 CORE\n", encoding="utf-8")
    (local_root / "ss7pcs").write_text("0-5093 VZB\n", encoding="utf-8")
    (local_root / "network_element_mapping.csv").write_text(
        "type,value,network_element_type\nsubnet,10.0.0.0/24,AMF\n",
        encoding="utf-8",
    )

    settings = WebSettings(
        host="127.0.0.1",
        port=8765,
        workdir=local_root / "web_runs",
        max_upload_mb=250,
        command_timeout_seconds=30,
        default_privacy_profile="share",
    )
    client = TestClient(create_app(settings))

    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert "Aktive lokale Defaults" in page.text
    assert f'Hosts: <code>{local_root / "hosts"}</code>' in page.text
    assert f'Subnets: <code>{local_root / "Subnets"}</code>' in page.text
    assert f'SS7 PCS: <code>{local_root / "ss7pcs"}</code>' in page.text
    assert f'Net element CSV: <code>{local_root / "network_element_mapping.csv"}</code>' in page.text
    assert "More Options" in page.text


def test_job_page_shows_discovery_name_resolution_usage(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    (store.discovery_dir(job_id) / "discover_trace.json").write_text(
        json.dumps(
            {
                "name_resolution": {
                    "hosts_file_used": True,
                    "mapping_file_used": False,
                    "subnets_file_used": True,
                    "ss7pcs_file_used": False,
                    "resolved_peer_count": 7,
                }
            }
        ),
        encoding="utf-8",
    )

    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert "Name resolution used" in page.text
    assert "Hosts file: yes" in page.text
    assert "Subnets file: yes" in page.text
    assert "Resolved peers: 7" in page.text


def test_analyze_uses_local_support_file_defaults_when_form_is_blank(tmp_path: Path) -> None:
    local_root = tmp_path / ".local"
    local_root.mkdir()
    (local_root / "hosts").write_text("10.0.0.1 mme\n", encoding="utf-8")
    (local_root / "ss7pcs").write_text("0-5093 VZB\n", encoding="utf-8")
    (local_root / "network_element_mapping.csv").write_text(
        "type,value,network_element_type\nsubnet,10.0.0.0/24,AMF\n",
        encoding="utf-8",
    )

    settings = WebSettings(
        host="127.0.0.1",
        port=8765,
        workdir=local_root / "web_runs",
        max_upload_mb=250,
        command_timeout_seconds=30,
        default_privacy_profile="share",
    )
    client = TestClient(create_app(settings))

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
        follow_redirects=False,
    )
    assert response.status_code == 303

    options = captured["options"]
    assert options.hosts_file == str(local_root / "hosts")
    assert options.ss7pcs_file == str(local_root / "ss7pcs")
    assert options.network_element_mapping_file == str(local_root / "network_element_mapping.csv")


def test_job_page_shows_detected_network_element_types(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    (store.artifacts_dir(job_id) / "sample_detail.json").write_text(
        json.dumps(
            {
                "messages": [
                    {
                        "src": {"labels": {"network_element_type": "AMF", "network_element_source": "protocol"}},
                        "dst": {"labels": {"network_element_type": "gNodeB", "network_element_source": "protocol"}},
                    },
                    {
                        "src": {"labels": {"network_element_type": "AMF", "network_element_source": "subnet_mapping"}},
                        "dst": {"labels": {"network_element_type": "unknown", "network_element_source": "unknown"}},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    page = client.get(f"/jobs/{job_id}")
    assert page.status_code == 200
    assert "Detected network element types" in page.text
    assert "AMF: 2" in page.text
    assert "gNodeB: 1" in page.text
    assert "protocol 2" in page.text
    assert "subnet_mapping 1" in page.text


def test_admin_cleanup_endpoint_deletes_old_jobs(tmp_path: Path) -> None:
    settings = WebSettings(
        host="127.0.0.1",
        port=8765,
        workdir=tmp_path / "web_runs",
        max_upload_mb=250,
        command_timeout_seconds=30,
        default_privacy_profile="share",
        cleanup_enabled=True,
        cleanup_max_age_days=7,
    )
    client = TestClient(create_app(settings))

    # Create an old job
    store = JobStore(tmp_path / "web_runs")
    rec_old = store.create("old_trace.pcapng")
    rec_old_loaded = store.load(rec_old.job_id)
    old_time = datetime.now(timezone.utc) - timedelta(days=10)
    rec_old_loaded.updated_at = old_time.isoformat()
    store.save(rec_old_loaded)

    # Call admin cleanup endpoint
    response = client.post("/admin/cleanup", headers={"Origin": "http://testserver"})
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["deleted_jobs"] == 1
    assert payload["max_age_days"] == 7
    assert not store.job_root(rec_old.job_id).exists()


def test_admin_cleanup_endpoint_respects_max_age_override(tmp_path: Path) -> None:
    settings = WebSettings(
        host="127.0.0.1",
        port=8765,
        workdir=tmp_path / "web_runs",
        max_upload_mb=250,
        command_timeout_seconds=30,
        default_privacy_profile="share",
        cleanup_enabled=True,
        cleanup_max_age_days=7,
    )
    client = TestClient(create_app(settings))

    # Create a job that's 3 days old
    store = JobStore(tmp_path / "web_runs")
    rec_3days = store.create("trace_3days.pcapng")
    rec_3days_loaded = store.load(rec_3days.job_id)
    old_time = datetime.now(timezone.utc) - timedelta(days=3)
    rec_3days_loaded.updated_at = old_time.isoformat()
    store.save(rec_3days_loaded)

    # Cleanup with strict max_age_days=1 should delete it
    response = client.post("/admin/cleanup", json={"max_age_days": 1}, headers={"Origin": "http://testserver"})
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["deleted_jobs"] == 1
    assert payload["max_age_days"] == 1
    assert not store.job_root(rec_3days.job_id).exists()


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
    assert record.last_error == "TShark was not found. Install Wireshark/TShark, add it to PATH, or configure a valid TShark path."
    assert record.last_error_code == "tshark_missing"


def test_load_settings_falls_back_to_generic_tshark_env(monkeypatch) -> None:
    monkeypatch.delenv("PCAP2LLM_WEB_TSHARK_PATH", raising=False)
    monkeypatch.setenv("PCAP2LLM_TSHARK_PATH", "/opt/tools/tshark")

    settings = load_settings()

    assert settings.tshark_path == "/opt/tools/tshark"


def test_load_settings_reads_local_settings_file_and_env_overrides(monkeypatch, tmp_path: Path) -> None:
    settings_file = tmp_path / "web_settings.json"
    settings_file.write_text(
        json.dumps(
            {
                "host": "127.0.0.9",
                "port": 9988,
                "max_upload_mb": 5,
                "command_timeout_seconds": 42,
                "tshark_path": "/file/tshark",
                "default_privacy_profile": "lab",
                "cleanup_enabled": False,
                "cleanup_max_age_days": 21,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PCAP2LLM_WEB_SETTINGS_FILE", str(settings_file))
    monkeypatch.setenv("PCAP2LLM_WEB_PORT", "8766")
    monkeypatch.delenv("PCAP2LLM_WEB_TSHARK_PATH", raising=False)
    monkeypatch.delenv("PCAP2LLM_TSHARK_PATH", raising=False)

    settings = load_settings()

    assert settings.host == "127.0.0.9"
    assert settings.port == 8766
    assert settings.max_upload_mb == 5
    assert settings.command_timeout_seconds == 42
    assert settings.tshark_path == "/file/tshark"
    assert settings.default_privacy_profile == "lab"
    assert settings.cleanup_enabled is False
    assert settings.cleanup_max_age_days == 21


def test_job_page_shows_grouped_profiles_and_tshark_status(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    response = client.get(f"/jobs/{job_id}")

    assert response.status_code == 200
    assert "<optgroup label=\"Transport\">" in response.text
    assert "transport-udp" in response.text
    assert "transport-sctp" in response.text
    assert "transport-tcp" in response.text
    assert "transport-core" in response.text
    assert "core-name-resolution" in response.text
    assert "Transport first for TCP/UDP/SCTP" in response.text
    assert "TShark runtime" in response.text


def test_zip_download_contains_job_files(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    store.load(job_id)
    (store.artifacts_dir(job_id) / "sample_summary.json").write_text("{}", encoding="utf-8")
    (store.discovery_dir(job_id) / "discover_trace.json").write_text("{}", encoding="utf-8")
    (store.logs_dir(job_id) / "analyze_stderr.log").write_text("err", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}/files.zip")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/zip")

    with zipfile.ZipFile(io.BytesIO(response.content), "r") as zf:
        names = set(zf.namelist())

    assert "artifacts/sample_summary.json" in names
    assert "discovery/discover_trace.json" in names
    assert "logs/analyze_stderr.log" in names


def test_job_page_keeps_discovery_logs_visible_after_analyze(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    logs_dir = store.logs_dir(job_id)
    (logs_dir / "discovery_stdout.log").write_text("discover ok", encoding="utf-8")
    (logs_dir / "discovery_stderr.log").write_text("", encoding="utf-8")
    (logs_dir / "analyze_stdout.log").write_text("analyze ok", encoding="utf-8")
    (logs_dir / "analyze_stderr.log").write_text("", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert "Discovery" in response.text
    assert "discover ok" in response.text
    assert "Analyze" in response.text
    assert "analyze ok" in response.text
    assert f"/jobs/{job_id}/files/logs/discovery_stdout.log" in response.text
    assert f"/jobs/{job_id}/files/logs/analyze_stdout.log" in response.text
    assert "<summary>" in response.text
    assert ">Logs<" in response.text
    assert '<details class="panel logs-panel" id="logs" data-logbook>' in response.text


def test_job_page_renders_flow_preview_as_img(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    (store.artifacts_dir(job_id) / "sample_flow.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="200"><title>Flow</title><rect width="100%" height="100%" fill="#fff" /></svg>',
        encoding="utf-8",
    )

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert 'class="flow-preview-shell"' in response.text
    assert 'class="flow-preview-canvas"' in response.text
    assert f'<img src="/jobs/{job_id}/files/artifacts/sample_flow.svg"' in response.text
    assert '<svg xmlns="http://www.w3.org/2000/svg"' not in response.text


def test_job_page_explains_advanced_analysis_toggles(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert "Export all packets to detail.json" in response.text
    assert "Ignores the packet limit" in response.text
    assert "Fail if the detail export would be cut off" in response.text
    assert "The run stops instead of silently exporting only the first N packets" in response.text
    assert "Better TShark reassembly for fragmented traffic" in response.text
    assert "Runs TShark in two-pass mode" in response.text


def test_job_page_hides_log_files_from_downloads_list(tmp_path: Path) -> None:
    client = _build_client(tmp_path)
    upload = client.post(
        "/jobs",
        files={"capture": ("trace.pcap", io.BytesIO(b"abc"), "application/octet-stream")},
        follow_redirects=False,
    )
    job_id = upload.headers["location"].split("/")[-1]

    store = JobStore(tmp_path / "web_runs")
    (store.artifacts_dir(job_id) / "sample_summary.json").write_text("{}", encoding="utf-8")
    (store.discovery_dir(job_id) / "discover_trace.json").write_text("{}", encoding="utf-8")
    (store.logs_dir(job_id) / "analyze_stdout.log").write_text("analyze ok", encoding="utf-8")
    (store.logs_dir(job_id) / "analyze_stderr.log").write_text("", encoding="utf-8")
    (store.logs_dir(job_id) / "analyze_command.json").write_text("{}", encoding="utf-8")

    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200
    assert f"/jobs/{job_id}/files/artifacts/sample_summary.json" in response.text
    assert f"/jobs/{job_id}/files/discovery/discover_trace.json" in response.text
    assert f"/jobs/{job_id}/files/logs/analyze_stdout.log" in response.text
    assert f"/jobs/{job_id}/files/logs/analyze_command.json" in response.text
    assert "/files/artifacts/analyze_stdout.log" not in response.text
    assert "/files/discovery/analyze_stdout.log" not in response.text


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

    response = client.post(
        f"/jobs/{job_id}/delete",
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert not store.job_root(job_id).exists()


def test_delete_all_outputs_keeps_job_and_capture(tmp_path: Path) -> None:
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
    (store.logs_dir(job_id) / "analyze_stdout.log").write_text("ok", encoding="utf-8")
    record.status = "done"
    record.recommended_profiles = [{"profile": "lte-core"}]
    record.suspected_domains = ["lte"]
    record.artifacts = ["sample_summary.json"]
    store.save(record)

    response = client.post(
        f"/jobs/{job_id}/outputs/delete",
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/jobs/{job_id}"

    updated = store.load(job_id)
    assert updated.status == "uploaded"
    assert updated.recommended_profiles == []
    assert updated.suspected_domains == []
    assert updated.artifacts == []
    assert store.capture_path(updated).exists()
    assert list(store.artifacts_dir(job_id).iterdir()) == []
    assert list(store.discovery_dir(job_id).iterdir()) == []
    assert list(store.logs_dir(job_id).iterdir()) == []
