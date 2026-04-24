from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from pcap2llm.web.jobs import JobStore
from pcap2llm.web.models import JobRecord
from pcap2llm.web.security import WebValidationError, ensure_within


def test_job_store_creates_layout_and_writes_job_json(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "web_runs")
    record = store.create("trace.pcapng")

    assert store.job_json_path(record.job_id).exists()
    assert store.input_dir(record.job_id).exists()
    assert store.discovery_dir(record.job_id).exists()
    assert store.artifacts_dir(record.job_id).exists()
    assert store.logs_dir(record.job_id).exists()


def test_status_update_and_sorted_artifacts(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "web_runs")
    record = store.create("trace.pcapng")
    artifact_dir = store.artifacts_dir(record.job_id)

    for name in [
        "run_01_detail.json",
        "run_01_summary.json",
        "run_01_summary.md",
        "run_01_flow.svg",
        "run_01_other.txt",
    ]:
        (artifact_dir / name).write_text("x", encoding="utf-8")

    updated = store.set_status(record.job_id, "done")
    assert updated.status == "done"

    ordered = store.sorted_artifacts(updated)
    assert ordered[:4] == [
        "run_01_summary.md",
        "run_01_summary.json",
        "run_01_detail.json",
        "run_01_flow.svg",
    ]


def test_ensure_within_blocks_outside_path(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")

    try:
        ensure_within(base, outside)
        assert False, "expected WebValidationError"
    except WebValidationError:
        pass


def test_cleanup_old_jobs_removes_old_records(tmp_path: Path) -> None:
    """Test that cleanup_old_jobs removes jobs older than max_age_days."""
    store = JobStore(tmp_path / "web_runs")

    # Create two jobs
    rec_old = store.create("old_trace.pcapng")
    rec_new = store.create("new_trace.pcapng")

    # Manually set old job's updated_at to 10 days ago
    rec_old_loaded = store.load(rec_old.job_id)
    old_time = datetime.now(timezone.utc) - timedelta(days=10)
    rec_old_loaded.updated_at = old_time.isoformat()
    store.save(rec_old_loaded)

    # Cleanup jobs older than 7 days
    deleted = store.cleanup_old_jobs(max_age_days=7)

    assert deleted == 1
    assert not store.job_root(rec_old.job_id).exists()
    assert store.job_root(rec_new.job_id).exists()


def test_cleanup_old_jobs_preserves_recent_records(tmp_path: Path) -> None:
    """Test that cleanup_old_jobs preserves recent jobs."""
    store = JobStore(tmp_path / "web_runs")

    # Create jobs
    rec1 = store.create("trace_1.pcapng")
    rec2 = store.create("trace_2.pcapng")

    # Both are recent (just created), so cleanup should delete neither
    deleted = store.cleanup_old_jobs(max_age_days=7)

    assert deleted == 0
    assert store.job_root(rec1.job_id).exists()
    assert store.job_root(rec2.job_id).exists()


def test_cleanup_old_jobs_respects_disable(tmp_path: Path) -> None:
    """Test that cleanup with max_age_days=0 or negative is disabled."""
    store = JobStore(tmp_path / "web_runs")

    # Create an old job
    rec_old = store.create("old_trace.pcapng")
    rec_old_loaded = store.load(rec_old.job_id)
    old_time = datetime.now(timezone.utc) - timedelta(days=100)
    rec_old_loaded.updated_at = old_time.isoformat()
    store.save(rec_old_loaded)

    # Cleanup with max_age_days=0 should do nothing
    deleted_zero = store.cleanup_old_jobs(max_age_days=0)
    assert deleted_zero == 0
    assert store.job_root(rec_old.job_id).exists()

    # Cleanup with max_age_days=-5 should do nothing
    deleted_neg = store.cleanup_old_jobs(max_age_days=-5)
    assert deleted_neg == 0
    assert store.job_root(rec_old.job_id).exists()
