from __future__ import annotations

from pathlib import Path

from pcap2llm.web.jobs import JobStore
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
