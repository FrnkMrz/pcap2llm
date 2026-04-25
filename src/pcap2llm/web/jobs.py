from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .models import JobRecord, JobStatus, now_utc_iso
from .security import ensure_within, validate_id


SENSITIVE_SIDECARS = {"pseudonym_mapping.json", "vault.json"}


class JobStore:
    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)

    def create(self, input_filename: str) -> JobRecord:
        job_id = str(uuid4())
        root = self.job_root(job_id)
        (root / "input").mkdir(parents=True, exist_ok=True)
        (root / "input" / "support").mkdir(parents=True, exist_ok=True)
        (root / "discovery").mkdir(parents=True, exist_ok=True)
        (root / "artifacts").mkdir(parents=True, exist_ok=True)
        (root / "logs").mkdir(parents=True, exist_ok=True)

        ts = now_utc_iso()
        record = JobRecord(
            job_id=job_id,
            status="created",
            input_filename=input_filename,
            created_at=ts,
            updated_at=ts,
        )
        self.save(record)
        return record

    def load(self, job_id: str) -> JobRecord:
        validate_id(job_id)
        path = self.job_json_path(job_id)
        payload = json.loads(path.read_text(encoding="utf-8"))
        return JobRecord.from_dict(payload)

    def save(self, record: JobRecord) -> None:
        validate_id(record.job_id)
        path = self.job_json_path(record.job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")

    def list_all(self) -> list[JobRecord]:
        records: list[JobRecord] = []
        for job_dir in self.workdir.iterdir():
            if not job_dir.is_dir():
                continue
            try:
                records.append(self.load(job_dir.name))
            except Exception:
                continue
        records.sort(key=lambda item: item.created_at, reverse=True)
        return records

    def set_status(
        self,
        job_id: str,
        status: JobStatus,
        *,
        last_error: str | None = None,
        last_error_code: str | None = None,
    ) -> JobRecord:
        record = self.load(job_id)
        record.status = status
        record.updated_at = now_utc_iso()
        record.last_error = last_error
        record.last_error_code = last_error_code
        self.save(record)
        return record

    def job_root(self, job_id: str) -> Path:
        validate_id(job_id)
        return ensure_within(self.workdir, self.workdir / job_id)

    def job_json_path(self, job_id: str) -> Path:
        return self.job_root(job_id) / "job.json"

    def input_dir(self, job_id: str) -> Path:
        return self.job_root(job_id) / "input"

    def discovery_dir(self, job_id: str) -> Path:
        return self.job_root(job_id) / "discovery"

    def artifacts_dir(self, job_id: str) -> Path:
        return self.job_root(job_id) / "artifacts"

    def logs_dir(self, job_id: str) -> Path:
        return self.job_root(job_id) / "logs"

    def capture_path(self, record: JobRecord) -> Path:
        return self.input_dir(record.job_id) / record.input_filename

    def support_dir(self, job_id: str) -> Path:
        return self.input_dir(job_id) / "support"

    def resolve_download(self, record: JobRecord, filename: str) -> Path:
        candidates = [
            self.artifacts_dir(record.job_id) / filename,
            self.discovery_dir(record.job_id) / filename,
            self.logs_dir(record.job_id) / filename,
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return ensure_within(self.job_root(record.job_id), candidate)
        raise FileNotFoundError(filename)

    def resolve_download_scoped(self, record: JobRecord, section: str, filename: str) -> Path:
        folder = self._section_folder(record.job_id, section)
        candidate = folder / filename
        if not candidate.exists() or not candidate.is_file():
            raise FileNotFoundError(filename)
        return ensure_within(self.job_root(record.job_id), candidate)

    def collect_job_files_for_zip(self, record: JobRecord) -> list[tuple[str, Path]]:
        groups = [(name, self._section_folder(record.job_id, name)) for name in ("artifacts", "discovery", "logs")]

        entries: list[tuple[str, Path]] = []
        for prefix, folder in groups:
            if not folder.exists():
                continue
            for path in sorted(folder.iterdir()):
                if not path.is_file():
                    continue
                safe_path = ensure_within(self.job_root(record.job_id), path)
                entries.append((f"{prefix}/{path.name}", safe_path))
        return entries

    def list_download_entries(self, record: JobRecord) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        for section in ("artifacts", "discovery"):
            folder = self._section_folder(record.job_id, section)
            if not folder.exists():
                continue
            for path in sorted(folder.iterdir()):
                if not path.is_file():
                    continue
                ensure_within(self.job_root(record.job_id), path)
                entries.append(
                    {
                        "section": section,
                        "name": path.name,
                        "size": self._format_size(path.stat().st_size),
                        "sensitive": "true" if path.name in SENSITIVE_SIDECARS else "false",
                    }
                )
        return entries

    def clear_generated_outputs(self, job_id: str) -> JobRecord:
        record = self.load(job_id)
        for folder in (self.discovery_dir(job_id), self.artifacts_dir(job_id), self.logs_dir(job_id)):
            if folder.exists():
                shutil.rmtree(folder)
            folder.mkdir(parents=True, exist_ok=True)

        record.status = "uploaded"
        record.updated_at = now_utc_iso()
        record.recommended_profiles = []
        record.suspected_domains = []
        record.artifacts = []
        record.last_error = None
        record.last_error_code = None
        self.save(record)
        return record

    def sorted_artifacts(self, record: JobRecord) -> list[str]:
        artifact_dir = self.artifacts_dir(record.job_id)
        if not artifact_dir.exists():
            return []

        priority = [
            "summary.md",
            "summary.json",
            "detail.json",
            "flow.svg",
            "flow.json",
            "pseudonym_mapping.json",
            "vault.json",
        ]

        files = [p.name for p in artifact_dir.iterdir() if p.is_file()]

        def rank(name: str) -> tuple[int, str]:
            for idx, suffix in enumerate(priority):
                if name.endswith(suffix):
                    return (idx, name)
            return (len(priority), name)

        return sorted(files, key=rank)

    def _section_folder(self, job_id: str, section: str) -> Path:
        match section:
            case "artifacts":
                return self.artifacts_dir(job_id)
            case "discovery":
                return self.discovery_dir(job_id)
            case "logs":
                return self.logs_dir(job_id)
            case _:
                raise FileNotFoundError(section)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KiB"
        return f"{size_bytes / (1024 * 1024):.1f} MiB"

    def cleanup_old_jobs(self, max_age_days: int) -> int:
        """Delete job directories older than max_age_days. Returns count of deleted jobs."""
        if max_age_days <= 0:
            return 0

        deleted_count = 0
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=max_age_days)

        for job_dir in self.workdir.iterdir():
            if not job_dir.is_dir():
                continue

            job_json_path = job_dir / "job.json"
            if not job_json_path.exists():
                continue

            try:
                record = self.load(job_dir.name)
                # Parse updated_at ISO 8601 string to datetime with timezone
                updated_at_str = record.updated_at
                updated_at = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
                
                if updated_at < cutoff_time:
                    shutil.rmtree(job_dir)
                    deleted_count += 1
            except Exception:
                # Skip jobs with invalid timestamps or other issues
                continue

        return deleted_count

    def get_stats(self) -> dict[str, int | list]:
        """Get dashboard statistics."""
        stats = {
            "total_jobs": 0,
            "jobs_by_status": {},
            "recent_jobs": [],
            "total_disk_usage_mb": 0,
        }
        recent_jobs: list[dict[str, str]] = []

        for job_dir in self.workdir.iterdir():
            if not job_dir.is_dir():
                continue

            try:
                record = self.load(job_dir.name)
                stats["total_jobs"] += 1

                # Count by status
                status = record.status
                stats["jobs_by_status"][status] = stats["jobs_by_status"].get(status, 0) + 1

                recent_jobs.append(
                    {
                        "job_id": record.job_id,
                        "status": record.status,
                        "filename": record.input_filename,
                        "created_at": record.created_at,
                    }
                )

                # Disk usage
                total_size = sum(f.stat().st_size for f in job_dir.rglob("*") if f.is_file())
                stats["total_disk_usage_mb"] += total_size / (1024 * 1024)
            except Exception:
                continue

        recent_jobs.sort(key=lambda item: item["created_at"], reverse=True)
        stats["recent_jobs"] = recent_jobs[:5]
        stats["total_disk_usage_mb"] = round(stats["total_disk_usage_mb"], 2)
        return stats
