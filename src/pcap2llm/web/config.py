from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WebSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    workdir: Path = Path("./web_runs")
    max_upload_mb: int = 1
    command_timeout_seconds: int = 600
    tshark_path: str = ""
    support_files_root: Path | None = None
    default_privacy_profile: str = "share"
    cleanup_enabled: bool = True
    cleanup_max_age_days: int = 7

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def local_workspace_dir(self) -> Path:
        """Resolve the local workspace that should hold helper files and profiles."""
        workdir_parent = self.workdir.parent
        if workdir_parent.name == ".local":
            return workdir_parent
        sibling_local = workdir_parent / ".local"
        if sibling_local.exists():
            return sibling_local
        if self.workdir.name == "web_runs":
            return workdir_parent
        return self.workdir

    @property
    def security_profiles_dir(self) -> Path:
        return self.local_workspace_dir / "profiles"



def load_settings() -> WebSettings:
    workdir_env = os.getenv("PCAP2LLM_WEB_WORKDIR")
    workdir_default = Path("./web_runs")
    workdir = Path(workdir_env) if workdir_env else workdir_default

    settings_file_env = os.getenv("PCAP2LLM_WEB_SETTINGS_FILE", "").strip()
    settings_file_path = Path(settings_file_env) if settings_file_env else _default_web_settings_path(workdir)
    settings_file = _load_web_settings_file(settings_file_path)

    host = os.getenv("PCAP2LLM_WEB_HOST") or str(settings_file.get("host", "127.0.0.1"))
    port = int(os.getenv("PCAP2LLM_WEB_PORT") or int(settings_file.get("port", 8765)))
    if not workdir_env:
        file_workdir = str(settings_file.get("workdir", "")).strip()
        if file_workdir:
            workdir = Path(file_workdir)

    max_upload_mb = int(
        os.getenv("PCAP2LLM_WEB_MAX_UPLOAD_MB") or int(settings_file.get("max_upload_mb", 1))
    )
    command_timeout_seconds = int(
        os.getenv("PCAP2LLM_WEB_COMMAND_TIMEOUT_SECONDS")
        or int(settings_file.get("command_timeout_seconds", 600))
    )
    tshark_path = (
        os.getenv("PCAP2LLM_WEB_TSHARK_PATH")
        or os.getenv("PCAP2LLM_TSHARK_PATH")
        or str(settings_file.get("tshark_path", ""))
    )

    support_files_root_env = os.getenv("PCAP2LLM_WEB_SUPPORT_FILES_ROOT")
    if support_files_root_env:
        support_files_root = Path(support_files_root_env)
    else:
        support_root_file = str(settings_file.get("support_files_root", "")).strip()
        support_files_root = Path(support_root_file) if support_root_file else None

    default_privacy_profile = (
        os.getenv("PCAP2LLM_WEB_DEFAULT_PRIVACY_PROFILE")
        or str(settings_file.get("default_privacy_profile", "share"))
    )
    cleanup_enabled = _parse_bool(
        os.getenv("PCAP2LLM_WEB_CLEANUP_ENABLED"),
        bool(settings_file.get("cleanup_enabled", True)),
    )
    cleanup_max_age_days = int(
        os.getenv("PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS")
        or int(settings_file.get("cleanup_max_age_days", 7))
    )

    return WebSettings(
        host=host,
        port=port,
        workdir=workdir,
        max_upload_mb=max_upload_mb,
        command_timeout_seconds=command_timeout_seconds,
        tshark_path=tshark_path,
        support_files_root=support_files_root,
        default_privacy_profile=default_privacy_profile,
        cleanup_enabled=cleanup_enabled,
        cleanup_max_age_days=cleanup_max_age_days,
    )


def _default_web_settings_path(workdir: Path) -> Path:
    local_root = _default_local_workspace_dir(workdir)
    return local_root / "web_settings.json"


def _default_local_workspace_dir(workdir: Path) -> Path:
    workdir_parent = workdir.parent
    if workdir_parent.name == ".local":
        return workdir_parent
    sibling_local = workdir_parent / ".local"
    if sibling_local.exists() or workdir.name == "web_runs":
        return sibling_local
    return workdir


def _load_web_settings_file(path: Path) -> dict[str, object]:
    if not path.exists() or not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _parse_bool(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes")
