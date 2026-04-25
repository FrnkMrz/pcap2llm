from __future__ import annotations

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
    host = os.getenv("PCAP2LLM_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("PCAP2LLM_WEB_PORT", "8765"))
    workdir = Path(os.getenv("PCAP2LLM_WEB_WORKDIR", "./web_runs"))
    max_upload_mb = int(os.getenv("PCAP2LLM_WEB_MAX_UPLOAD_MB", "1"))
    command_timeout_seconds = int(os.getenv("PCAP2LLM_WEB_COMMAND_TIMEOUT_SECONDS", "600"))
    tshark_path = os.getenv("PCAP2LLM_WEB_TSHARK_PATH", "")
    support_files_root_env = os.getenv("PCAP2LLM_WEB_SUPPORT_FILES_ROOT", "")
    support_files_root = Path(support_files_root_env) if support_files_root_env else None
    default_privacy_profile = os.getenv("PCAP2LLM_WEB_DEFAULT_PRIVACY_PROFILE", "share")
    cleanup_enabled = os.getenv("PCAP2LLM_WEB_CLEANUP_ENABLED", "true").lower() in ("true", "1", "yes")
    cleanup_max_age_days = int(os.getenv("PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS", "7"))

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
