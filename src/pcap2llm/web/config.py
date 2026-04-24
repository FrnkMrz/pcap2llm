from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WebSettings:
    host: str = "127.0.0.1"
    port: int = 8765
    workdir: Path = Path("./web_runs")
    max_upload_mb: int = 250
    command_timeout_seconds: int = 600
    tshark_path: str = ""
    default_privacy_profile: str = "share"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024



def load_settings() -> WebSettings:
    host = os.getenv("PCAP2LLM_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("PCAP2LLM_WEB_PORT", "8765"))
    workdir = Path(os.getenv("PCAP2LLM_WEB_WORKDIR", "./web_runs"))
    max_upload_mb = int(os.getenv("PCAP2LLM_WEB_MAX_UPLOAD_MB", "250"))
    command_timeout_seconds = int(os.getenv("PCAP2LLM_WEB_COMMAND_TIMEOUT_SECONDS", "600"))
    tshark_path = os.getenv("PCAP2LLM_WEB_TSHARK_PATH", "")
    default_privacy_profile = os.getenv("PCAP2LLM_WEB_DEFAULT_PRIVACY_PROFILE", "share")

    return WebSettings(
        host=host,
        port=port,
        workdir=workdir,
        max_upload_mb=max_upload_mb,
        command_timeout_seconds=command_timeout_seconds,
        tshark_path=tshark_path,
        default_privacy_profile=default_privacy_profile,
    )
