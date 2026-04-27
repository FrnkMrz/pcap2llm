from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pcap2llm.config import build_privacy_modes


JobStatus = Literal[
    "created",
    "uploaded",
    "discovering",
    "discovered",
    "analyzing",
    "done",
    "failed",
]


@dataclass
class AnalyzeOptions:
    profile: str
    privacy_profile: str = "share"
    display_filter: str | None = None
    max_packets: int | None = None
    all_packets: bool = False
    fail_on_truncation: bool = False
    max_capture_size_mb: int | None = None
    oversize_factor: float | None = None
    render_flow_svg: bool = False
    flow_title: str | None = None
    flow_max_events: int | None = None
    flow_svg_width: int | None = None
    collapse_repeats: bool = True
    hosts_file: str | None = None
    mapping_file: str | None = None
    subnets_file: str | None = None
    ss7pcs_file: str | None = None
    network_element_mapping_file: str | None = None
    tshark_path: str | None = None
    two_pass: bool = False


@dataclass
class RunResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    command: list[str]
    artifacts: list[Path] = field(default_factory=list)


@dataclass
class JobRecord:
    job_id: str
    status: JobStatus
    input_filename: str
    created_at: str
    updated_at: str
    selected_profile: str | None = None
    selected_privacy_profile: str | None = None
    recommended_profiles: list[dict[str, Any]] = field(default_factory=list)
    suspected_domains: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    last_error: str | None = None
    last_error_code: str | None = None
    analyze_form: dict[str, Any] = field(default_factory=dict)
    discover_form: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "JobRecord":
        # Tolerate manifests written before optional fields existed.
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in known})



def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class SecurityProfile:
    """Local editable privacy profile used by the web GUI."""

    id: str
    name: str
    description: str
    modes: dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=now_utc_iso)
    updated_at: str = field(default_factory=now_utc_iso)
    source: str = "local"
    builtin_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["modes"] = build_privacy_modes({}, self.modes)
        return data

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecurityProfile":
        return cls(
            id=str(payload.get("id", "")),
            name=str(payload.get("name", "")),
            description=str(payload.get("description", "")),
            modes=build_privacy_modes({}, payload.get("modes", {})),
            created_at=str(payload.get("created_at", now_utc_iso())),
            updated_at=str(payload.get("updated_at", now_utc_iso())),
            source=str(payload.get("source", "local")),
            builtin_name=str(payload["builtin_name"]) if payload.get("builtin_name") else None,
        )
