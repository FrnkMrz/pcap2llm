from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ProtectionMode(str, Enum):
    KEEP = "keep"
    MASK = "mask"
    PSEUDONYMIZE = "pseudonymize"
    ENCRYPT = "encrypt"
    REMOVE = "remove"


DATA_CLASSES = [
    "ip",
    "hostname",
    "subscriber_id",
    "msisdn",
    "imsi",
    "imei",
    "email",
    "distinguished_name",
    "token",
    "uri",
    "apn_dnn",
    "diameter_identity",
    "payload_text",
]


class ResolvedEndpoint(BaseModel):
    ip: str | None = None
    hostname: str | None = None
    alias: str | None = None
    role: str | None = None
    site: str | None = None
    labels: dict[str, Any] = Field(default_factory=dict)


class TransportContext(BaseModel):
    proto: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    stream: int | str | None = None
    sctp_stream: int | str | None = None
    anomaly: bool = False
    notes: list[str] = Field(default_factory=list)


class MessageContext(BaseModel):
    protocol: str
    fields: dict[str, Any] = Field(default_factory=dict)


class PrivacySummary(BaseModel):
    modes: dict[str, str] = Field(default_factory=dict)


class NormalizedPacket(BaseModel):
    packet_no: int
    time_rel_ms: float | None = None
    time_epoch: str | None = None
    top_protocol: str
    frame_protocols: list[str] = Field(default_factory=list)
    src: ResolvedEndpoint = Field(default_factory=ResolvedEndpoint)
    dst: ResolvedEndpoint = Field(default_factory=ResolvedEndpoint)
    transport: TransportContext = Field(default_factory=TransportContext)
    privacy: PrivacySummary = Field(default_factory=PrivacySummary)
    anomalies: list[str] = Field(default_factory=list)
    message: MessageContext


class CaptureMetadata(BaseModel):
    capture_file: str
    packet_count: int
    first_seen_epoch: str | None = None
    last_seen_epoch: str | None = None
    relevant_protocols: list[str] = Field(default_factory=list)
    raw_protocols: list[str] = Field(default_factory=list)
    display_filter: str | None = None


class InspectResult(BaseModel):
    metadata: CaptureMetadata
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    transport_counts: dict[str, int] = Field(default_factory=dict)
    conversations: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)


class ProfileDefinition(BaseModel):
    name: str
    description: str
    relevant_protocols: list[str]
    top_protocol_priority: list[str]
    protocol_aliases: dict[str, list[str]] = Field(default_factory=dict)
    full_detail_fields: dict[str, list[str]] = Field(default_factory=dict)
    reduced_transport_fields: list[str] = Field(default_factory=list)
    default_privacy_modes: dict[str, str] = Field(default_factory=dict)
    tshark: dict[str, Any] = Field(default_factory=dict)
    summary_heuristics: list[str] = Field(default_factory=list)


class AnalyzeArtifacts(BaseModel):
    summary: dict[str, Any]
    detail: dict[str, Any]
    markdown: str
    pseudonym_mapping: dict[str, dict[str, str]] = Field(default_factory=dict)
    vault: dict[str, Any] | None = None
