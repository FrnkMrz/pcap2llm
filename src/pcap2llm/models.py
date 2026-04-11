from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SCHEMA_VERSION = "1.0"


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
    hosts_file_used: bool = False
    mapping_file_used: bool = False
    resolved_peers: list[dict[str, Any]] = Field(default_factory=list)

    def summary_model_dump(self) -> dict[str, Any]:
        """Return the stable capture-metadata view used by analyze artifacts."""
        return self.model_dump(
            exclude={
                "hosts_file_used",
                "mapping_file_used",
                "resolved_peers",
            }
        )


class InspectResult(BaseModel):
    metadata: CaptureMetadata
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    transport_counts: dict[str, int] = Field(default_factory=dict)
    conversations: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    # --- enrichment fields (populated by enrich_inspect_result) ---
    suspected_domains: list[dict[str, Any]] = Field(default_factory=list)
    candidate_profiles: list[dict[str, Any]] = Field(default_factory=list)
    dominant_signaling_protocols: list[str] = Field(default_factory=list)
    trace_shape: str = "unknown"
    trace_shape_reasons: list[str] = Field(default_factory=list)
    next_step_hints: list[str] = Field(default_factory=list)
    # Methodological discovery notes — separate from network anomalies.
    # Covers decode limitations, host-hint-only evidence, family ambiguity, etc.
    classification_notes: list[str] = Field(default_factory=list)


class PrivacyProfileDefinition(BaseModel):
    """Standalone privacy policy: maps each data class to a protection mode."""

    name: str
    description: str = ""
    modes: dict[str, str] = Field(default_factory=dict)


class PackageMetadataExpectation(BaseModel):
    license_expression: str
    author_hint: str


class SelectorMetadata(BaseModel):
    family: str
    domain: str
    interface: str | None = None
    function: str | None = None
    triggers: dict[str, list[str]] = Field(default_factory=dict)
    strong_indicators: list[str] = Field(default_factory=list)
    weak_indicators: list[str] = Field(default_factory=list)
    use_when: list[str] = Field(default_factory=list)
    avoid_when: list[str] = Field(default_factory=list)
    cost_hint: str | None = None
    output_focus: str | None = None


class ProfileDefinition(BaseModel):
    name: str
    description: str
    relevant_protocols: list[str]
    top_protocol_priority: list[str]
    protocol_aliases: dict[str, list[str]] = Field(default_factory=dict)
    full_detail_fields: dict[str, list[str]] = Field(default_factory=dict)
    verbatim_protocols: list[str] = Field(
        default_factory=list,
        description=(
            "Protocols whose TShark layer is retained with minimal transformation. "
            "Top-level protocol fields are kept, repeated nested protocol fields "
            "such as Diameter AVPs are surfaced into flat protocol-prefixed keys, "
            "and _ws.* keys are stripped. Takes priority over full_detail_fields "
            "for the same protocol."
        ),
    )
    keep_raw_avps: bool = Field(
        default=False,
        description=(
            "When true, retain raw AVP dump fields such as diameter.avp, "
            "diameter.avp_tree, and related *_tree decoder structures alongside "
            "surfaced semantic Diameter fields. Default false keeps output "
            "smaller and less noisy for LLM consumption."
        ),
    )
    reduced_transport_fields: list[str] = Field(default_factory=list)
    default_privacy_modes: dict[str, str] | None = Field(
        default=None,
        description=(
            "Deprecated: move privacy configuration to a dedicated privacy profile "
            "and use --privacy-profile / privacy_profile in the config file."
        ),
    )
    selector_metadata: SelectorMetadata | None = None
    tshark: dict[str, Any] = Field(default_factory=dict)
    summary_heuristics: list[str] = Field(default_factory=list)
    max_conversations: int = Field(
        default=25,
        description="Maximum number of conversation rows kept in InspectResult.",
    )


class AnalyzeArtifacts(BaseModel):
    summary: dict[str, Any]
    detail: dict[str, Any]
    markdown: str
    pseudonym_mapping: dict[str, dict[str, str]] = Field(default_factory=dict)
    vault: dict[str, Any] | None = None


class ArtifactCoverage(BaseModel):
    detail_packets_included: int
    detail_packets_available: int
    detail_truncated: bool
    summary_packet_count: int
    truncation_note: str | None = None


class SummaryArtifactV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    generated_at: str
    capture_sha256: str | None = None
    profile: str
    artifact_role: Literal["summary_sidecar"] = "summary_sidecar"
    capture_metadata: dict[str, Any]
    relevant_protocols: list[str] = Field(default_factory=list)
    conversations: list[dict[str, Any]] = Field(default_factory=list)
    packet_message_counts: dict[str, Any] = Field(default_factory=dict)
    anomalies: list[str] = Field(default_factory=list)
    anomaly_counts_by_layer: dict[str, int] = Field(default_factory=dict)
    deterministic_findings: list[str] = Field(default_factory=list)
    probable_notable_findings: list[str] = Field(default_factory=list)
    privacy_modes: dict[str, str] = Field(default_factory=dict)
    privacy_policy: dict[str, Any] = Field(default_factory=dict)
    coverage: ArtifactCoverage
    timing_stats: dict[str, Any] | None = None
    burst_periods: list[dict[str, Any]] = Field(default_factory=list)
    dropped_packets: int | None = None
    detail_truncated: dict[str, Any] | None = None
    privacy_audit: dict[str, Any] | None = None


class DetailArtifactV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    generated_at: str
    capture_sha256: str | None = None
    profile: str
    artifact_role: Literal["llm_input"] = "llm_input"
    coverage: ArtifactCoverage
    messages: list[dict[str, Any]] = Field(default_factory=list)
    selected_packets: list[dict[str, Any]] = Field(default_factory=list)
