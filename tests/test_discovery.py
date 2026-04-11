from __future__ import annotations

from pathlib import Path

from pcap2llm.discovery import build_discovery_markdown, build_discovery_payload
from pcap2llm.models import CaptureMetadata, InspectResult


def _make_result(
    protocol_counts: dict[str, int],
    transport_counts: dict[str, int] | None = None,
    raw_protocols: list[str] | None = None,
) -> InspectResult:
    total = sum(protocol_counts.values())
    raw = raw_protocols or list(protocol_counts.keys())
    return InspectResult(
        metadata=CaptureMetadata(
            capture_file="/tmp/sample.pcapng",
            packet_count=total,
            first_seen_epoch="1.0",
            last_seen_epoch="2.0",
            relevant_protocols=raw,
            raw_protocols=raw,
        ),
        protocol_counts=protocol_counts,
        transport_counts=transport_counts or {},
        conversations=[],
        anomalies=[],
    )


def test_build_discovery_payload_adds_dominant_signaling_protocols() -> None:
    result = _make_result(
        {"ip": 497, "dtap": 3},
        {"sctp": 500},
        ["ip", "dtap", "ngap", "nas-5gs", "sctp"],
    )
    payload = build_discovery_payload(
        capture_path=Path("/tmp/sample.pcapng"),
        inspect_result=result,
        candidate_profiles={
            "suspected_domains": [{"domain": "5g-sa-core", "score": 0.81, "reason": ["primary 5G domain"]}],
            "recommended_profiles": [{"profile": "5g-n2", "score": 7.2, "reason": ["aligned with suspected domain 5g-sa-core"]}],
            "suppressed_profiles": [],
        },
    )

    dominant = payload["protocol_summary"]["dominant_signaling_protocols"]
    assert dominant[0] == {"name": "ngap", "count": 0, "strength": "strong"}
    assert dominant[1] == {"name": "nas-5gs", "count": 0, "strength": "strong"}
    assert any(item["name"] == "sctp" and item["strength"] == "supporting" for item in dominant)
    assert payload["protocol_summary"]["top_protocols"][0]["name"] == "ip"


def test_build_discovery_markdown_renders_dominant_signaling_first() -> None:
    discovery = {
        "capture": {"path": "/tmp/sample.pcapng", "packet_count": 503},
        "protocol_summary": {
            "dominant_signaling_protocols": [
                {"name": "ngap", "count": 0, "strength": "strong"},
                {"name": "nas-5gs", "count": 0, "strength": "strong"},
                {"name": "sctp", "count": 500, "strength": "supporting"},
            ],
            "top_protocols": [{"name": "ip", "count": 497}, {"name": "dtap", "count": 3}],
        },
        "suspected_domains": [{"domain": "5g-sa-core", "score": 0.81, "reason": ["primary 5G domain"]}],
        "candidate_profiles": [{"profile": "5g-n2", "score": 7.2, "reason": ["aligned with suspected domain 5g-sa-core"]}],
    }

    markdown = build_discovery_markdown(discovery)
    assert "## Dominant Signaling Protocols" in markdown
    assert markdown.index("## Dominant Signaling Protocols") < markdown.index("## Top Protocols")
    assert "`ngap` [strong]" in markdown
    assert "`ip`: 497" in markdown
