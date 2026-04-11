from __future__ import annotations

from pathlib import Path

from pcap2llm.discovery import build_discovery_markdown, build_discovery_payload
from pcap2llm.models import CaptureMetadata, InspectResult


def _make_result(
    protocol_counts: dict[str, int],
    transport_counts: dict[str, int] | None = None,
    raw_protocols: list[str] | None = None,
    resolved_peers: list[dict[str, str]] | None = None,
    hosts_file_used: bool = False,
    mapping_file_used: bool = False,
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
            hosts_file_used=hosts_file_used,
            mapping_file_used=mapping_file_used,
            resolved_peers=resolved_peers or [],
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
        ["eth", "ethertype", "vlan", "ip", "dtap", "ngap", "nas-5gs", "sctp", "ipcp", "pap"],
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
    assert dominant[0] == {"name": "ngap", "strength": "strong"}
    assert dominant[1] == {"name": "nas-5gs", "strength": "strong"}
    assert not any(item["name"] == "nas-eps" for item in dominant)
    assert not any(item["name"] == "nr-rrc" for item in dominant)
    assert not any(item["name"] in {"eth", "ethertype", "vlan", "ipcp", "pap"} for item in dominant)
    assert any(item["name"] == "sctp" and item["strength"] == "supporting" for item in dominant)
    assert all(item.get("count", 1) != 0 for item in dominant)
    assert payload["capture_context"]["link_or_envelope_protocols"] == ["eth", "ethertype", "ip", "ipcp", "pap", "vlan"]
    assert payload["capture_context"]["transport_support_protocols"] == ["sctp"]
    assert payload["protocol_summary"]["top_protocols"][0]["name"] == "ip"
    assert payload["protocol_summary"]["relevant_protocols"] == ["dtap", "ngap", "nas-5gs", "sctp"]


def test_build_discovery_payload_surfaces_name_resolution_transparently() -> None:
    result = _make_result(
        {"s1ap": 20, "nas-eps": 10, "sctp": 30, "ip": 30},
        {"sctp": 30},
        ["s1ap", "nas-eps", "sctp", "ip"],
        resolved_peers=[
            {"ip": "10.109.182.14", "name": "AMF-01"},
            {"ip": "10.112.175.10", "name": "gNB-Cluster-A"},
        ],
        hosts_file_used=True,
        mapping_file_used=False,
    )
    payload = build_discovery_payload(
        capture_path=Path("/tmp/sample.pcapng"),
        inspect_result=result,
        candidate_profiles={
            "suspected_domains": [{"domain": "lte-eps", "score": 0.91, "reason": ["primary LTE domain"]}],
            "recommended_profiles": [{"profile": "lte-s1", "score": 7.2, "reason": ["aligned with suspected domain lte-eps"]}],
            "suppressed_profiles": [],
        },
    )

    assert payload["name_resolution"] == {
        "hosts_file_used": True,
        "mapping_file_used": False,
        "resolved_peer_count": 2,
    }
    assert payload["resolved_peers"][0] == {"ip": "10.109.182.14", "name": "AMF-01"}


def test_build_discovery_markdown_renders_dominant_signaling_first() -> None:
    discovery = {
        "capture": {"path": "/tmp/sample.pcapng", "packet_count": 503},
        "name_resolution": {
            "hosts_file_used": True,
            "mapping_file_used": False,
            "resolved_peer_count": 2,
        },
        "resolved_peers": [
            {"ip": "10.109.182.14", "name": "AMF-01"},
            {"ip": "10.112.175.10", "name": "gNB-Cluster-A"},
        ],
        "capture_context": {
            "link_or_envelope_protocols": ["eth", "ethertype", "vlan", "ipcp", "pap"],
            "transport_support_protocols": ["sctp"],
        },
        "protocol_summary": {
            "dominant_signaling_protocols": [
                {"name": "ngap", "strength": "strong"},
                {"name": "nas-5gs", "strength": "strong"},
                {"name": "sctp", "count": 500, "strength": "supporting"},
            ],
            "top_protocols": [{"name": "ip", "count": 497}, {"name": "dtap", "count": 3}],
        },
        "suspected_domains": [{"domain": "5g-sa-core", "score": 0.81, "reason": ["primary 5G domain"]}],
        "candidate_profiles": [{"profile": "5g-n2", "score": 7.2, "reason": ["aligned with suspected domain 5g-sa-core"]}],
    }

    markdown = build_discovery_markdown(discovery)
    assert "## Dominant Signaling Protocols" in markdown
    assert "## Capture Context" in markdown
    assert markdown.index("## Dominant Signaling Protocols") < markdown.index("## Top Protocols")
    assert "`ngap` [strong]" in markdown
    assert "`ethertype`" in markdown
    assert "`ip`: 497" in markdown
    assert "Raw top-protocol count view" in markdown
    assert "Hosts file used" in markdown
    assert "`10.109.182.14 -> AMF-01`" in markdown
