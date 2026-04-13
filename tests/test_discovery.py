from __future__ import annotations

from pathlib import Path

from pcap2llm.discovery import build_discovery_markdown, build_discovery_payload, write_discovery_artifacts
from pcap2llm.models import CaptureMetadata, InspectResult


def _make_result(
    protocol_counts: dict[str, int],
    transport_counts: dict[str, int] | None = None,
    raw_protocols: list[str] | None = None,
    resolved_peers: list[dict[str, str]] | None = None,
    hosts_file_used: bool = False,
    mapping_file_used: bool = False,
    subnets_file_used: bool = False,
    ss7pcs_file_used: bool = False,
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
            subnets_file_used=subnets_file_used,
            ss7pcs_file_used=ss7pcs_file_used,
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
    # ngap and nas-5gs are raw_protocol entries (count=0 in protocol_counts) — they get
    # "supporting" strength to distinguish them from packet-counted protocols.
    assert dominant[0] == {"name": "ngap", "strength": "supporting"}
    assert dominant[1] == {"name": "nas-5gs", "strength": "supporting"}
    assert not any(item["name"] == "nas-eps" for item in dominant)
    assert not any(item["name"] == "nr-rrc" for item in dominant)
    assert not any(item["name"] in {"eth", "ethertype", "vlan", "ipcp", "pap"} for item in dominant)
    assert any(item["name"] == "sctp" and item["strength"] == "supporting" for item in dominant)
    # No entry should carry an explicit count of 0 — omit count key entirely for uncounted protocols
    assert all(item.get("count", 1) != 0 for item in dominant)
    assert payload["run"]["action"] == "discover"
    assert payload["capture"]["filename"] == "sample.pcapng"
    assert payload["capture"]["first_packet_number"] is None
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
        "subnets_file_used": False,
        "ss7pcs_file_used": False,
        "resolved_peer_count": 2,
    }
    assert payload["resolved_peers"][0] == {"ip": "10.109.182.14", "name": "AMF-01"}


def test_build_discovery_markdown_renders_ss7_point_code_examples_explicitly() -> None:
    discovery = {
        "run": {"action": "discover"},
        "capture": {"path": "/tmp/sample.pcapng", "filename": "sample.pcapng", "first_packet_number": None, "packet_count": 2},
        "artifact": {"version": "V_01"},
        "name_resolution": {
            "hosts_file_used": False,
            "mapping_file_used": False,
            "subnets_file_used": False,
            "ss7pcs_file_used": True,
            "resolved_peer_count": 2,
        },
        "resolved_peers": [
            {"ip": "10.0.0.1", "name": "VZB", "ss7_point_code": "0-5093", "ss7_point_code_alias": "VZB"},
            {"ip": "10.0.0.2", "name": "VZA", "ss7_point_code": "0-5091", "ss7_point_code_alias": "VZA"},
        ],
        "capture_context": {"link_or_envelope_protocols": [], "transport_support_protocols": []},
        "protocol_summary": {"dominant_signaling_protocols": [], "top_protocols": []},
        "suspected_domains": [],
        "candidate_profiles": [],
    }

    markdown = build_discovery_markdown(discovery)
    assert "SS7 point-code file used" in markdown
    assert "SS7 PC `0-5093` -> `VZB`" in markdown


def test_build_discovery_markdown_renders_dominant_signaling_first() -> None:
    discovery = {
        "run": {"action": "discover"},
        "capture": {"path": "/tmp/sample.pcapng", "filename": "sample.pcapng", "first_packet_number": None, "packet_count": 503},
        "artifact": {"version": "V_03"},
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
                # ngap/nas-5gs have no packet count (raw signal only) — strength="supporting"
                {"name": "ngap", "strength": "supporting"},
                {"name": "nas-5gs", "strength": "supporting"},
                {"name": "sctp", "count": 500, "strength": "supporting"},
            ],
            "top_protocols": [{"name": "ip", "count": 497}, {"name": "dtap", "count": 3}],
        },
        "suspected_domains": [{"domain": "5g-sa-core", "score": 0.81, "reason": ["primary 5G domain"]}],
        "candidate_profiles": [{
            "profile": "5g-n2",
            "score": 7.2,
            "confidence": "high",
            "evidence_class": "protocol_strong",
            "reason": ["aligned with suspected domain 5g-sa-core"],
        }],
    }

    markdown = build_discovery_markdown(discovery)
    assert markdown.index("- Action: `discover`") < markdown.index("- Capture file: `sample.pcapng`")
    assert markdown.index("- Capture file: `sample.pcapng`") < markdown.index("- Start packet: `unknown`")
    assert markdown.index("- Start packet: `unknown`") < markdown.index("- Artifact version: `V_03`")
    assert "## Dominant Signaling Protocols" in markdown
    assert "## Capture Context" in markdown
    assert markdown.index("## Dominant Signaling Protocols") < markdown.index("## Top Protocols")
    # ngap has no packet count (raw signal) — rendered with [raw signal] label
    assert "`ngap` [raw signal]" in markdown
    assert "`ethertype`" in markdown
    assert "`ip`: 497" in markdown
    assert "Raw top-protocol count view" in markdown
    assert "Hosts file used" in markdown
    assert "`10.109.182.14 -> AMF-01`" in markdown
    assert "[high/protocol_strong]" in markdown


def test_write_discovery_artifacts_adds_explicit_version_metadata(tmp_path: Path) -> None:
    discovery = {
        "run": {"action": "discover"},
        "capture": {
            "path": "/tmp/sample.pcapng",
            "filename": "sample.pcapng",
            "first_packet_number": 42,
            "first_seen": "1712390000.0",
            "last_seen": "1712390001.0",
            "packet_count": 10,
            "sha256": "abc123",
        },
        "artifact": {"version": None},
        "status": "ok",
        "mode": "discovery",
        "name_resolution": {"hosts_file_used": False, "mapping_file_used": False, "resolved_peer_count": 0},
        "resolved_peers": [],
        "capture_context": {"link_or_envelope_protocols": [], "transport_support_protocols": []},
        "transport_summary": {"udp": 10},
        "protocol_summary": {"dominant_signaling_protocols": [], "top_protocols": [], "relevant_protocols": [], "raw_protocols": []},
        "conversations": [],
        "anomalies": [],
        "suspected_domains": [],
        "candidate_profiles": [],
        "suppressed_profiles": [],
    }

    outputs = write_discovery_artifacts(tmp_path, discovery, "")
    payload = outputs["discovery_json"].read_text(encoding="utf-8")
    markdown = outputs["discovery_md"].read_text(encoding="utf-8")

    assert '"version": "V_01"' in payload
    assert "- Action: `discover`" in markdown
    assert "- Capture file: `sample.pcapng`" in markdown
    assert "- Start packet: `42`" in markdown
    assert "- Artifact version: `V_01`" in markdown
