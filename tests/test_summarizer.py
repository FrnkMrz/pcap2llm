from __future__ import annotations

from pathlib import Path

from pcap2llm.models import CaptureMetadata, InspectResult
from pcap2llm.profiles import load_profile
from pcap2llm.summarizer import build_markdown_summary, build_summary


def _make_inspect_result(
    *,
    packet_count: int = 10,
    relevant_protocols: list[str] | None = None,
    anomalies: list[str] | None = None,
    capture_file: str = "sample.pcapng",
) -> InspectResult:
    metadata = CaptureMetadata(
        capture_file=capture_file,
        packet_count=packet_count,
        first_seen_epoch="1712390000.0",
        last_seen_epoch="1712390010.0",
        relevant_protocols=relevant_protocols or ["diameter"],
        raw_protocols=["eth", "ip", "sctp", "diameter"],
        display_filter=None,
    )
    return InspectResult(
        metadata=metadata,
        protocol_counts={"diameter": packet_count},
        transport_counts={"sctp": packet_count},
        conversations=[
            {
                "transport": "sctp",
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "top_protocol": "diameter",
                "packet_count": packet_count,
            }
        ],
        anomalies=anomalies or [],
    )


def _make_detail_packets(count: int = 3, protocol: str = "diameter") -> list[dict]:
    return [{"top_protocol": protocol, "packet_no": i} for i in range(count)]


def test_build_summary_structure() -> None:
    profile = load_profile("lte-core")
    inspect_result = _make_inspect_result()
    detail = _make_detail_packets(3)
    summary = build_summary(inspect_result, detail, profile=profile, privacy_modes={"ip": "keep"})

    assert summary["profile"] == "lte-core"
    assert summary["capture_metadata"]["packet_count"] == 10
    assert summary["packet_message_counts"]["total_packets"] == 10
    assert summary["packet_message_counts"]["top_protocols"]["diameter"] == 3
    assert summary["privacy_modes"] == {"ip": "keep"}
    assert "conversations" in summary
    assert "anomalies" in summary
    assert "probable_notable_findings" in summary


def test_build_summary_notable_findings_include_anomaly_count() -> None:
    profile = load_profile("lte-core")
    inspect_result = _make_inspect_result(anomalies=["Packet 3: retransmission", "Packet 7: out_of_order"])
    summary = build_summary(inspect_result, _make_detail_packets(), profile=profile, privacy_modes={})

    findings_text = " ".join(summary["probable_notable_findings"])
    assert "2 anomalies" in findings_text


def test_build_summary_no_anomalies_produces_findings() -> None:
    profile = load_profile("lte-core")
    inspect_result = _make_inspect_result(anomalies=[])
    summary = build_summary(inspect_result, _make_detail_packets(5), profile=profile, privacy_modes={})

    assert summary["anomalies"] == []
    # Protocol breakdown still appears
    assert any("diameter" in f for f in summary["probable_notable_findings"])


def test_build_markdown_summary_contains_key_sections() -> None:
    profile = load_profile("lte-core")
    inspect_result = _make_inspect_result()
    summary = build_summary(
        inspect_result, _make_detail_packets(), profile=profile, privacy_modes={"ip": "mask"}
    )
    md = build_markdown_summary(summary)

    assert "# PCAP2LLM Summary" in md
    assert "sample.pcapng" in md
    assert "diameter" in md
    assert "ip" in md
    assert "mask" in md
    assert "detail.json" in md


def test_build_markdown_summary_includes_optional_files() -> None:
    profile = load_profile("lte-core")
    inspect_result = _make_inspect_result()
    summary = build_summary(inspect_result, [], profile=profile, privacy_modes={})
    md = build_markdown_summary(
        summary,
        mapping_filename="pseudonym_mapping.json",
        vault_filename="vault.json",
    )

    assert "pseudonym_mapping.json" in md
    assert "vault.json" in md


def test_build_markdown_summary_omits_optional_files_when_not_given() -> None:
    profile = load_profile("lte-core")
    inspect_result = _make_inspect_result()
    summary = build_summary(inspect_result, [], profile=profile, privacy_modes={})
    md = build_markdown_summary(summary)

    assert "pseudonym_mapping.json" not in md
    assert "vault.json" not in md


def test_build_summary_empty_capture() -> None:
    profile = load_profile("lte-core")
    inspect_result = _make_inspect_result(packet_count=0, relevant_protocols=[])
    summary = build_summary(inspect_result, [], profile=profile, privacy_modes={})

    assert summary["packet_message_counts"]["total_packets"] == 0
    assert summary["packet_message_counts"]["top_protocols"] == {}
