"""Tests for inspect_enrichment: domain detection, trace shape, anomalies, next-step hints."""
from __future__ import annotations


from pcap2llm.inspect_enrichment import build_inspect_markdown, enrich_inspect_result
from pcap2llm.models import CaptureMetadata, InspectResult
from pcap2llm.profiles import load_all_profiles
from pcap2llm.signaling import dominant_signaling_names


def _make_result(
    protocol_counts: dict,
    transport_counts: dict | None = None,
    packet_count: int | None = None,
    anomalies: list[str] | None = None,
) -> InspectResult:
    total = packet_count or sum(protocol_counts.values())
    return InspectResult(
        metadata=CaptureMetadata(
            capture_file="/dev/null",
            packet_count=total,
            first_seen_epoch="1712390000.0",
            last_seen_epoch="1712390010.0",
            relevant_protocols=list(protocol_counts.keys()),
            raw_protocols=list(protocol_counts.keys()),
        ),
        protocol_counts=protocol_counts,
        transport_counts=transport_counts or {},
        conversations=[],
        anomalies=anomalies or [],
    )


# ---------------------------------------------------------------------------
# dominant_signaling
# ---------------------------------------------------------------------------

def test_dominant_signaling_excludes_transport() -> None:
    inspect = _make_result({"ngap": 400, "sctp": 500, "ip": 500, "nas-5gs": 80}, {"sctp": 500})
    result = dominant_signaling_names(inspect)
    assert "sctp" not in result
    assert "ip" not in result
    assert "ngap" in result
    assert "nas-5gs" in result


def test_dominant_signaling_sorts_by_count() -> None:
    inspect = _make_result({"ngap": 400, "nas-5gs": 80, "diameter": 200})
    result = dominant_signaling_names(inspect)
    assert result[0] == "ngap"
    assert result[1] == "diameter"


# ---------------------------------------------------------------------------
# trace_shape
# ---------------------------------------------------------------------------

def test_single_domain_5g() -> None:
    result = _make_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500})
    # Enrich to get suspected_domains
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    assert enriched.trace_shape == "single_domain"


def test_mixed_domain() -> None:
    # Strong 5G + strong IMS voice → mixed
    result = _make_result({"ngap": 300, "sip": 200, "sdp": 100, "sctp": 300, "ip": 300, "tcp": 200})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    assert enriched.trace_shape == "mixed_domain"


def test_transport_only_shape() -> None:
    result = _make_result({"sctp": 500, "ip": 500}, transport_counts={"sctp": 500})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    assert enriched.trace_shape == "transport_only"


def test_raw_signaling_presence_avoids_false_transport_only_shape() -> None:
    result = _make_result({"ip": 100}, transport_counts={"sctp": 100})
    result.metadata.raw_protocols = ["ip", "sctp", "diameter"]
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    assert enriched.trace_shape != "transport_only"
    assert any("raw signaling hints" in reason for reason in enriched.trace_shape_reasons)


# ---------------------------------------------------------------------------
# inspect_anomalies
# ---------------------------------------------------------------------------

def test_transport_only_anomaly_flagged() -> None:
    result = _make_result({"sctp": 500, "ip": 500}, transport_counts={"sctp": 500})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    anomaly_text = " ".join(enriched.anomalies)
    assert "transport" in anomaly_text.lower() or "sctp" in anomaly_text.lower()


def test_raw_signaling_coarse_decode_flagged_without_transport_only_warning() -> None:
    result = _make_result({"ip": 100}, transport_counts={"sctp": 100})
    result.metadata.raw_protocols = ["ip", "sctp", "diameter"]
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    # "coarse" decode note goes into classification_notes, not anomalies
    all_notes = " ".join(enriched.classification_notes).lower()
    assert "coarse" in all_notes
    anomaly_text = " ".join(enriched.anomalies).lower()
    assert "no application or signaling protocol decoded" not in anomaly_text


def test_legacy_modern_mix_flagged() -> None:
    result = _make_result({"ngap": 400, "sctp": 400, "ip": 400, "bssap": 5, "dtap": 3})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    anomaly_text = " ".join(enriched.anomalies).lower()
    assert "legacy" in anomaly_text or "interworking" in anomaly_text


def test_http_without_json_flagged() -> None:
    result = _make_result({"http": 100, "tcp": 200, "ip": 200})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    anomaly_text = " ".join(enriched.anomalies).lower()
    assert "json" in anomaly_text or "sbi" in anomaly_text or "http" in anomaly_text


# ---------------------------------------------------------------------------
# next_step_hints
# ---------------------------------------------------------------------------

def test_5g_hints_mention_5g_profiles() -> None:
    result = _make_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    hints_text = " ".join(enriched.next_step_hints)
    assert "5g" in hints_text.lower()


def test_lte_hints_mention_lte_profiles() -> None:
    result = _make_result({"s1ap": 300, "nas-eps": 100, "sctp": 400, "ip": 400})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    hints_text = " ".join(enriched.next_step_hints)
    assert "lte" in hints_text.lower()


def test_large_capture_hint() -> None:
    result = _make_result(
        {"ngap": 4000, "sctp": 5000, "ip": 5000},
        packet_count=10000,
    )
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    hints_text = " ".join(enriched.next_step_hints)
    assert "filter" in hints_text.lower() or "narrow" in hints_text.lower()


# ---------------------------------------------------------------------------
# enrich_inspect_result
# ---------------------------------------------------------------------------

def test_enrich_populates_suspected_domains() -> None:
    result = _make_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    assert enriched.suspected_domains
    assert enriched.suspected_domains[0]["domain"] == "5g-sa-core"


def test_enrich_populates_candidate_profiles() -> None:
    result = _make_result({"ngap": 400, "sctp": 500, "ip": 500})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    names = [p["profile"] for p in enriched.candidate_profiles]
    assert any(n.startswith("5g-") for n in names)


def test_enrich_does_not_mutate_original() -> None:
    result = _make_result({"ngap": 100, "sctp": 100, "ip": 100})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    assert result.suspected_domains == []
    assert enriched.suspected_domains != []


def test_existing_anomalies_preserved() -> None:
    result = _make_result(
        {"sctp": 500, "ip": 500},
        anomalies=["Packet 1: retransmission"],
    )
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    assert "Packet 1: retransmission" in enriched.anomalies


# ---------------------------------------------------------------------------
# build_inspect_markdown
# ---------------------------------------------------------------------------

def test_markdown_contains_all_sections() -> None:
    result = _make_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    md = build_inspect_markdown(enriched)
    assert "## Capture Overview" in md
    assert "## Trace Shape" in md
    assert "## Suspected Domains" in md
    assert "## Dominant Signaling Protocols" in md
    assert "## Major Conversations" in md
    assert "## Candidate Profiles" in md
    assert "## Suggested Next Steps" in md


def test_markdown_has_useful_content() -> None:
    result = _make_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500})
    profiles = load_all_profiles()
    enriched = enrich_inspect_result(result, profiles)
    md = build_inspect_markdown(enriched)
    assert "ngap" in md
    assert "5g" in md.lower()
