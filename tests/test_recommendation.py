"""Tests for discovery scoring and profile recommendation.

Covers:
- Strong 5G signals produce 5g-sa-core domain + 5G profiles ranked first
- Strong LTE signals produce lte-eps domain + LTE S1 profiles ranked first
- Strong legacy 2G/3G signals produce legacy-2g3g domain
- Transport-only signals (sctp, ip, tcp) do NOT produce strong recommendations
- Rare domain protocols do not dominate when a different domain has majority traffic
"""
from __future__ import annotations

from pcap2llm.models import CaptureMetadata, InspectResult
from pcap2llm.profiles import load_all_profiles
from pcap2llm.recommendation import _score_profile, infer_domains, recommend_profiles_from_inspect


def _mock_result(protocol_counts: dict, transport_counts: dict | None = None) -> InspectResult:
    total = sum(protocol_counts.values())
    all_protos = list(protocol_counts.keys())
    return InspectResult(
        metadata=CaptureMetadata(
            capture_file="/dev/null",
            packet_count=total,
            first_seen_epoch="1.0",
            last_seen_epoch="2.0",
            relevant_protocols=all_protos,
            raw_protocols=all_protos,
        ),
        conversations=[],
        anomalies=[],
        protocol_counts=protocol_counts,
        transport_counts=transport_counts or {},
    )


# ---------------------------------------------------------------------------
# infer_domains
# ---------------------------------------------------------------------------

def test_5g_n2_strong_signal_detects_5g_sa_core() -> None:
    result = _mock_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500})
    domains = infer_domains(result)
    assert domains, "expected at least one domain"
    assert domains[0]["domain"] == "5g-sa-core"
    assert domains[0]["score"] >= 0.85


def test_5g_ngap_only_detects_5g_sa_core() -> None:
    result = _mock_result({"ngap": 200, "sctp": 200, "ip": 200})
    domains = infer_domains(result)
    names = [d["domain"] for d in domains]
    assert "5g-sa-core" in names


def test_lte_s1_strong_signal_detects_lte_eps() -> None:
    result = _mock_result({"s1ap": 300, "nas-eps": 100, "sctp": 400, "ip": 400})
    domains = infer_domains(result)
    assert domains[0]["domain"] == "lte-eps"
    assert domains[0]["score"] >= 0.85


def test_diameter_sctp_detects_lte_eps() -> None:
    result = _mock_result({"diameter": 200, "sctp": 200, "ip": 200})
    domains = infer_domains(result)
    names = [d["domain"] for d in domains]
    assert "lte-eps" in names


def test_sip_sdp_detects_ims_voice() -> None:
    result = _mock_result({"sip": 100, "sdp": 50, "tcp": 200, "ip": 200})
    domains = infer_domains(result)
    names = [d["domain"] for d in domains]
    assert "ims-voice" in names
    voice = next(d for d in domains if d["domain"] == "ims-voice")
    assert voice["score"] >= 0.80


def test_map_tcap_sccp_detects_legacy_2g3g() -> None:
    result = _mock_result({"map": 150, "tcap": 100, "sccp": 200, "ip": 200})
    domains = infer_domains(result)
    assert domains[0]["domain"] == "legacy-2g3g"
    assert domains[0]["score"] >= 0.80


def test_transport_only_produces_no_domain() -> None:
    """Pure ip+sctp+tcp without any domain protocol must not produce a domain."""
    result = _mock_result({"ip": 500, "sctp": 300, "tcp": 100})
    domains = infer_domains(result)
    domain_names = [d["domain"] for d in domains]
    assert "5g-sa-core" not in domain_names
    assert "lte-eps" not in domain_names
    assert "legacy-2g3g" not in domain_names


def test_rare_dtap_does_not_dominate_strong_5g_trace() -> None:
    """3 dtap packets in a 5G-dominant trace must not produce legacy-2g3g above 5g-sa-core."""
    result = _mock_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500, "dtap": 3, "bssap": 2})
    domains = infer_domains(result)
    if domains:
        assert domains[0]["domain"] == "5g-sa-core"
    names = [d["domain"] for d in domains]
    # legacy-2g3g should not appear (too rare to meet threshold)
    assert "legacy-2g3g" not in names


# ---------------------------------------------------------------------------
# _score_profile
# ---------------------------------------------------------------------------

def test_5g_n2_profile_scores_high_on_ngap_trace() -> None:
    from pcap2llm.profiles import load_profile
    result = _mock_result({"ngap": 400, "sctp": 400, "ip": 400}, {"sctp": 400})
    profile = load_profile("5g-n2")
    score, reasons = _score_profile(result, profile)
    assert score >= 5.0
    assert any("ngap" in r for r in reasons)


def test_transport_only_does_not_score_lte_sgs() -> None:
    """lte-sgs must not score above 1 when only sctp and ip are present (no sgsap)."""
    from pcap2llm.profiles import load_profile
    result = _mock_result({"sctp": 500, "ip": 500}, {"sctp": 500})
    profile = load_profile("lte-sgs")
    score, _ = _score_profile(result, profile)
    assert score <= 1.0, f"lte-sgs scored {score} from transport-only trace (expected ≤1)"


def test_rare_protocol_is_dampened() -> None:
    """A profile whose key protocol appears in <1% of packets scores much less than one at >5%."""
    from pcap2llm.profiles import load_profile
    # bssap = 2/500 = 0.4% → dampened
    result_rare = _mock_result({"ngap": 400, "sctp": 400, "ip": 400, "bssap": 2}, {"sctp": 400})
    # bssap = 100/500 = 20% → full weight
    result_frequent = _mock_result({"bssap": 100, "sctp": 200, "ip": 200}, {"sctp": 200})
    profile = load_profile("2g3g-geran")
    score_rare, _ = _score_profile(result_rare, profile)
    score_frequent, _ = _score_profile(result_frequent, profile)
    assert score_frequent > score_rare * 3, (
        f"frequent ({score_frequent:.2f}) should be much higher than rare ({score_rare:.2f})"
    )


# ---------------------------------------------------------------------------
# recommend_profiles_from_inspect — ranking
# ---------------------------------------------------------------------------

def test_5g_profiles_rank_above_2g3g_on_ngap_trace() -> None:
    """5G profiles must rank above 2G/3G profiles on a clear NGAP trace."""
    result = _mock_result(
        {"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500, "dtap": 3},
        {"sctp": 500},
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles)
    names = [r["profile"] for r in rec["recommended_profiles"]]
    # At least one 5G profile in top 3
    top3 = names[:3]
    assert any(n.startswith("5g-") for n in top3), f"No 5G profile in top 3: {top3}"
    # No 2G/3G profile above all 5G profiles
    first_5g = next((i for i, n in enumerate(names) if n.startswith("5g-")), 999)
    first_2g3g = next((i for i, n in enumerate(names) if n.startswith("2g3g-")), 999)
    assert first_5g < first_2g3g, (
        f"2G/3G profile at position {first_2g3g} ranked above first 5G at {first_5g}"
    )


def test_lte_s1_profiles_rank_above_5g_on_s1ap_trace() -> None:
    result = _mock_result(
        {"s1ap": 300, "nas-eps": 100, "sctp": 400, "ip": 400},
        {"sctp": 400},
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles)
    names = [r["profile"] for r in rec["recommended_profiles"]]
    top3 = names[:3]
    assert any(n.startswith("lte-") for n in top3), f"No LTE profile in top 3: {top3}"


def test_transport_only_produces_few_or_no_recommendations() -> None:
    """Pure transport trace must not produce many confident profile recommendations."""
    result = _mock_result({"sctp": 500, "ip": 500}, {"sctp": 500})
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles)
    recommended = rec["recommended_profiles"]
    # Either none, or all have very low scores
    for item in recommended:
        assert item["score"] <= 1.5, (
            f"Profile {item['profile']} scored {item['score']} from transport-only trace"
        )


def test_suspected_domains_not_empty_for_5g_trace() -> None:
    result = _mock_result({"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500})
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles)
    assert rec["suspected_domains"], "suspected_domains must not be empty for strong 5G signals"
    assert rec["suspected_domains"][0]["domain"] == "5g-sa-core"
