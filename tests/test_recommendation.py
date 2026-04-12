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


def _mock_result(
    protocol_counts: dict,
    transport_counts: dict | None = None,
    raw_protocols: list[str] | None = None,
    resolved_peers: list[dict] | None = None,
) -> InspectResult:
    total = sum(protocol_counts.values())
    all_protos = raw_protocols or list(protocol_counts.keys())
    return InspectResult(
        metadata=CaptureMetadata(
            capture_file="/dev/null",
            packet_count=total,
            first_seen_epoch="1.0",
            last_seen_epoch="2.0",
            relevant_protocols=all_protos,
            raw_protocols=all_protos,
            resolved_peers=resolved_peers or [],
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


def test_raw_protocols_can_recover_strong_5g_domain_from_flat_top_protocols() -> None:
    result = _mock_result(
        {"ip": 497, "dtap": 3},
        {"sctp": 500},
        ["ip", "dtap", "ngap", "nas-5gs", "nas-eps", "sctp", "nr-rrc", "gsm_a.dtap"],
    )
    domains = infer_domains(result)
    assert domains, "expected raw_protocols to recover a domain hypothesis"
    assert domains[0]["domain"] == "5g-sa-core"
    assert domains[0]["score"] >= 0.75
    assert any("ngap" in reason for reason in domains[0]["reason"])
    assert any("nas-5gs" in reason for reason in domains[0]["reason"])


def test_dtap_alone_is_not_enough_for_legacy_domain() -> None:
    result = _mock_result(
        {"ip": 500, "dtap": 3},
        None,
        ["ip", "dtap", "gsm_a.dtap"],
    )
    domains = infer_domains(result)
    assert not any(d["domain"].startswith("legacy-") for d in domains)


def test_real_legacy_combo_remains_strong() -> None:
    result = _mock_result(
        {"bssap": 150, "dtap": 120, "sccp": 200, "mtp3": 200, "ip": 200},
        None,
        ["bssap", "dtap", "sccp", "mtp3", "ip"],
    )
    domains = infer_domains(result)
    assert domains
    assert domains[0]["domain"] == "legacy-2g3g"
    assert domains[0]["score"] >= 0.8


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


def test_dtap_only_profile_signal_is_gated_without_legacy_partners() -> None:
    from pcap2llm.profiles import load_profile

    result = _mock_result({"ip": 500, "dtap": 3}, None, ["ip", "dtap", "gsm_a.dtap"])
    profile = load_profile("2g3g-geran")
    score, reasons = _score_profile(result, profile)
    assert score < 1.0
    assert any("gated" in reason for reason in reasons)


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


def test_raw_5g_signals_rank_above_legacy_profiles() -> None:
    result = _mock_result(
        {"ip": 497, "dtap": 3},
        {"sctp": 500},
        ["ip", "dtap", "ngap", "nas-5gs", "nas-eps", "sctp", "nr-rrc", "gsm_a.dtap"],
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles)
    names = [r["profile"] for r in rec["recommended_profiles"][:5]]
    assert any(name.startswith("5g-") for name in names), f"No 5G profile in top 5: {names}"
    first_5g = next((i for i, name in enumerate(names) if name.startswith("5g-")), 999)
    first_2g3g = next((i for i, name in enumerate(names) if name.startswith("2g3g-")), 999)
    assert first_5g < first_2g3g, (
        f"Legacy profile ranked above recovered 5G domain: top5={names}"
    )


def test_domain_bonus_does_not_recommend_zero_evidence_profiles() -> None:
    result = _mock_result(
        {"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500},
        {"sctp": 500},
        ["ngap", "nas-5gs", "sctp", "ip"],
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles, limit=20)
    names = [r["profile"] for r in rec["recommended_profiles"]]
    assert "5g-cbc-cbs" not in names
    assert "5g-dns" not in names

    suppressed_names = [r["profile"] for r in rec["suppressed_profiles"]]
    assert "5g-cbc-cbs" in suppressed_names
    assert "5g-dns" in suppressed_names


def test_vonr_profiles_downrank_without_voice_indicators() -> None:
    result = _mock_result(
        {"ngap": 400, "nas-5gs": 80, "sctp": 500, "ip": 500},
        {"sctp": 500},
        ["ngap", "nas-5gs", "sctp", "ip"],
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles, limit=12)
    names = [r["profile"] for r in rec["recommended_profiles"]]
    assert names.index("5g-core") < names.index("vonr-n1-n2-voice")


def test_lte_diameter_candidates_stay_above_generic_5g_matches() -> None:
    result = _mock_result(
        {"diameter": 200, "sctp": 200, "ip": 200},
        {"sctp": 200},
        ["diameter", "sctp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert names[0] == "lte-s6a"
    assert "5g-n2" not in names[:5]
    ims_scores = {
        item["profile"]: item["score"]
        for item in rec["recommended_profiles"]
        if item["profile"] in {"volte-diameter-cx", "volte-diameter-rx", "volte-diameter-sh", "volte-ims-core"}
    }
    assert ims_scores
    assert all(score < 2.5 for score in ims_scores.values())


def test_gtpv2_trace_prefers_lte_control_plane_profiles() -> None:
    result = _mock_result(
        {"gtpv2": 120, "udp": 120, "ip": 120},
        {"udp": 120},
        ["gtpv2", "udp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=6)
    top = [item["profile"] for item in rec["recommended_profiles"][:4]]
    assert {"lte-s10", "lte-s11"}.issubset(top)


def test_legacy_ss7_trace_prefers_legacy_profiles() -> None:
    result = _mock_result(
        {"map": 150, "tcap": 100, "sccp": 200, "ip": 200},
        None,
        ["map", "tcap", "sccp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=6)
    top = [item["profile"] for item in rec["recommended_profiles"][:3]]
    assert top[0] in {"2g3g-gr", "2g3g-map-core"}
    assert all(name.startswith("2g3g-") for name in top)
    assert rec["suspected_domains"][0]["domain"] == "legacy-2g3g"


def test_map_tcap_sccp_trace_keeps_bssap_geran_family_below_core_profiles() -> None:
    result = _mock_result(
        {"map": 140, "tcap": 110, "sccp": 150, "mtp3": 120, "m2pa": 120},
        None,
        ["map", "tcap", "sccp", "mtp3", "m2pa"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=10)
    scores = {item["profile"]: item["score"] for item in rec["recommended_profiles"]}
    assert "2g3g-map-core" in scores
    assert "2g3g-sccp-mtp" in scores
    for gated in ("2g3g-bssap", "2g3g-geran", "2g3g-gs", "2g3g-ss7-geran"):
        if gated in scores:
            assert scores[gated] < scores["2g3g-map-core"]
            assert scores[gated] < scores["2g3g-sccp-mtp"]


def test_bssap_dtap_evidence_raises_geran_side_profiles() -> None:
    result = _mock_result(
        {"bssap": 150, "dtap": 120, "sccp": 180, "mtp3": 180},
        None,
        ["bssap", "dtap", "sccp", "mtp3"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
    top = [item["profile"] for item in rec["recommended_profiles"][:5]]
    assert any(name in top for name in {"2g3g-bssap", "2g3g-geran", "2g3g-gs"})


def test_5g_domain_remains_primary_when_nas_eps_side_signal_is_present() -> None:
    result = _mock_result(
        {"ngap": 400, "nas-5gs": 80, "nas-eps": 20, "sctp": 500, "ip": 500},
        {"sctp": 500},
        ["ngap", "nas-5gs", "nas-eps", "sctp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=10)
    assert rec["suspected_domains"][0]["domain"] == "5g-sa-core"
    names = [item["profile"] for item in rec["recommended_profiles"][:5]]
    assert any(name.startswith("5g-") for name in names[:3])


def test_lte_primary_domain_with_small_sip_dns_only_surfaces_voice_as_side_signal() -> None:
    result = _mock_result(
        {"s1ap": 240, "nas-eps": 80, "sctp": 320, "sip": 5, "dns": 6, "ip": 320},
        {"sctp": 320},
        ["s1ap", "nas-eps", "sctp", "sip", "dns", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert names[:3] == ["lte-s1", "lte-s1-nas", "lte-core"]
    assert any(name.startswith("volte-") for name in names[3:])
    if "vonr-n1-n2-voice" in names:
        vonr_index = names.index("vonr-n1-n2-voice")
        first_volte_index = min(i for i, name in enumerate(names) if name.startswith("volte-"))
        assert first_volte_index < vonr_index
        vonr_reason = next(r["reason"] for r in rec["recommended_profiles"] if r["profile"] == "vonr-n1-n2-voice")
        assert vonr_reason[0].startswith("voice profile downranked")
        assert any("no SIP/IMS indicators" in reason for reason in vonr_reason)


def test_dns_only_trace_does_not_raise_sip_or_sbc_profiles() -> None:
    result = _mock_result(
        {"dns": 120, "udp": 120, "ip": 120},
        {"udp": 120},
        ["dns", "udp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
    names = [item["profile"] for item in rec["recommended_profiles"][:6]]
    assert "5g-dns" in names
    assert "lte-dns" in names
    assert not any(name in names for name in {"volte-sbc", "volte-sip", "volte-sip-call", "volte-sip-register"})


def test_gtpv2_with_s5s8_host_hints_prefers_s5_s8_profiles() -> None:
    result = _mock_result(
        {"gtpv2": 120, "udp": 120, "ip": 120},
        {"udp": 120},
        ["gtpv2", "udp", "ip"],
    )
    result.metadata.resolved_peers = [
        {"ip": "10.0.0.1", "name": "S5-S8-PGW-01", "role": "pgw"},
        {"ip": "10.0.0.2", "name": "S5-S8-SGW-01", "role": "sgw"},
    ]
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=6)
    names = [item["profile"] for item in rec["recommended_profiles"][:4]]
    assert names[:2] == ["lte-s5", "lte-s8"]
    reasons = next(item["reason"] for item in rec["recommended_profiles"] if item["profile"] == "lte-s5")
    assert any("protocol evidence is partial; resolved peer hints strongly suggest S5/S8 context" in reason for reason in reasons)


def test_plain_gtp_without_gtpv2_does_not_promote_lte_s5_s8() -> None:
    """Plain GTPv1 (no GTPv2) with S5/S8 peer hints: lte-s5/s8 must NOT be in top-3.
    The legacy-2g3g-gprs domain must be inferred; lte-eps must not appear.
    If lte-s5 appears at all it must be low confidence."""
    result = _mock_result(
        {"gtp": 80, "udp": 80, "ip": 80},
        {"udp": 80},
        ["gtp", "udp", "ip"],
    )
    result.metadata.resolved_peers = [
        {"ip": "10.0.0.1", "name": "S5-S8-PGW-01", "role": "pgw"},
        {"ip": "10.0.0.2", "name": "S5-S8-SGW-01", "role": "sgw"},
    ]
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=6)

    # Domain inference must favor legacy-2g3g-gprs, not lte-eps
    domain_names = [d["domain"] for d in rec["suspected_domains"]]
    assert "legacy-2g3g-gprs" in domain_names, f"Expected legacy-2g3g-gprs domain: {domain_names}"
    assert "lte-eps" not in domain_names, f"lte-eps must not appear for plain GTPv1: {domain_names}"

    # Legacy GTPv1 profiles must lead — lte-s5/s8 must not be in top-2
    top2 = [item["profile"] for item in rec["recommended_profiles"][:2]]
    assert "lte-s5" not in top2, f"lte-s5 must not lead for plain GTPv1: {top2}"
    assert "lte-s8" not in top2, f"lte-s8 must not lead for plain GTPv1: {top2}"
    # 2g3g legacy profiles must dominate top-2
    assert all(n.startswith("2g3g-") for n in top2), (
        f"Legacy 2g3g profiles must occupy top-2 for plain GTPv1: {top2}"
    )

    # If lte-s5 appears at all, it must be low confidence (heavily gated) and below legacy
    lte_s5 = next((item for item in rec["recommended_profiles"] if item["profile"] == "lte-s5"), None)
    if lte_s5 is not None:
        assert lte_s5["confidence"] == "low", f"lte-s5 must be low confidence for plain GTPv1: {lte_s5}"
        # lte-s5 score must be below the leading legacy profile
        top_score = rec["recommended_profiles"][0]["score"]
        assert lte_s5["score"] < top_score, (
            f"lte-s5 ({lte_s5['score']:.2f}) must be below leading legacy ({top_score:.2f})"
        )


def test_generic_sbi_trace_prefers_generic_profiles_over_many_specific_interfaces() -> None:
    result = _mock_result(
        {"http": 90, "json": 60, "tcp": 100, "ip": 100},
        {"tcp": 100},
        ["http", "json", "tcp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=10)
    names = [item["profile"] for item in rec["recommended_profiles"][:6]]
    assert names[:2] == ["5g-sbi", "5g-core"]
    assert names.count("5g-sbi") == 1


def test_diameter_with_ims_hints_can_raise_ims_profiles() -> None:
    result = _mock_result(
        {"diameter": 200, "sctp": 200, "sip": 30, "dns": 20, "ip": 220},
        {"sctp": 200},
        ["diameter", "sctp", "sip", "dns", "ip"],
    )
    result.metadata.resolved_peers = [
        {"ip": "10.0.0.1", "name": "IMS-CSCF-01", "role": "cscf"},
        {"ip": "10.0.0.2", "name": "IMS-HSS-01", "role": "hss"},
    ]
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
    ims = [item for item in rec["recommended_profiles"] if item["profile"] in {"volte-diameter-cx", "volte-ims-core"}]
    assert ims
    assert any(item["score"] > 4.0 for item in ims)
    assert any(
        "IMS" in " ".join(item["reason"]) or "cscf" in " ".join(item["reason"]).lower()
        for item in ims
    )


def test_mixed_legacy_and_modern_trace_surfaces_multiple_domains() -> None:
    result = _mock_result(
        {"sccp": 120, "tcap": 70, "mtp3": 70, "diameter": 80, "sctp": 80, "ip": 150},
        {"sctp": 80},
        ["sccp", "tcap", "mtp3", "diameter", "sctp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
    domains = [item["domain"] for item in rec["suspected_domains"]]
    assert "legacy-2g3g" in domains
    assert "lte-eps" in domains


def test_lte_voice_mix_prefers_volte_over_vonr_when_primary_domain_is_lte() -> None:
    result = _mock_result(
        {"s1ap": 240, "nas-eps": 80, "sctp": 320, "sip": 50, "dns": 30, "ip": 320},
        {"sctp": 320},
        ["s1ap", "nas-eps", "sctp", "sip", "dns", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=12)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    first_volte = next(i for i, name in enumerate(names) if name.startswith("volte-"))
    first_vonr = next(i for i, name in enumerate(names) if name.startswith("vonr-"))
    assert first_volte < first_vonr


def test_sip_sdp_call_flow_prefers_call_profile_over_register_profile() -> None:
    result = _mock_result(
        {"sip": 220, "sdp": 150, "dns": 40, "tcp": 220, "ip": 220},
        {"tcp": 220},
        ["sip", "sdp", "dns", "tcp", "ip"],
        resolved_peers=[
            {"name": "pcscf.ims.example.net", "role": "pcscf"},
            {"name": "scscf.ims.example.net", "role": "scscf"},
        ],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=10)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert names.index("volte-sip-call") < names.index("volte-sip-register")


def test_registration_flavored_ims_trace_prefers_register_over_call() -> None:
    result = _mock_result(
        {"sip": 220, "dns": 120, "diameter": 120, "sctp": 120, "tcp": 220, "ip": 220},
        {"sctp": 120, "tcp": 220},
        ["sip", "dns", "diameter", "sctp", "tcp", "ip"],
        resolved_peers=[
            {"name": "pcscf.ims.mnc001.mcc262.3gppnetwork.org", "role": "pcscf"},
            {"name": "ims-hss-01", "role": "hss"},
        ],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=10)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert "volte-sip-register" in names
    if "volte-sip-call" in names:
        assert names.index("volte-sip-register") < names.index("volte-sip-call")
    if "volte-sbc" in names:
        assert names.index("volte-ims-core") < names.index("volte-sbc")


def test_sbc_peer_hints_raise_sbc_profile_above_other_specializations() -> None:
    result = _mock_result(
        {"sip": 180, "sdp": 120, "dns": 30, "tcp": 180, "ip": 180},
        {"tcp": 180},
        ["sip", "sdp", "dns", "tcp", "ip"],
        resolved_peers=[
            {"name": "ims-sbc-edge-01", "role": "sbc"},
            {"name": "pcscf.ims.example.net", "role": "pcscf"},
        ],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=10)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert names.index("volte-sbc") < names.index("volte-sip-register")


def test_sctp_icmp_transport_trace_does_not_emit_gn_candidate() -> None:
    result = _mock_result(
        {"icmp": 20, "ip": 500},
        {"sctp": 500},
        ["icmp", "sctp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=12)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert "2g3g-gn" not in names


def test_lte_candidates_marked_as_side_signals_in_5g_trace() -> None:
    result = _mock_result(
        {"ip": 497, "dtap": 3},
        {"sctp": 500},
        ["ip", "dtap", "ngap", "nas-5gs", "nas-eps", "sctp", "nr-rrc", "gsm_a.dtap"],
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles, limit=12)
    names = [r["profile"] for r in rec["recommended_profiles"]]
    assert names.index("5g-n2") < names.index("lte-s1")
    assert names.index("5g-core") < names.index("lte-s1")

    lte_reason = next(r["reason"] for r in rec["recommended_profiles"] if r["profile"] == "lte-s1")
    assert lte_reason[0].startswith("treated as cross-generation side signal")
    assert any("cross-generation side signal" in reason for reason in lte_reason)


def test_low_level_context_protocols_do_not_drive_domains_or_candidates() -> None:
    result = _mock_result(
        {"ip": 400, "ethertype": 200, "vlan": 200, "ipcp": 40, "pap": 10},
        None,
        ["eth", "ethertype", "vlan", "ip", "ipcp", "pap"],
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles)
    assert infer_domains(result) == []
    assert rec["recommended_profiles"] == []


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
    assert rec["suspected_domains"][0]["reason"]


# ---------------------------------------------------------------------------
# GTPv1 modeling tests (Issue 2 + Issue 3)
# ---------------------------------------------------------------------------

def test_plain_gtp_without_gtpv2_infers_legacy_domain() -> None:
    """Plain 'gtp' (GTPv1 TShark name) without gtpv2 must infer legacy-2g3g-gprs domain."""
    result = _mock_result(
        {"gtp": 200, "udp": 200, "ip": 200},
        {"udp": 200},
        ["gtp", "udp", "ip"],
    )
    domains = infer_domains(result)
    domain_names = [d["domain"] for d in domains]
    assert "legacy-2g3g-gprs" in domain_names, (
        f"Expected legacy-2g3g-gprs from plain gtp+udp: {domain_names}"
    )
    assert "lte-eps" not in domain_names, (
        f"lte-eps must not appear for plain gtp without gtpv2: {domain_names}"
    )
    legacy = next(d for d in domains if d["domain"] == "legacy-2g3g-gprs")
    assert legacy["score"] >= 0.35, f"legacy-2g3g-gprs score too low: {legacy['score']}"


def test_plain_gtp_domain_reason_mentions_no_gtpv2() -> None:
    """Domain reason for plain gtp must mention the absence of GTPv2 / Gn/Gp ambiguity."""
    result = _mock_result(
        {"gtp": 150, "udp": 150, "ip": 150},
        {"udp": 150},
    )
    domains = infer_domains(result)
    legacy = next((d for d in domains if d["domain"] == "legacy-2g3g-gprs"), None)
    assert legacy is not None, f"Expected legacy-2g3g-gprs: {domains}"
    reasons_text = " ".join(legacy["reason"]).lower()
    assert "gtp" in reasons_text, f"Reason must mention gtp: {legacy['reason']}"
    assert any(kw in reasons_text for kw in ("legacy", "gn", "gp", "ambiguous", "v1")), (
        f"Reason must indicate legacy/Gn/Gp context: {legacy['reason']}"
    )


def test_gtpv2_eps_trace_does_not_infer_legacy_domain() -> None:
    """GTPv2 trace must infer lte-eps, not legacy-2g3g-gprs."""
    result = _mock_result(
        {"gtpv2": 120, "udp": 120, "ip": 120},
        {"udp": 120},
        ["gtpv2", "udp", "ip"],
    )
    domains = infer_domains(result)
    domain_names = [d["domain"] for d in domains]
    assert "lte-eps" in domain_names, f"Expected lte-eps from gtpv2+udp: {domain_names}"
    assert "legacy-2g3g-gprs" not in domain_names, (
        f"legacy-2g3g-gprs must not appear when gtpv2 is present: {domain_names}"
    )


def test_gtpv2_eps_trace_excludes_2g3g_gn_from_candidates() -> None:
    """Clear GTPv2/EPS trace must not carry 2g3g-gn in recommended profiles."""
    result = _mock_result(
        {"gtpv2": 120, "udp": 120, "gtp": 50, "ip": 120},
        {"udp": 120},
        ["gtpv2", "gtp", "udp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=12)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert "2g3g-gn" not in names, (
        f"2g3g-gn must not appear in EPS/GTPv2 Inspect results: {names}"
    )


def test_gtpv2_present_zeros_out_2g3g_gn_even_with_gtp_userplane() -> None:
    """GTPv2 + GTP user-plane: 2g3g-gn must be suppressed (GTP-U is LTE bearer, not legacy Gn)."""
    result = _mock_result(
        {"gtpv2": 100, "gtp": 80, "udp": 180, "ip": 200},
        {"udp": 180},
        ["gtpv2", "gtp", "udp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=12)
    names = [item["profile"] for item in rec["recommended_profiles"]]
    assert "2g3g-gn" not in names, (
        f"2g3g-gn must not appear when gtpv2 is the control plane: {names}"
    )
    # lte-eps domain must be recognized
    domain_names = [d["domain"] for d in rec["suspected_domains"]]
    assert "lte-eps" in domain_names, f"Expected lte-eps domain: {domain_names}"


def test_lte_s5_s8_heavily_downranked_for_gtp_without_gtpv2() -> None:
    """lte-s5/lte-s8 score must be heavily reduced when gtp is present but gtpv2 is absent."""
    result = _mock_result(
        {"gtp": 200, "udp": 200, "ip": 200},
        {"udp": 200},
        ["gtp", "udp", "ip"],
    )
    profiles = load_all_profiles()
    rec = recommend_profiles_from_inspect(result, profiles, limit=12)
    for name in ("lte-s5", "lte-s8"):
        candidate = next((item for item in rec["recommended_profiles"] if item["profile"] == name), None)
        if candidate is not None:
            assert candidate["score"] < 3.0, (
                f"{name} scored {candidate['score']} for plain GTPv1 — expected < 3.0"
            )


# ---------------------------------------------------------------------------
# 5G SA side signal tests (Issue 4)
# ---------------------------------------------------------------------------

def test_vonr_n1_n2_voice_suppressed_in_5g_sa_without_sip() -> None:
    """5G SA trace with DNS but no SIP/RTP: vonr-n1-n2-voice must be downranked."""
    result = _mock_result(
        {"ngap": 400, "nas-5gs": 80, "dns": 50, "sctp": 400, "udp": 50, "ip": 500},
        {"sctp": 400, "udp": 50},
        ["ngap", "nas-5gs", "dns", "sctp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=12)
    names = [r["profile"] for r in rec["recommended_profiles"]]
    core_idx = next(i for i, n in enumerate(names) if n.startswith("5g-"))
    if "vonr-n1-n2-voice" in names:
        vonr_idx = names.index("vonr-n1-n2-voice")
        assert core_idx < vonr_idx, (
            f"vonr-n1-n2-voice must rank below 5G core profiles: {names[:6]}"
        )
        vonr = next(r for r in rec["recommended_profiles"] if r["profile"] == "vonr-n1-n2-voice")
        assert any("voice profile downranked" in reason or "no SIP/IMS" in reason
                   for reason in vonr["reason"]), (
            f"vonr-n1-n2-voice must carry a downrank reason: {vonr['reason']}"
        )


def test_lte_s1_suppressed_in_strong_5g_sa_without_lte_anchor() -> None:
    """5G SA trace without s1ap/diameter/gtpv2: lte-s1 must be heavily penalized."""
    result = _mock_result(
        {"ngap": 400, "nas-5gs": 100, "sctp": 500, "ip": 500},
        {"sctp": 500},
        ["ngap", "nas-5gs", "sctp", "ip"],
    )
    rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=12)
    names = [r["profile"] for r in rec["recommended_profiles"]]

    first_5g = next((i for i, n in enumerate(names) if n.startswith("5g-")), 999)
    lte_s1_entry = next((r for r in rec["recommended_profiles"] if r["profile"] == "lte-s1"), None)

    if lte_s1_entry is not None:
        lte_s1_idx = names.index("lte-s1")
        assert first_5g < lte_s1_idx, (
            f"lte-s1 must rank below 5G profiles in pure 5G SA trace: {names[:8]}"
        )
        assert any(
            "suppressed" in reason or "5G SA" in reason or "cross-generation" in reason
            for reason in lte_s1_entry["reason"]
        ), f"lte-s1 must carry a suppression reason: {lte_s1_entry['reason']}"
