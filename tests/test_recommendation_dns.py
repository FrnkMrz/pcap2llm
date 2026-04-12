"""Tests for discovery fine-tuning: DNS family spread, classification_notes,
mixed-domain roles, legacy profile gates, reason deduplication,
and classification_state (final fine-tuning round)."""
from __future__ import annotations

from pcap2llm.inspect_enrichment import enrich_inspect_result
from pcap2llm.models import CaptureMetadata, InspectResult
from pcap2llm.profiles import load_all_profiles
from pcap2llm.recommendation import infer_domains, recommend_profiles_from_inspect


def _make_inspect_result(
    protocol_counts: dict,
    transport_counts: dict | None = None,
    raw_protocols: list[str] | None = None,
    resolved_peers: list[dict] | None = None,
    dns_qry_names: list[str] | None = None,
) -> InspectResult:
    total = sum(protocol_counts.values()) or 1
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
            dns_qry_names=dns_qry_names or [],
        ),
        protocol_counts=protocol_counts,
        transport_counts=transport_counts or {},
        conversations=[],
        anomalies=[],
    )


class TestDiscoveryFinetuning:
    """Six fine-tuning tests for discovery scoring and classification_notes."""

    def test_a_dns_only_family_ambiguous(self) -> None:
        """DNS-only trace: family-specific DNS profiles (volte-dns etc.) must score very low."""
        result = _make_inspect_result({"dns": 500, "udp": 500, "ip": 1000})
        enriched = enrich_inspect_result(result, load_all_profiles())
        # Family-specific DNS profiles must be either absent from top-4 or score very low
        top_profiles = [p["profile"] for p in enriched.candidate_profiles[:4]]
        if "volte-dns" in top_profiles:
            volte_score = next(
                p["score"] for p in enriched.candidate_profiles if p["profile"] == "volte-dns"
            )
            assert volte_score < 2.0, f"volte-dns scored {volte_score} in DNS-only trace, expected < 2.0"
        # DNS-only classification note should be present
        assert any(
            "dns" in note.lower() or "DNS" in note
            for note in enriched.classification_notes
        ), f"No DNS classification note found. Notes: {enriched.classification_notes}"

    def test_b_dns_with_ims_peer_hint_raises_volte_dns(self) -> None:
        """DNS trace with an IMS peer hint (pcscf hostname) should allow volte-dns to score higher."""
        result = _make_inspect_result(
            {"dns": 500, "udp": 500},
            resolved_peers=[{"name": "pcscf.ims.mnc001.mcc262.3gppnetwork.org", "role": "pcscf"}],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        volte_dns = next(
            (p for p in enriched.candidate_profiles if p["profile"] == "volte-dns"), None
        )
        assert volte_dns is not None, "volte-dns not found in candidates"
        assert volte_dns["score"] > 1.0, (
            f"volte-dns scored {volte_dns['score']} with IMS peer hint, expected > 1.0"
        )

    def test_c_host_hint_only_gtp_classification_note(self) -> None:
        """GTP with host hints only should produce a classification note about host hints."""
        result = _make_inspect_result(
            {"gtp": 200, "udp": 200},
            resolved_peers=[{"name": "s5-pgw.example.com", "role": "pgw"}],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        assert any(
            "host hint" in note.lower()
            for note in enriched.classification_notes
        ), f"No host-hint classification note found. Notes: {enriched.classification_notes}"

    def test_d_mixed_legacy_lte_domains_with_roles(self) -> None:
        """MAP+TCAP+SCCP + some Diameter should produce mixed_domain; domains have role field."""
        result = _make_inspect_result(
            {"map": 100, "tcap": 80, "sccp": 90, "diameter": 30, "sctp": 30}
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        assert enriched.trace_shape == "mixed_domain", (
            f"Expected mixed_domain, got {enriched.trace_shape}"
        )
        domains = {d["domain"]: d for d in enriched.suspected_domains}
        assert "legacy-2g3g" in domains, (
            f"legacy-2g3g not in suspected_domains: {list(domains.keys())}"
        )
        assert "role" in domains["legacy-2g3g"], "role field missing from legacy-2g3g domain"
        assert domains["legacy-2g3g"]["role"] in ("primary", "secondary"), (
            f"Unexpected role: {domains['legacy-2g3g']['role']}"
        )

    def test_e_map_tcap_sccp_without_isup_bssap_keeps_isup_out_of_top(self) -> None:
        """MAP+TCAP+SCCP without ISUP/BSSAP must not surface isup profiles in top-5."""
        result = _make_inspect_result({"map": 100, "tcap": 80, "sccp": 90, "mtp3": 50})
        enriched = enrich_inspect_result(result, load_all_profiles())
        top_profiles = [p["profile"] for p in enriched.candidate_profiles[:5]]
        assert "2g3g-isup" not in top_profiles, (
            f"2g3g-isup should not appear in top-5 without ISUP evidence: {top_profiles}"
        )
        # A map/gr/sccp oriented profile should be present
        assert any(
            "map" in p or "gr" in p or "sccp" in p for p in top_profiles
        ), f"Expected a MAP/GR/SCCP profile in top-5: {top_profiles}"

    def test_f_reason_texts_no_duplicates(self) -> None:
        """No candidate profile should have duplicate reason strings."""
        result = _make_inspect_result({"diameter": 100, "sctp": 100})
        enriched = enrich_inspect_result(result, load_all_profiles())
        for prof in enriched.candidate_profiles:
            reasons = prof.get("reason", [])
            assert len(reasons) == len(set(reasons)), (
                f"Duplicate reasons in {prof['profile']}: {reasons}"
            )


class TestFinalFineTuning:
    """Tests for the final fine-tuning round: classification_state, role cleanup,
    DNS gate for lte-dns/5g-dns, and reason dedup in infer_domains."""

    def test_a_dns_only_classification_state_ambiguous_support(self) -> None:
        """DNS-only trace must produce classification_state='ambiguous_support'."""
        result = _make_inspect_result({"dns": 900, "udp": 900, "ip": 1800})
        enriched = enrich_inspect_result(result, load_all_profiles())
        assert enriched.classification_state == "ambiguous_support", (
            f"Expected ambiguous_support, got {enriched.classification_state}"
        )
        # No broad voice/SIP promotion — volte-sip/sbc should not be in top-4
        top_4 = [p["profile"] for p in enriched.candidate_profiles[:4]]
        assert "volte-sip" not in top_4, f"volte-sip should not appear in top-4 for DNS-only: {top_4}"
        assert "volte-sbc" not in top_4, f"volte-sbc should not appear in top-4 for DNS-only: {top_4}"
        # lte-dns and 5g-dns should be gated below their ungated score of 5.20
        for cand in enriched.candidate_profiles:
            if cand["profile"] in ("lte-dns", "5g-dns"):
                assert cand["score"] < 5.0, (
                    f"{cand['profile']} scored {cand['score']} for DNS-only, expected < 5.0 (gated)"
                )

    def test_b_single_domain_never_tagged_secondary(self) -> None:
        """A trace with exactly one suspected domain must have role='primary', never 'secondary'."""
        # Pure diameter → single lte-eps domain
        result = _make_inspect_result({"diameter": 500, "sctp": 500})
        domains = infer_domains(result)
        assert len(domains) >= 1
        for d in domains:
            assert d.get("role") != "secondary", (
                f"Single-domain trace must not have role=secondary: {domains}"
            )
        # DNS-only → single dns-support domain
        result2 = _make_inspect_result({"dns": 400, "udp": 400})
        domains2 = infer_domains(result2)
        assert len(domains2) == 1
        assert domains2[0].get("role") == "primary", (
            f"Single dns-support domain should have role=primary: {domains2}"
        )

    def test_c_mixed_domain_roles_remain(self) -> None:
        """Mixed modern+legacy trace must produce multiple domains, each with a role field.

        Co-dominant domains (both scoring >= 0.7) may both receive 'primary'.
        The important invariant is: every domain entry in a multi-domain result has a role.
        """
        # map+tcap+sccp fires the legacy-2g3g combo; ngap+nas-5gs fires 5g-sa-core
        result = _make_inspect_result({"ngap": 200, "nas-5gs": 150, "map": 80, "tcap": 70, "sccp": 80})
        domains = infer_domains(result)
        assert len(domains) >= 2, f"Expected mixed domains, got: {domains}"
        # Every domain must have a role when multiple domains are present
        for d in domains:
            assert "role" in d, f"Domain missing role field in multi-domain result: {d}"
            assert d["role"] in ("primary", "secondary", "supporting"), (
                f"Unexpected role value: {d['role']}"
            )
        # At least one primary must exist
        assert any(d["role"] == "primary" for d in domains), (
            f"No primary domain in mixed trace: {domains}"
        )

    def test_d_ims_diameter_no_duplicate_downrank_reasons(self) -> None:
        """Diameter-only trace: IMS Diameter profiles must not stack near-duplicate downrank reasons."""
        result = _make_inspect_result({"diameter": 300, "sctp": 300})
        enriched = enrich_inspect_result(result, load_all_profiles())
        for cand in enriched.candidate_profiles:
            if "ims" in cand["profile"] or "volte-diameter" in cand["profile"]:
                reasons = cand.get("reason", [])
                # Count how many reasons contain "downranked"
                downrank_reasons = [r for r in reasons if "downranked" in r]
                assert len(downrank_reasons) <= 1, (
                    f"{cand['profile']} has {len(downrank_reasons)} downranked reasons: {downrank_reasons}"
                )

    def test_e_gtp_host_hint_only_classification_state_partial(self) -> None:
        """Weak GTP trace with S5/S8 peer names only → classification_state='partial'."""
        result = _make_inspect_result(
            {"gtp": 100, "udp": 100},
            resolved_peers=[
                {"name": "s5-pgw.roaming.example.com", "role": "pgw"},
                {"name": "s8-sgw.example.com", "role": "sgw"},
            ],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        assert enriched.classification_state in ("partial", "ambiguous_support"), (
            f"Expected partial or ambiguous_support, got {enriched.classification_state}"
        )
        # Should carry a classification note about low confidence
        has_note = any(
            "host hint" in note.lower() or "partial" in note.lower()
            for note in enriched.classification_notes
        )
        assert has_note, f"No low-confidence note found. Notes: {enriched.classification_notes}"


class TestDnsSupportSuppression:
    """Bug fix: dns-support domain must be suppressed when a primary telecom domain is present.

    The bare (frozenset({"dns"}), "dns-support") combo rule fires for any trace
    that has DNS traffic — including IMS, 5G, and LTE captures where DNS is
    ancillary infrastructure.  When a stronger domain is identified, dns-support
    is noise and causes false classification_state=mixed.
    """

    def test_sip_dns_no_dns_support_alongside_ims(self) -> None:
        """sip+dns (IMS registration trace) must not surface dns-support as a domain."""
        result = _make_inspect_result({"sip": 300, "dns": 200, "udp": 300, "tcp": 200})
        domains = infer_domains(result)
        domain_names = [d["domain"] for d in domains]
        assert "ims-voice" in domain_names, f"Expected ims-voice: {domain_names}"
        assert "dns-support" not in domain_names, (
            f"dns-support must be suppressed when ims-voice is present, got: {domain_names}"
        )

    def test_sip_dns_classification_state_not_mixed(self) -> None:
        """sip+dns trace must not produce classification_state='mixed' after suppression."""
        result = _make_inspect_result({"sip": 300, "dns": 200, "udp": 300, "tcp": 200})
        enriched = enrich_inspect_result(result, load_all_profiles())
        assert enriched.classification_state != "mixed", (
            f"sip+dns must not be 'mixed' after dns-support suppression. "
            f"Got: {enriched.classification_state}, domains: {enriched.suspected_domains}"
        )

    def test_5g_dns_no_dns_support_alongside_5g_core(self) -> None:
        """5G trace with ancillary DNS must not produce dns-support as a domain."""
        result = _make_inspect_result(
            {"ngap": 400, "nas-5gs": 100, "dns": 100, "sctp": 400, "udp": 100}
        )
        domains = infer_domains(result)
        domain_names = [d["domain"] for d in domains]
        assert "dns-support" not in domain_names, (
            f"dns-support must not appear alongside 5g-sa-core: {domain_names}"
        )

    def test_lte_diameter_dns_no_dns_support(self) -> None:
        """LTE Diameter trace with DNS must not produce dns-support alongside lte-eps."""
        result = _make_inspect_result({"diameter": 200, "sctp": 200, "dns": 50, "udp": 50})
        domains = infer_domains(result)
        domain_names = [d["domain"] for d in domains]
        assert "lte-eps" in domain_names, f"Expected lte-eps: {domain_names}"
        assert "dns-support" not in domain_names, (
            f"dns-support must be suppressed when lte-eps is present: {domain_names}"
        )

    def test_dns_only_still_produces_dns_support(self) -> None:
        """DNS-only trace must still produce dns-support when no suppressor domain exists.

        Regression guard: the suppression must only remove dns-support when a
        primary domain is also present.
        """
        result = _make_inspect_result({"dns": 500, "udp": 500})
        domains = infer_domains(result)
        domain_names = [d["domain"] for d in domains]
        assert "dns-support" in domain_names, (
            f"DNS-only trace must still produce dns-support: {domain_names}"
        )

    def test_sip_sdp_dns_produces_confident_not_mixed(self) -> None:
        """sip+sdp+dns trace: ims-voice dominant, dns-support suppressed, state not mixed."""
        result = _make_inspect_result({"sip": 200, "sdp": 150, "dns": 50, "udp": 200})
        enriched = enrich_inspect_result(result, load_all_profiles())
        domain_names = [d["domain"] for d in enriched.suspected_domains]
        assert "dns-support" not in domain_names, (
            f"dns-support must be suppressed in sip+sdp+dns: {domain_names}"
        )
        assert enriched.classification_state in ("confident", "partial"), (
            f"sip+sdp+dns state should be confident or partial, got: {enriched.classification_state}"
        )


class TestCoreNameResolution:
    """Tests for the core-name-resolution cross-generation DNS profile."""

    def test_a_3gppnetwork_org_raises_core_name_resolution(self) -> None:
        """DNS trace with 3gppnetwork.org query names must raise core-name-resolution prominently."""
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            dns_qry_names=["epc.mnc001.mcc262.3gppnetwork.org", "apn.epc.mnc001.mcc262.3gppnetwork.org"],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        top = enriched.candidate_profiles[0]
        assert top["profile"] == "core-name-resolution", (
            f"Expected core-name-resolution at top, got: {[p['profile'] for p in enriched.candidate_profiles[:3]]}"
        )
        assert top["score"] > 4.0, f"Expected score > 4.0, got {top['score']}"
        assert any("3gppnetwork" in r.lower() for r in top.get("reason", [])), (
            f"Expected 3gppnetwork.org in reasons: {top.get('reason')}"
        )
        # Interpretive summary must be present as the primary reason
        assert any(
            "telecom core naming" in r.lower() or "service resolution" in r.lower()
            for r in top.get("reason", [])
        ), f"Expected interpretive summary in reasons: {top.get('reason')}"

    def test_b_gprs_domain_raises_core_name_resolution(self) -> None:
        """DNS trace with .gprs operator domains must raise core-name-resolution prominently."""
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            dns_qry_names=["operator.gprs", "mnc001.mcc262.gprs", "apn.mnc001.mcc262.gprs"],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        core = next((p for p in enriched.candidate_profiles if p["profile"] == "core-name-resolution"), None)
        assert core is not None, "core-name-resolution not found in candidates"
        assert core["score"] > 4.0, f"Expected score > 4.0 for .gprs trace, got {core['score']}"
        assert any(".gprs" in r.lower() or "gprs" in r.lower() for r in core.get("reason", [])), (
            f"Expected .gprs in reasons: {core.get('reason')}"
        )

    def test_c_mcc_mnc_naming_raises_core_name_resolution(self) -> None:
        """MCC/MNC naming pattern should strongly favor core-name-resolution."""
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            dns_qry_names=["mnc001.mcc262.3gppnetwork.org", "hss.epc.mnc001.mcc262.3gppnetwork.org"],
        )
        rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=6)
        profiles_ranked = [p["profile"] for p in rec["recommended_profiles"]]
        assert "core-name-resolution" in profiles_ranked[:2], (
            f"core-name-resolution should be in top-2 for MCC/MNC naming: {profiles_ranked}"
        )
        core = next(p for p in rec["recommended_profiles"] if p["profile"] == "core-name-resolution")
        assert any("MCC/MNC" in r or "mnc" in r.lower() or "3gppnetwork" in r.lower()
                   for r in core.get("reason", [])), (
            f"Expected MCC/MNC reason: {core.get('reason')}"
        )

    def test_d_generic_dns_does_not_strongly_raise_core_name_resolution(self) -> None:
        """Generic DNS without telecom naming must not score > 3.5 for core-name-resolution."""
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            dns_qry_names=["www.google.com", "api.example.com", "cdn.cloudflare.net"],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        core = next((p for p in enriched.candidate_profiles if p["profile"] == "core-name-resolution"), None)
        if core is not None:
            assert core["score"] < 3.5, (
                f"core-name-resolution scored {core['score']} for generic DNS — should be < 3.5"
            )
        # classification_state must still be ambiguous_support
        assert enriched.classification_state == "ambiguous_support"

    def test_e_telecom_dns_plus_lte_keeps_core_name_visible(self) -> None:
        """Telecom DNS + LTE anchor: core-name-resolution stays visible, LTE profiles may rank higher."""
        result = _make_inspect_result(
            {"dns": 200, "udp": 200, "diameter": 200, "sctp": 200},
            dns_qry_names=["epc.mnc001.mcc262.3gppnetwork.org"],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        profiles_ranked = [p["profile"] for p in enriched.candidate_profiles]
        assert "core-name-resolution" in profiles_ranked, (
            "core-name-resolution should remain in candidates even with LTE anchor"
        )
        # LTE profiles are allowed to rank above it
        core_pos = profiles_ranked.index("core-name-resolution")
        # It should be in top-6
        assert core_pos < 6, f"core-name-resolution too low at position {core_pos}: {profiles_ranked}"

    def test_f_strong_naming_suppresses_dns_family_fanout(self) -> None:
        """When core-name-resolution dominates, family-specific *-dns profiles are clearly suppressed.

        The fan-out suppression activates when core-name-resolution scores >= 5.0
        and no signaling anchor (ngap, s1ap, diameter, sip ...) is present.
        Family-specific DNS profiles should score well below core-name-resolution.
        """
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            dns_qry_names=[
                "epc.mnc001.mcc262.3gppnetwork.org",
                "ims.mnc001.mcc262.3gppnetwork.org",
            ],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        # core-name-resolution must lead
        assert enriched.candidate_profiles[0]["profile"] == "core-name-resolution", (
            f"Expected core-name-resolution at top: {[p['profile'] for p in enriched.candidate_profiles[:4]]}"
        )
        core_score = enriched.candidate_profiles[0]["score"]
        assert core_score >= 5.0, f"core-name-resolution score too low: {core_score}"
        # All family-specific DNS profiles must be clearly suppressed
        for prof in enriched.candidate_profiles:
            if prof["profile"].endswith("-dns") and prof["profile"] != "core-name-resolution":
                assert prof["score"] < 2.0, (
                    f"{prof['profile']} scored {prof['score']} — should be suppressed below 2.0 "
                    f"when core-name-resolution={core_score}"
                )

    def test_g_apn_ims_naming_raises_core_name_resolution(self) -> None:
        """DNS trace with APN/IMS/EPC MCC/MNC naming must raise core-name-resolution prominently.

        Also verifies that the interpretive summary reason is present — the output
        should explain 'telecom core naming support traffic', not just list matched strings.
        """
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            dns_qry_names=[
                "hss.epc.mnc001.mcc262.3gppnetwork.org",
                "pcscf.ims.mnc001.mcc262.3gppnetwork.org",
            ],
        )
        enriched = enrich_inspect_result(result, load_all_profiles())
        core = next(
            (p for p in enriched.candidate_profiles if p["profile"] == "core-name-resolution"), None
        )
        assert core is not None, "core-name-resolution not found in candidates"
        assert core["score"] > 4.0, (
            f"Expected score > 4.0 for APN/IMS naming trace, got {core['score']}"
        )
        # Reasons must reflect IMS, APN, or EPC evidence — not just generic DNS
        reasons = core.get("reason", [])
        assert any(
            any(kw in r.lower() for kw in ("ims", "apn", "epc", "mcc/mnc", "3gppnetwork", "mnc"))
            for r in reasons
        ), f"Expected APN/IMS/EPC naming evidence in reasons: {reasons}"
        # evidence_class must not be "weak" — real naming evidence warrants at least partial
        assert core.get("evidence_class") != "weak", (
            f"evidence_class 'weak' unexpected for APN/IMS naming trace: {core}"
        )
        # The interpretive summary reason must be present — not just pattern labels
        assert any(
            "telecom core naming" in r.lower() or "service resolution" in r.lower()
            for r in reasons
        ), f"Expected interpretive summary reason in: {reasons}"


class TestDnsNamingAwareness:
    """Tests for naming-aware DNS scoring (Issue 1).

    Verifies that telecom naming patterns materially improve core-name-resolution,
    that reason texts mention the actual matched patterns, and that the fan-out
    suppression activates at the correct threshold.
    """

    def test_supporting_evidence_names_in_reasons(self) -> None:
        """DNS trace with supporting naming patterns (pcscf, amf., nrf.) must mention
        specific pattern names in core-name-resolution reasons, not just a generic summary."""
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            resolved_peers=[
                {"name": "pcscf.ims.example.com", "role": "cscf"},
                {"name": "nrf.5gc.example.com", "role": "nrf"},
                {"name": "amf.5gc.example.com", "role": "amf"},
            ],
        )
        rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
        core = next((p for p in rec["recommended_profiles"] if p["profile"] == "core-name-resolution"), None)
        assert core is not None, "core-name-resolution must appear with telecom peer naming"
        reasons_text = " ".join(core.get("reason", [])).lower()
        # At least one specific pattern should be mentioned (not just generic summary)
        assert any(kw in reasons_text for kw in ("pcscf", "nrf", "amf", "5g nrf", "cscf", "naming")), (
            f"Expected specific pattern names in reasons: {core.get('reason')}"
        )

    def test_fanout_suppression_activates_with_single_strong_hit(self) -> None:
        """A single strong telecom naming hit (.gprs) plus good DNS must trigger fan-out suppression.

        Previously the threshold was 5.0 (requiring 2 strong hits or 1 strong + high DNS factor).
        The corrected threshold is 4.0 so that 1 strong hit with moderate DNS also suppresses
        family-specific DNS profiles.
        """
        result = _make_inspect_result(
            {"dns": 300, "udp": 300},
            dns_qry_names=["operator.gprs", "mnc001.mcc262.gprs"],
        )
        rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
        core = next((p for p in rec["recommended_profiles"] if p["profile"] == "core-name-resolution"), None)
        assert core is not None, "core-name-resolution must appear for .gprs trace"
        core_score = core["score"]
        assert core_score >= 4.0, f"core-name-resolution score {core_score} too low for .gprs"
        # Family-specific DNS profiles must be suppressed below core-name-resolution
        for prof in rec["recommended_profiles"]:
            if prof["profile"].endswith("-dns") and prof["profile"] != "core-name-resolution":
                assert prof["score"] < core_score, (
                    f"{prof['profile']} ({prof['score']:.2f}) must be below core-name-resolution "
                    f"({core_score:.2f}) after fan-out suppression"
                )

    def test_supporting_only_evidence_produces_summary_reason(self) -> None:
        """DNS trace with only supporting naming evidence (no strong 3gpp/gprs hits) must still
        produce a summary reason indicating telecom DNS context."""
        result = _make_inspect_result(
            {"dns": 400, "udp": 400},
            resolved_peers=[
                {"name": "smf.5gc.example.net", "role": "smf"},
                {"name": "udm.5gc.example.net", "role": "udm"},
                {"name": "ausf.5gc.example.net", "role": "ausf"},
            ],
        )
        rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
        core = next((p for p in rec["recommended_profiles"] if p["profile"] == "core-name-resolution"), None)
        if core is not None:
            reasons_text = " ".join(core.get("reason", [])).lower()
            assert any(kw in reasons_text for kw in ("telecom", "core", "naming", "5g", "smf", "udm", "ausf")), (
                f"Expected telecom context in reasons for supporting-only evidence: {core.get('reason')}"
            )

    def test_fanout_suppression_does_not_fire_when_anchor_present(self) -> None:
        """DNS fan-out suppression must NOT fire when a real signaling anchor is present.
        lte-dns should remain visible alongside core-name-resolution in a combined trace."""
        result = _make_inspect_result(
            {"dns": 200, "diameter": 200, "sctp": 200, "udp": 200},
            dns_qry_names=["epc.mnc001.mcc262.3gppnetwork.org"],
        )
        rec = recommend_profiles_from_inspect(result, load_all_profiles(), limit=8)
        lte_dns = next((p for p in rec["recommended_profiles"] if p["profile"] == "lte-dns"), None)
        assert lte_dns is not None, (
            "lte-dns must remain visible when diameter (LTE anchor) is present alongside DNS"
        )
        # With diameter anchor, lte-dns should not carry the suppression reason
        if lte_dns is not None:
            suppressed_reason = "downranked: telecom core naming support profile"
            assert not any(suppressed_reason in r for r in lte_dns.get("reason", [])), (
                f"lte-dns must not be fan-out suppressed when LTE anchor present: {lte_dns['reason']}"
            )


class TestProtocolCountPresentation:
    """Tests for protocol count presentation consistency (Issue 5).

    Verifies that raw-protocol entries in dominant_signaling_protocols
    get 'supporting' strength (not 'strong'), and that no entry carries
    an explicit zero count.
    """

    def test_counted_protocol_gets_strong_label(self) -> None:
        """Protocols with actual packet counts get 'strong' strength."""
        from pcap2llm.models import CaptureMetadata, InspectResult
        from pcap2llm.signaling import dominant_signaling_protocols
        result = InspectResult(
            metadata=CaptureMetadata(
                capture_file="/dev/null",
                packet_count=200,
                first_seen_epoch="1.0",
                last_seen_epoch="2.0",
                relevant_protocols=["ngap", "sctp"],
                raw_protocols=["ngap", "sctp"],
            ),
            protocol_counts={"ngap": 150, "sctp": 150},
            transport_counts={"sctp": 150},
            conversations=[],
            anomalies=[],
        )
        dominant = dominant_signaling_protocols(result)
        ngap_entry = next((item for item in dominant if item["name"] == "ngap"), None)
        assert ngap_entry is not None
        assert ngap_entry["strength"] == "strong", (
            f"Counted ngap must get 'strong' label, got {ngap_entry['strength']}"
        )
        assert ngap_entry.get("count", 0) == 150

    def test_raw_protocol_gets_supporting_label(self) -> None:
        """Protocols only in raw_protocols (count=0) get 'supporting' strength — not 'strong'."""
        from pcap2llm.models import CaptureMetadata, InspectResult
        from pcap2llm.signaling import dominant_signaling_protocols
        result = InspectResult(
            metadata=CaptureMetadata(
                capture_file="/dev/null",
                packet_count=500,
                first_seen_epoch="1.0",
                last_seen_epoch="2.0",
                relevant_protocols=["ngap", "nas-5gs", "sctp"],
                raw_protocols=["ngap", "nas-5gs", "sctp"],
            ),
            protocol_counts={"ip": 497, "dtap": 3},
            transport_counts={"sctp": 500},
            conversations=[],
            anomalies=[],
        )
        dominant = dominant_signaling_protocols(result)
        for item in dominant:
            if item["name"] in {"ngap", "nas-5gs", "nr-rrc", "nas-eps"}:
                assert item["strength"] != "strong", (
                    f"Raw-protocol '{item['name']}' must not get 'strong' label: {item}"
                )
                assert "count" not in item or item["count"] == 0, (
                    f"Raw-protocol '{item['name']}' must not carry a non-zero count: {item}"
                )

    def test_no_entry_carries_explicit_zero_count(self) -> None:
        """No dominant signaling entry may carry an explicit count of 0."""
        from pcap2llm.models import CaptureMetadata, InspectResult
        from pcap2llm.signaling import dominant_signaling_protocols
        result = InspectResult(
            metadata=CaptureMetadata(
                capture_file="/dev/null",
                packet_count=500,
                first_seen_epoch="1.0",
                last_seen_epoch="2.0",
                relevant_protocols=["ngap", "nas-5gs", "nas-eps", "nr-rrc"],
                raw_protocols=["ngap", "nas-5gs", "nas-eps", "nr-rrc"],
            ),
            protocol_counts={"ip": 500},
            transport_counts={"sctp": 500},
            conversations=[],
            anomalies=[],
        )
        dominant = dominant_signaling_protocols(result)
        for item in dominant:
            assert item.get("count", 1) != 0, (
                f"Entry {item['name']} must not have explicit count=0: {item}"
            )

    def test_raw_signal_label_in_discovery_markdown(self) -> None:
        """Discovery markdown must render raw-protocol entries with [raw signal] label."""
        from pcap2llm.discovery import build_discovery_markdown
        discovery = {
            "run": {"action": "discover"},
            "capture": {"path": "/tmp/t.pcapng", "filename": "t.pcapng",
                        "first_packet_number": None, "packet_count": 500},
            "artifact": {"version": "V_01"},
            "name_resolution": {"hosts_file_used": False, "mapping_file_used": False, "resolved_peer_count": 0},
            "resolved_peers": [],
            "capture_context": {"link_or_envelope_protocols": [], "transport_support_protocols": []},
            "protocol_summary": {
                "dominant_signaling_protocols": [
                    # counted entry
                    {"name": "ngap", "strength": "strong", "count": 150},
                    # raw-signal entry (no count)
                    {"name": "nas-5gs", "strength": "supporting"},
                ],
                "top_protocols": [],
            },
            "suspected_domains": [],
            "candidate_profiles": [],
        }
        markdown = build_discovery_markdown(discovery)
        assert "`ngap` [strong]: 150" in markdown, "Counted protocol must show count"
        assert "`nas-5gs` [raw signal]" in markdown, (
            "Raw-signal protocol must render with [raw signal] label, not [supporting]"
        )
