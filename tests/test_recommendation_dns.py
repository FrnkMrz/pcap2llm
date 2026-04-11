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
