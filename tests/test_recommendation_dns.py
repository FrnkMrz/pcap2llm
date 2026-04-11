"""Tests for discovery fine-tuning: DNS family spread, classification_notes,
mixed-domain roles, legacy profile gates, and reason deduplication."""
from __future__ import annotations

from pcap2llm.inspect_enrichment import enrich_inspect_result
from pcap2llm.models import CaptureMetadata, InspectResult
from pcap2llm.profiles import load_all_profiles


def _make_inspect_result(
    protocol_counts: dict,
    transport_counts: dict | None = None,
    raw_protocols: list[str] | None = None,
    resolved_peers: list[dict] | None = None,
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
