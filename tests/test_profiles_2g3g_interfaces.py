from pcap2llm.profiles import load_profile


PROFILE_EXPECTATIONS = {
    "2g3g-gn": "gtpv1",
    "2g3g-gp": "gtpv1",
    "2g3g-gr": "map",
    "2g3g-gs": "bssap+",
    "2g3g-geran": "bssap",
    "2g3g-dns": "dns",
    "2g3g-map-core": "map",
    "2g3g-cap": "cap",
    "2g3g-bssap": "bssap",
    "2g3g-isup": "isup",
    "2g3g-sccp-mtp": "sccp",
}


def test_2g3g_interface_profiles_load() -> None:
    for name, top in PROFILE_EXPECTATIONS.items():
        profile = load_profile(name)
        assert profile.name == name
        assert top in profile.relevant_protocols
        assert profile.summary_heuristics
        assert profile.tshark is not None


def test_2g3g_interface_profiles_have_quality_basics() -> None:
    for name in PROFILE_EXPECTATIONS:
        profile = load_profile(name)
        assert profile.description.strip()
        assert profile.top_protocol_priority
        assert profile.protocol_aliases
        assert profile.reduced_transport_fields
        top = profile.top_protocol_priority[0]
        assert top in profile.relevant_protocols
        assert (
            top in profile.full_detail_fields
            or top in profile.verbatim_protocols
        )


def test_2g3g_profiles_do_not_pull_in_utran_or_lte_language() -> None:
    banned_terms = ("utran", "iu-", "rnc", "ranap", "lte", "s1ap", "ngap")
    for name in PROFILE_EXPECTATIONS:
        profile = load_profile(name)
        description = profile.description.lower()
        assert not any(term in description for term in banned_terms), name


def test_2g3g_gn_and_gp_are_not_identical() -> None:
    gn = load_profile("2g3g-gn")
    gp = load_profile("2g3g-gp")
    assert gn.description != gp.description
    assert gn.summary_heuristics != gp.summary_heuristics


def test_2g3g_gr_and_map_core_are_not_identical() -> None:
    gr = load_profile("2g3g-gr")
    map_core = load_profile("2g3g-map-core")
    assert gr.description != map_core.description
    assert gr.summary_heuristics != map_core.summary_heuristics


def test_2g3g_geran_and_bssap_are_not_identical() -> None:
    geran = load_profile("2g3g-geran")
    bssap = load_profile("2g3g-bssap")
    assert geran.description != bssap.description
    assert geran.summary_heuristics != bssap.summary_heuristics


def test_2g3g_isup_and_sccp_mtp_are_not_identical() -> None:
    isup = load_profile("2g3g-isup")
    sccp_mtp = load_profile("2g3g-sccp-mtp")
    assert isup.description != sccp_mtp.description
    assert isup.top_protocol_priority[0] != sccp_mtp.top_protocol_priority[0]
