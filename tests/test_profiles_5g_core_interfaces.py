from pcap2llm.profiles import load_profile


PROFILE_EXPECTATIONS = {
    "5g-n1-n2": "ngap",
    "5g-n2": "ngap",
    "5g-nas-5gs": "nas-5gs",
    "5g-sbi": "http",
    "5g-sbi-auth": "http",
    "5g-n8": "http",
    "5g-n10": "http",
    "5g-n11": "http",
    "5g-n12": "http",
    "5g-n13": "http",
    "5g-n14": "http",
    "5g-n15": "http",
    "5g-n16": "http",
    "5g-n22": "http",
    "5g-n26": "gtpv2",
    "5g-n40": "http",
    "5g-dns": "dns",
    "5g-cbc-cbs": "sbcap",
}


def test_5g_core_interface_profiles_load() -> None:
    for name, top in PROFILE_EXPECTATIONS.items():
        profile = load_profile(name)
        assert profile.name == name
        assert top in profile.relevant_protocols
        assert profile.summary_heuristics
        assert profile.tshark is not None


def test_5g_core_interface_profiles_have_quality_basics() -> None:
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


def test_5g_profiles_do_not_pull_in_2g3g_or_lte_terms() -> None:
    banned_terms = ("utran", "ranap", "gsm_map", "bssap", "isup", "lte", "diameter", "s1ap")
    for name in PROFILE_EXPECTATIONS:
        profile = load_profile(name)
        description = profile.description.lower()
        assert not any(term in description for term in banned_terms), name


def test_5g_n1_n2_n2_and_nas_5gs_are_distinct() -> None:
    n1n2 = load_profile("5g-n1-n2")
    n2 = load_profile("5g-n2")
    nas = load_profile("5g-nas-5gs")
    assert n1n2.top_protocol_priority != n2.top_protocol_priority
    assert nas.top_protocol_priority[0] == "nas-5gs"
    assert n1n2.summary_heuristics != n2.summary_heuristics
    assert n1n2.summary_heuristics != nas.summary_heuristics


def test_5g_sbi_and_sbi_auth_are_distinct() -> None:
    sbi = load_profile("5g-sbi")
    auth = load_profile("5g-sbi-auth")
    assert sbi.description != auth.description
    assert sbi.summary_heuristics != auth.summary_heuristics


def test_5g_n11_is_narrower_than_generic_sbi() -> None:
    sbi = load_profile("5g-sbi")
    n11 = load_profile("5g-n11")
    assert sbi.description != n11.description
    assert sbi.summary_heuristics != n11.summary_heuristics


def test_5g_n26_is_explicitly_hybrid() -> None:
    n26 = load_profile("5g-n26")
    assert "gtpv2" in n26.relevant_protocols
    assert "http" in n26.relevant_protocols
    assert "hybrid" in n26.description.lower()
