from pcap2llm.profiles import load_profile


def test_load_lte_core_profile() -> None:
    profile = load_profile("lte-core")
    assert profile.name == "lte-core"
    assert "diameter" in profile.relevant_protocols
    assert profile.default_privacy_modes is None


def test_load_5g_core_profile() -> None:
    profile = load_profile("5g-core")
    assert profile.name == "5g-core"
    assert "pfcp" in profile.relevant_protocols
    assert profile.protocol_aliases["http"] == ["http2", "http"]


def test_load_2g3g_ss7_geran_profile() -> None:
    profile = load_profile("2g3g-ss7-geran")
    assert profile.name == "2g3g-ss7-geran"
    assert "map" in profile.relevant_protocols
    assert profile.protocol_aliases["map"] == ["gsm_map", "map"]


def test_load_profile_accepts_yaml_suffix() -> None:
    profile = load_profile("lte-s6a.yaml")
    assert profile.name == "lte-s6a"
    assert "diameter" in profile.verbatim_protocols


def test_load_lte_interface_profiles() -> None:
    expected = {
        "lte-s1": "s1ap",
        "lte-s1-nas": "nas-eps",
        "lte-s6a": "diameter",
        "lte-s11": "gtpv2",
        "lte-s10": "gtpv2",
        "lte-sgs": "sgsap",
        "lte-s5": "gtpv2",
        "lte-s8": "gtpv2",
        "lte-dns": "dns",
        "lte-sbc-cbc": "sbcap",
    }
    for name, expected_protocol in expected.items():
        profile = load_profile(name)
        assert profile.name == name
        assert expected_protocol in profile.relevant_protocols
        assert profile.summary_heuristics
        assert profile.reduced_transport_fields


def test_lte_interface_profiles_have_quality_basics() -> None:
    names = [
        "lte-s1",
        "lte-s1-nas",
        "lte-s6a",
        "lte-s11",
        "lte-s10",
        "lte-sgs",
        "lte-s5",
        "lte-s8",
        "lte-dns",
        "lte-sbc-cbc",
    ]
    for name in names:
        profile = load_profile(name)
        assert profile.description.strip()
        assert profile.top_protocol_priority
        assert profile.protocol_aliases
        assert profile.tshark is not None
        top = profile.top_protocol_priority[0]
        assert top in profile.relevant_protocols
        assert (
            top in profile.full_detail_fields
            or top in profile.verbatim_protocols
        )
