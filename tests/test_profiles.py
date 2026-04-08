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
