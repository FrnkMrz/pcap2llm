from pcap2llm.profiles import load_profile


def test_load_lte_core_profile() -> None:
    profile = load_profile("lte-core")
    assert profile.name == "lte-core"
    assert "diameter" in profile.relevant_protocols
    assert profile.default_privacy_modes["token"] == "remove"
