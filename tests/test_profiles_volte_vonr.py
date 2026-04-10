from pcap2llm.profiles import load_profile


PROFILE_EXPECTATIONS = {
    "volte-sip": "sip",
    "volte-sip-register": "sip",
    "volte-sip-call": "sip",
    "volte-diameter-cx": "diameter",
    "volte-diameter-rx": "diameter",
    "volte-diameter-sh": "diameter",
    "volte-dns": "dns",
    "volte-rtp-signaling": "sip",
    "volte-sbc": "sip",
    "volte-ims-core": "sip",
    "vonr-sip": "sip",
    "vonr-sip-register": "sip",
    "vonr-sip-call": "sip",
    "vonr-ims-core": "sip",
    "vonr-policy": "http",
    "vonr-dns": "dns",
    "vonr-n1-n2-voice": "ngap",
    "vonr-sbi-auth": "http",
    "vonr-sbi-pdu": "http",
    "vonr-sbc": "sip",
}


def test_voice_profiles_load() -> None:
    for name, top in PROFILE_EXPECTATIONS.items():
        profile = load_profile(name)
        assert profile.name == name
        assert top in profile.relevant_protocols
        assert profile.summary_heuristics
        assert profile.tshark is not None


def test_voice_profiles_have_quality_basics() -> None:
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


def test_voice_loader_accepts_yaml_suffix() -> None:
    assert load_profile("volte-sip.yaml").name == "volte-sip"
    assert load_profile("vonr-sbi-auth.yaml").name == "vonr-sbi-auth"


def test_volte_profiles_stay_out_of_5gs_language() -> None:
    banned_terms = ("5gs", "5g nr", "vonr", "ngap", "nas-5gs", "http/2 sbi")
    for name in [n for n in PROFILE_EXPECTATIONS if n.startswith("volte-")]:
        profile = load_profile(name)
        description = profile.description.lower()
        assert not any(term in description for term in banned_terms), name


def test_vonr_profiles_stay_out_of_eps_language() -> None:
    banned_terms = ("eps", "volte", "s1ap", "lte / eps", "lte/eps")
    for name in [n for n in PROFILE_EXPECTATIONS if n.startswith("vonr-")]:
        profile = load_profile(name)
        description = profile.description.lower()
        assert not any(term in description for term in banned_terms), name


def test_volte_sip_profiles_are_distinct() -> None:
    generic = load_profile("volte-sip")
    register = load_profile("volte-sip-register")
    call = load_profile("volte-sip-call")
    assert generic.summary_heuristics != register.summary_heuristics
    assert generic.summary_heuristics != call.summary_heuristics
    assert register.summary_heuristics != call.summary_heuristics
    assert generic.description != register.description
    assert generic.description != call.description


def test_vonr_sip_profiles_are_distinct() -> None:
    generic = load_profile("vonr-sip")
    register = load_profile("vonr-sip-register")
    call = load_profile("vonr-sip-call")
    assert generic.summary_heuristics != register.summary_heuristics
    assert generic.summary_heuristics != call.summary_heuristics
    assert register.summary_heuristics != call.summary_heuristics
    assert generic.description != register.description
    assert generic.description != call.description


def test_volte_diameter_profiles_are_distinct_and_verbatim() -> None:
    cx = load_profile("volte-diameter-cx")
    rx = load_profile("volte-diameter-rx")
    sh = load_profile("volte-diameter-sh")
    assert "diameter" in cx.verbatim_protocols
    assert "diameter" in rx.verbatim_protocols
    assert "diameter" in sh.verbatim_protocols
    assert cx.summary_heuristics != rx.summary_heuristics
    assert cx.summary_heuristics != sh.summary_heuristics
    assert rx.summary_heuristics != sh.summary_heuristics


def test_volte_and_vonr_dns_are_not_the_same_context() -> None:
    volte = load_profile("volte-dns")
    vonr = load_profile("vonr-dns")
    assert volte.description != vonr.description
    assert volte.summary_heuristics != vonr.summary_heuristics


def test_sbc_profiles_are_voice_sbc_not_cell_broadcast_sbc() -> None:
    volte = load_profile("volte-sbc")
    vonr = load_profile("vonr-sbc")
    assert "session border controller" in volte.description.lower()
    assert "session border controller" in vonr.description.lower()
    assert "cell broadcast" not in volte.description.lower()
    assert "cell broadcast" not in vonr.description.lower()


def test_broad_voice_profiles_remain_broad_but_voice_specific() -> None:
    volte = load_profile("volte-ims-core")
    vonr = load_profile("vonr-ims-core")
    assert "diameter" in volte.relevant_protocols
    assert "http" in vonr.relevant_protocols
    assert "voice" in volte.description.lower()
    assert "voice" in vonr.description.lower()
    assert "5gs" in vonr.description.lower()
