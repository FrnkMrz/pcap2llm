from __future__ import annotations

from pcap2llm.visualize import build_flow_model, render_flow_svg


def _packet(packet_no: int, src_alias: str, dst_alias: str, msg_name: str) -> dict:
    return {
        "packet_no": packet_no,
        "time_rel_ms": float(packet_no * 10),
        "time_epoch": f"171239000{packet_no}.0",
        "top_protocol": "diameter",
        "src": {"alias": src_alias, "role": src_alias.lower()},
        "dst": {"alias": dst_alias, "role": dst_alias.lower()},
        "anomalies": [],
        "message": {
            "protocol": "diameter",
            "fields": {
                "message_name": msg_name,
            },
        },
    }


def _packet_with_fields(
    packet_no: int,
    src_alias: str,
    dst_alias: str,
    msg_name: str,
    fields: dict,
) -> dict:
    packet = _packet(packet_no, src_alias, dst_alias, msg_name)
    packet["message"]["fields"].update(fields)
    return packet


def test_build_flow_model_truncates_and_sets_warning() -> None:
    packets = [
        _packet(1, "AMF", "SMF", "CreateSMContext Request"),
        _packet(2, "SMF", "AMF", "CreateSMContext Response"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="5g-core",
        privacy_profile="llm-telecom-safe",
        max_events=1,
        title="5G Signaling",
    )

    assert flow["event_count_rendered"] == 1
    assert flow["event_count_uncollapsed"] == 1
    assert flow["packet_count_total"] == 2
    assert flow["warnings"]
    assert flow["title"] == "5G Signaling"


def test_build_flow_model_collapses_repeated_messages() -> None:
    packets = [
        _packet(1, "AMF", "SMF", "Nsmf_CreateSMContext Request"),
        _packet(2, "AMF", "SMF", "Nsmf_CreateSMContext Request"),
        _packet(3, "AMF", "SMF", "Nsmf_CreateSMContext Request"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="5g-core",
        privacy_profile="llm-telecom-safe",
    )

    assert flow["event_count_rendered"] == 1
    assert flow["event_count_uncollapsed"] == 3
    assert flow["events"][0]["repeat_count"] == 3


def test_build_flow_model_pairs_request_and_response() -> None:
    packets = [
        _packet_with_fields(
            1,
            "AMF",
            "SMF",
            "Create Session Request",
            {"gtpv2.seq_no": "42"},
        ),
        _packet_with_fields(
            2,
            "SMF",
            "AMF",
            "Create Session Response",
            {"gtpv2.seq_no": "42"},
        ),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-s11",
        privacy_profile=None,
    )

    first = flow["events"][0]
    second = flow["events"][1]
    assert first["paired_event_id"] == second["id"]
    assert second["paired_event_id"] == first["id"]


def test_build_flow_model_pairs_gtpv2_request_and_response_with_seq() -> None:
    packets = [
        _packet_with_fields(
            1,
            "MME",
            "SGW",
            "",
            {"gtpv2.message_type": "32", "gtpv2.seq": "42"},
        ),
        _packet_with_fields(
            2,
            "SGW",
            "MME",
            "",
            {"gtpv2.message_type": "33", "gtpv2.seq": "42"},
        ),
    ]
    del packets[0]["message"]["fields"]["message_name"]
    del packets[1]["message"]["fields"]["message_name"]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-s11",
        privacy_profile=None,
    )

    first = flow["events"][0]
    second = flow["events"][1]
    assert first["correlation_id"] == "gtpv2.seq:42"
    assert second["correlation_id"] == "gtpv2.seq:42"
    assert first["paired_event_id"] == second["id"]
    assert second["paired_event_id"] == first["id"]


def test_build_flow_model_pairs_without_correlation_id_by_message_base() -> None:
    packets = [
        _packet(1, "AMF", "SMF", "Create Session Request"),
        _packet(2, "SMF", "AMF", "Create Session Response"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-s11",
        privacy_profile=None,
    )

    assert flow["events"][0]["paired_event_id"] == flow["events"][1]["id"]
    assert flow["events"][1]["paired_event_id"] == flow["events"][0]["id"]


def test_build_flow_model_creates_phases() -> None:
    packets = [
        _packet(1, "MME", "HSS", "Authentication Information Request"),
        _packet(2, "HSS", "MME", "Authentication Information Answer"),
        _packet(3, "MME", "SGW", "Create Session Request"),
        _packet(4, "SGW", "MME", "Create Session Response"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    assert flow["phases"]
    phase_kinds = {phase["kind"] for phase in flow["phases"]}
    assert "authentication" in phase_kinds
    assert "session_setup" in phase_kinds


def test_build_flow_model_uses_family_specific_phase_rules_for_5g() -> None:
    packets = [
        _packet(1, "UE", "AMF", "Registration Request"),
        _packet(2, "AMF", "SMF", "Nsmf_CreateSMContext Request"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="5g-core",
        privacy_profile=None,
    )

    kinds = [phase["kind"] for phase in flow["phases"]]
    assert "registration" in kinds
    assert "session_setup" in kinds


def test_build_flow_model_uses_profile_family_lane_order() -> None:
    packets = [
        _packet(1, "SMF", "AMF", "Nsmf_CreateSMContext Request"),
        _packet(2, "AMF", "UE", "DL NAS"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="5g-core",
        privacy_profile=None,
    )

    labels = [node["label"] for node in flow["nodes"]]
    assert labels.index("UE") < labels.index("AMF")
    assert labels.index("AMF") < labels.index("SMF")


def test_render_flow_svg_contains_event_metadata_attributes() -> None:
    packets = [_packet(1, "MME", "HSS", "AIR")]
    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    svg = render_flow_svg(flow, width=1200)

    assert "<svg" in svg
    assert "data-event-id=\"event-1\"" in svg
    assert "data-packet-no=\"1\"" in svg
    assert "AIR" in svg


def test_render_flow_svg_omits_phase_band_and_keeps_repeat_marker() -> None:
    packets = [
        _packet(1, "MME", "HSS", "AIR"),
        _packet(2, "MME", "HSS", "AIR"),
    ]
    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    svg = render_flow_svg(flow, width=1200)

    assert 'class="phases"' not in svg
    assert ">Authentication<" not in svg
    assert ">#1 07:53:21<" in svg
    assert "AIR x2" in svg


def test_render_flow_svg_separates_title_from_lane_labels() -> None:
    packets = [
        {
            "packet_no": 1,
            "time_rel_ms": 1.0,
            "time_epoch": "1712390001.0",
            "top_protocol": "diameter",
            "src": {"hostname": "mme01.local", "ip": "10.0.0.10", "role": "mme"},
            "dst": {"hostname": "hss01.local", "ip": "10.0.0.20", "role": "hss"},
            "anomalies": [],
            "message": {"protocol": "diameter", "fields": {"message_name": "AIR"}},
        }
    ]
    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
        title="Flow Test",
    )

    svg = render_flow_svg(flow, width=1200)

    assert '<text x="24" y="60"' in svg
    assert '<line x1="18" y1="82"' in svg
    assert 'y="112" text-anchor="middle" font-weight="bold"' in svg
    assert 'y1="154"' in svg


def test_build_flow_model_no_collapse_keeps_all_events() -> None:
    packets = [
        _packet(1, "MME", "HSS", "AIR"),
        _packet(2, "MME", "HSS", "AIR"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
        collapse_repeats=False,
    )

    assert flow["event_count_rendered"] == 2
    assert flow["event_count_uncollapsed"] == 2


def test_build_flow_model_endpoint_label_includes_name_and_ip() -> None:
    packets = [
        {
            "packet_no": 1,
            "time_rel_ms": 1.0,
            "time_epoch": "1712390001.0",
            "top_protocol": "diameter",
            "src": {"hostname": "mme01.local", "ip": "10.0.0.10", "role": "mme"},
            "dst": {"hostname": "hss01.local", "ip": "10.0.0.20", "role": "hss"},
            "anomalies": [],
            "message": {"protocol": "diameter", "fields": {"message_name": "AIR"}},
        }
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    labels = [node["label"] for node in flow["nodes"]]
    assert "mme01.local (10.0.0.10)" in labels
    assert "hss01.local (10.0.0.20)" in labels


def test_build_flow_model_uses_diameter_origin_destination_hosts_as_lane_labels() -> None:
    packets = [
        {
            "packet_no": 1,
            "time_rel_ms": 1.0,
            "time_epoch": "1712390001.0",
            "top_protocol": "diameter",
            "src": {"ip": "10.0.0.10", "role": "diameter"},
            "dst": {"ip": "10.0.0.20", "role": "diameter"},
            "anomalies": [],
            "message": {
                "protocol": "diameter",
                "fields": {
                    "message_name": "Update-Location Request",
                    "diameter.Origin-Host": "mme01.epc.example.net",
                    "diameter.Destination-Host": "hss01.epc.example.net",
                },
            },
        }
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-s6a",
        privacy_profile=None,
    )

    labels = [node["label"] for node in flow["nodes"]]
    assert "mme01.epc.example.net (10.0.0.10)" in labels
    assert "hss01.epc.example.net (10.0.0.20)" in labels


def test_build_flow_model_expands_diameter_command_code_label() -> None:
    packets = [
        {
            "packet_no": 1,
            "time_rel_ms": 1.0,
            "time_epoch": "1712390001.0",
            "top_protocol": "diameter",
            "src": {"alias": "MME", "role": "mme"},
            "dst": {"alias": "HSS", "role": "hss"},
            "anomalies": [],
            "message": {
                "protocol": "diameter",
                "fields": {
                    "command_code": "272",
                    "diameter.flags.request": "1",
                },
            },
        }
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Credit-Control Request (272)"


def test_gtpv2_echo_label_has_no_double_suffix() -> None:
    request = _packet_with_fields(
        1,
        "PGW",
        "SGW",
        "",
        {"gtpv2.message_type": "1", "message_name": None},
    )
    del request["message"]["fields"]["message_name"]
    response = _packet_with_fields(
        2,
        "SGW",
        "PGW",
        "",
        {"gtpv2.message_type": "2"},
    )
    del response["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [request, response],
        capture_file="sample.pcapng",
        profile="lte-s11",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Echo Request (1)"
    assert flow["events"][1]["message_name"] == "Echo Response (2)"


def test_diameter_answer_label_carries_result_code() -> None:
    packet = {
        "packet_no": 1,
        "time_rel_ms": 1.0,
        "time_epoch": "1712390001.0",
        "top_protocol": "diameter",
        "src": {"alias": "HSS", "role": "hss"},
        "dst": {"alias": "MME", "role": "mme"},
        "anomalies": [],
        "message": {
            "protocol": "diameter",
            "fields": {
                "command_code": "316",
                "diameter.flags.request": "0",
                "diameter.Result-Code": "2001",
            },
        },
    }

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-s6a",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Update-Location Answer (316) · Result 2001"


def test_diameter_message_name_passthrough_appends_result_code() -> None:
    packet = _packet_with_fields(
        1,
        "HSS",
        "MME",
        "Update-Location Answer",
        {"diameter.Result-Code": "5001"},
    )

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-s6a",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Update-Location Answer · Result 5001"


def test_ngap_procedure_code_is_named() -> None:
    packet = _packet_with_fields(
        1,
        "gNB",
        "AMF",
        "",
        {"ngap.procedureCode": "32"},
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="5g-core",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "InitialUEMessage (32)"


def test_nas_eps_message_type_is_named() -> None:
    packet = _packet_with_fields(
        1,
        "UE",
        "MME",
        "",
        {"nas_eps.message_type": "0x41"},
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-s1-nas",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Attach Request"


def test_nas_5gs_message_type_is_named() -> None:
    packet = _packet_with_fields(
        1,
        "UE",
        "AMF",
        "",
        {"nas_5gs.mm.message_type": "0x41"},
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="5g-core",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Registration Request"


def test_http2_request_uses_method_and_path() -> None:
    packet = _packet_with_fields(
        1,
        "AMF",
        "SMF",
        "",
        {
            "http2.headers.method": "POST",
            "http2.headers.path": "/nsmf-pdusession/v1/sm-contexts",
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="5g-sbi",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "POST /nsmf-pdusession/v1/sm-contexts"


def test_collapsed_repeats_track_first_and_last_packet() -> None:
    packets = [
        _packet(5, "MME", "HSS", "AIR"),
        _packet(6, "MME", "HSS", "AIR"),
        _packet(7, "MME", "HSS", "AIR"),
    ]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )
    event = flow["events"][0]

    assert event["repeat_count"] == 3
    assert event["first_packet_no"] == 5
    assert event["last_packet_no"] == 7
    assert event["first_relative_ms"] == 50.0
    assert event["last_relative_ms"] == 70.0


def test_render_flow_svg_includes_tooltip_and_accessibility_nodes() -> None:
    packets = [_packet(1, "MME", "HSS", "AIR")]
    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
        title="Flow Test",
    )

    svg = render_flow_svg(flow, width=1200)

    assert 'role="img"' in svg
    assert '<title id="flow-title">Flow Test</title>' in svg
    assert '<desc id="flow-desc">' in svg
    assert "first packet 06.04.2024" in svg
    assert "<title>pkt #1 | MME → HSS | diameter | t=10.0 ms</title>" in svg
    assert "<title>pkt #1 | AIR" not in svg


def test_build_flow_model_adds_first_packet_date_to_subtitle() -> None:
    packets = [_packet(1, "MME", "HSS", "AIR")]

    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    assert flow["first_packet_date"] == "06.04.2024"
    assert flow["subtitle"] == "lte-core | privacy-default | first packet 06.04.2024"


def test_render_flow_svg_adds_wide_transparent_event_hover_target() -> None:
    packets = [_packet(1, "MME", "HSS", "AIR")]
    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    svg = render_flow_svg(flow, width=1200)

    assert '<g class="event" cursor="help" data-event-id="event-1"' in svg
    assert 'stroke="transparent" stroke-width="18" pointer-events="stroke"' in svg
    assert 'stroke-width="1.7" marker-end="url(#arrow)" pointer-events="none"' in svg
    assert ".event:hover .event-tooltip{display:inline;}" in svg
    assert '<text class="event-tooltip"' in svg


def test_gtpv2_response_label_carries_cause_name_on_error() -> None:
    packet = _packet_with_fields(
        1,
        "SGW",
        "MME",
        "",
        {
            "gtpv2.message_type": "33",
            # tshark represents cause nested inside a named container key
            "Cause: Missing or unknown APN (78)": {"gtpv2.cause": "78"},
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-s11",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == (
        "Create Session Response (33) · Cause 78 (Missing or unknown APN)"
    )
    assert flow["events"][0]["status"] == "error"


def test_gtpv2_response_label_compact_for_success_cause() -> None:
    packet = _packet_with_fields(
        1,
        "SGW",
        "MME",
        "",
        {
            "gtpv2.message_type": "33",
            "Cause: Request accepted (16)": {"gtpv2.cause": "16"},
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-s11",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Create Session Response (33) · Cause 16"
    assert flow["events"][0]["status"] == "response"


def test_gtpv2_request_label_never_gets_cause_suffix() -> None:
    packet = _packet_with_fields(
        1,
        "MME",
        "SGW",
        "",
        {"gtpv2.message_type": "32"},
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-s11",
        privacy_profile=None,
    )

    assert flow["events"][0]["message_name"] == "Create Session Request (32)"


def test_dns_query_label_uses_name_and_type() -> None:
    packet = _packet_with_fields(
        1,
        "UE",
        "DNS",
        "",
        {
            "dns.id": "0xcafe",
            "dns.flags_tree": {"dns.flags.response": "0"},
            "Queries": {
                "example.com: type A, class IN": {
                    "dns.qry.name": "example.com",
                    "dns.qry.type": "1",
                }
            },
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-dns",
        privacy_profile=None,
    )

    event = flow["events"][0]
    assert event["message_name"] == "DNS A example.com"
    assert event["status"] == "request"
    assert event["correlation_id"] == "dns.id:0xcafe"


def test_dns_nxdomain_response_is_flagged_as_error() -> None:
    packet = _packet_with_fields(
        1,
        "DNS",
        "UE",
        "",
        {
            "dns.id": "0xcafe",
            "dns.flags_tree": {"dns.flags.response": "1", "dns.flags.rcode": "3"},
            "dns.count.answers": "0",
            "Queries": {
                "missing.example.com: type A, class IN": {
                    "dns.qry.name": "missing.example.com",
                    "dns.qry.type": "1",
                }
            },
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-dns",
        privacy_profile=None,
    )

    event = flow["events"][0]
    assert event["message_name"] == "DNS A missing.example.com · NXDOMAIN"
    assert event["status"] == "error"


def test_dns_error_rcode_labels_response_without_response_flag() -> None:
    packet = _packet_with_fields(
        1,
        "DNS",
        "UE",
        "",
        {
            "dns.qry.name": "missing.example.com",
            "dns.qry.type": "1",
            "dns.flags.rcode": "3",
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    event = flow["events"][0]
    assert event["message_name"] == "DNS A missing.example.com · NXDOMAIN"
    assert event["status"] == "error"


def test_dns_noerror_response_shows_answer_count() -> None:
    packet = _packet_with_fields(
        1,
        "DNS",
        "UE",
        "",
        {
            "dns.id": "0x1234",
            "dns.flags_tree": {"dns.flags.response": "1", "dns.flags.rcode": "0"},
            "dns.count.answers": "2",
            "Queries": {
                "example.com: type A, class IN": {
                    "dns.qry.name": "example.com",
                    "dns.qry.type": "1",
                }
            },
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-dns",
        privacy_profile=None,
    )

    event = flow["events"][0]
    assert event["message_name"] == "DNS A example.com · NOERROR (2 ans)"
    assert event["status"] == "response"


def test_dns_naptr_query_falls_back_to_type_number_if_unknown() -> None:
    packet = _packet_with_fields(
        1,
        "UE",
        "DNS",
        "",
        {
            "dns.flags_tree": {"dns.flags.response": "0"},
            "Queries": {
                "apn.epc.mnc001.mcc001.3gppnetwork.org: type NAPTR, class IN": {
                    "dns.qry.name": "apn.epc.mnc001.mcc001.3gppnetwork.org",
                    "dns.qry.type": "35",
                }
            },
        },
    )
    del packet["message"]["fields"]["message_name"]

    flow = build_flow_model(
        [packet],
        capture_file="sample.pcapng",
        profile="lte-dns",
        privacy_profile=None,
    )

    event = flow["events"][0]
    assert event["message_name"] == "DNS NAPTR apn.epc.mnc001.mcc001.3gppnetwork.org"


def test_render_flow_svg_shows_repeat_packet_range_in_label() -> None:
    packets = [
        _packet(1, "MME", "HSS", "AIR"),
        _packet(2, "MME", "HSS", "AIR"),
    ]
    flow = build_flow_model(
        packets,
        capture_file="sample.pcapng",
        profile="lte-core",
        privacy_profile=None,
    )

    svg = render_flow_svg(flow, width=1200)

    assert "AIR x2 (pkts 1" in svg
