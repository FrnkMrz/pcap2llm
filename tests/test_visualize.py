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


def test_render_flow_svg_includes_phase_and_repeat_marker() -> None:
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

    assert 'class="phases"' in svg
    assert "AIR x2" in svg


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
