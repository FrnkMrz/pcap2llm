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
    assert flow["packet_count_total"] == 2
    assert flow["warnings"]
    assert flow["title"] == "5G Signaling"


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
