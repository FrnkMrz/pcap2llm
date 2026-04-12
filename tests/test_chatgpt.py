from __future__ import annotations

from pathlib import Path

from pcap2llm.chatgpt import build_chatgpt_prompt, extract_response_text
from pcap2llm.models import AnalyzeArtifacts


def _artifacts() -> AnalyzeArtifacts:
    return AnalyzeArtifacts(
        summary={
            "profile": "lte-s6a",
            "relevant_protocols": ["diameter", "sctp"],
            "conversations": [{"src": "IP_a", "dst": "IP_b", "packet_count": 2}],
            "packet_message_counts": {"total_packets": 2},
            "anomalies": ["unanswered CER"],
            "anomaly_counts_by_layer": {"diameter": 1},
            "deterministic_findings": ["1 anomaly detected"],
            "probable_notable_findings": [],
            "coverage": {"detail_packets_included": 2},
            "timing_stats": {"duration_ms": 1.0},
            "burst_periods": [],
            "privacy_modes": {"ip": "pseudonymize"},
        },
        detail={
            "artifact_role": "llm_input",
            "coverage": {"detail_packets_included": 2},
            "messages": [
                {"packet_no": 1, "message": {"protocol": "diameter", "fields": {"diameter.cmd.code": "257"}}},
                {"packet_no": 2, "message": {"protocol": "diameter", "fields": {"diameter.cmd.code": "257"}}},
            ],
        },
        markdown="# summary\n",
    )


def test_build_chatgpt_prompt_respects_max_messages() -> None:
    prompt, metadata = build_chatgpt_prompt(
        capture=Path("trace.pcapng"),
        profile_name="lte-s6a",
        privacy_profile_name="llm-telecom-safe",
        question="What failed?",
        artifacts=_artifacts(),
        max_messages=1,
    )
    assert "What failed?" in prompt
    assert metadata["included_messages"] == 1
    assert metadata["available_messages"] == 2
    assert metadata["detail_excerpt_truncated"] is True


def test_extract_response_text_prefers_output_text() -> None:
    payload = {"output_text": "Hello telecom"}
    assert extract_response_text(payload) == "Hello telecom"


def test_extract_response_text_falls_back_to_output_content() -> None:
    payload = {
        "output": [
            {"content": [{"text": "First"}, {"text": "Second"}]},
        ]
    }
    assert extract_response_text(payload) == "First\n\nSecond"
