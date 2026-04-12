from __future__ import annotations

from pcap2llm.gemini import extract_gemini_response_text


def test_extract_gemini_response_text_reads_candidate_parts() -> None:
    payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "First finding"},
                        {"text": "Second finding"},
                    ]
                }
            }
        ]
    }
    assert extract_gemini_response_text(payload) == "First finding\n\nSecond finding"
