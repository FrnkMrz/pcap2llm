from __future__ import annotations

from pcap2llm.claude import extract_claude_response_text


def test_extract_claude_response_text_reads_text_blocks() -> None:
    payload = {
        "content": [
            {"type": "text", "text": "First finding"},
            {"type": "text", "text": "Second finding"},
        ]
    }
    assert extract_claude_response_text(payload) == "First finding\n\nSecond finding"
