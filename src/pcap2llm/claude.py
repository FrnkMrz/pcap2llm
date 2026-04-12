from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib import error, request

from pcap2llm.chatgpt import DEFAULT_SYSTEM_PROMPT, build_chatgpt_prompt
from pcap2llm.output_metadata import semantic_artifact_filename


def request_claude_response(
    *,
    model: str,
    prompt: str,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    api_key_env: str = "ANTHROPIC_API_KEY",
    timeout_seconds: int = 120,
    base_url: str | None = None,
    max_tokens: int = 2000,
) -> dict[str, Any]:
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise RuntimeError(f"{api_key_env} is not set.")

    endpoint_base = (base_url or os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
    }
    req = request.Request(
        f"{endpoint_base}/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Anthropic API request failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Anthropic API request failed: {exc.reason}") from exc

    raw = json.loads(body)
    return {
        "raw": raw,
        "text": extract_claude_response_text(raw),
    }


def extract_claude_response_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for content in payload.get("content", []):
        if not isinstance(content, dict):
            continue
        if content.get("type") != "text":
            continue
        text_value = content.get("text")
        if isinstance(text_value, str) and text_value.strip():
            parts.append(text_value.strip())
    if parts:
        return "\n\n".join(parts)
    raise RuntimeError("Anthropic response did not contain readable output text.")


def write_claude_handoff_files(
    *,
    out_dir: Path,
    capture: Path,
    first_packet_number: int | None,
    prompt_text: str,
    response_text: str,
    response_payload: dict[str, Any],
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    version = "V_01"
    prompt_path = out_dir / semantic_artifact_filename(
        action="claude",
        capture_path=capture,
        start_packet_number=first_packet_number,
        version=version,
        extension=".md",
        artifact_kind="prompt",
    )
    response_md_path = out_dir / semantic_artifact_filename(
        action="claude",
        capture_path=capture,
        start_packet_number=first_packet_number,
        version=version,
        extension=".md",
        artifact_kind="response",
    )
    response_json_path = out_dir / semantic_artifact_filename(
        action="claude",
        capture_path=capture,
        start_packet_number=first_packet_number,
        version=version,
        extension=".json",
        artifact_kind="response_raw",
    )
    prompt_path.write_text(prompt_text, encoding="utf-8")
    response_md_path.write_text(response_text.rstrip() + "\n", encoding="utf-8")
    response_json_path.write_text(json.dumps(response_payload, indent=2), encoding="utf-8")
    return {
        "prompt": prompt_path,
        "response_markdown": response_md_path,
        "response_json": response_json_path,
    }


__all__ = [
    "build_chatgpt_prompt",
    "extract_claude_response_text",
    "request_claude_response",
    "write_claude_handoff_files",
]
