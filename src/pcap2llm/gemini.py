from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from pcap2llm.chatgpt import DEFAULT_SYSTEM_PROMPT, build_chatgpt_prompt
from pcap2llm.output_metadata import semantic_artifact_filename


def request_gemini_response(
    *,
    model: str,
    prompt: str,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    api_key_env: str = "GEMINI_API_KEY",
    timeout_seconds: int = 120,
    base_url: str | None = None,
) -> dict[str, Any]:
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise RuntimeError(f"{api_key_env} is not set.")

    endpoint_base = (base_url or os.environ.get("GEMINI_BASE_URL") or "https://generativelanguage.googleapis.com").rstrip("/")
    payload = {
        "system_instruction": {
            "parts": [{"text": system_prompt}],
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
    }
    encoded_model = parse.quote(model, safe="")
    req = request.Request(
        f"{endpoint_base}/v1beta/models/{encoded_model}:generateContent?key={api_key}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Gemini API request failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Gemini API request failed: {exc.reason}") from exc

    raw = json.loads(body)
    return {
        "raw": raw,
        "text": extract_gemini_response_text(raw),
    }


def extract_gemini_response_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for candidate in payload.get("candidates", []):
        if not isinstance(candidate, dict):
            continue
        content = candidate.get("content")
        if not isinstance(content, dict):
            continue
        for part in content.get("parts", []):
            if not isinstance(part, dict):
                continue
            text_value = part.get("text")
            if isinstance(text_value, str) and text_value.strip():
                parts.append(text_value.strip())
    if parts:
        return "\n\n".join(parts)
    raise RuntimeError("Gemini response did not contain readable output text.")


def write_gemini_handoff_files(
    *,
    out_dir: Path,
    capture: Path,
    first_packet_number: int | None,
    first_seen: str | None,
    prompt_text: str,
    response_text: str,
    response_payload: dict[str, Any],
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    version = "V_01"
    prompt_path = out_dir / semantic_artifact_filename(
        action="gemini",
        capture_path=capture,
        start_packet_number=first_packet_number,
        first_seen=first_seen,
        version=version,
        extension=".md",
        artifact_kind="prompt",
    )
    response_md_path = out_dir / semantic_artifact_filename(
        action="gemini",
        capture_path=capture,
        start_packet_number=first_packet_number,
        first_seen=first_seen,
        version=version,
        extension=".md",
        artifact_kind="response",
    )
    response_json_path = out_dir / semantic_artifact_filename(
        action="gemini",
        capture_path=capture,
        start_packet_number=first_packet_number,
        first_seen=first_seen,
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
    "extract_gemini_response_text",
    "request_gemini_response",
    "write_gemini_handoff_files",
]
