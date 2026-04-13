from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib import error, request

from pcap2llm.models import AnalyzeArtifacts
from pcap2llm.output_metadata import semantic_artifact_filename

DEFAULT_CHATGPT_QUESTION = (
    "Explain what this telecom trace shows, identify the failure point if any, "
    "and rank the most likely root causes. Separate direct trace evidence from hypotheses."
)

DEFAULT_SYSTEM_PROMPT = (
    "You are a senior telecom troubleshooting assistant. "
    "Work only from the provided pcap2llm artifacts. "
    "Do not invent packets, messages, or protocol states that are not present. "
    "State confirmed evidence first, then likely hypotheses, then open questions."
)


def build_chatgpt_prompt(
    *,
    capture: Path,
    profile_name: str,
    privacy_profile_name: str,
    question: str,
    artifacts: AnalyzeArtifacts,
    max_messages: int,
) -> tuple[str, dict[str, Any]]:
    detail_messages = list(artifacts.detail.get("messages", []))
    included_all_messages = len(detail_messages) <= max_messages
    selected_messages = detail_messages if included_all_messages else detail_messages[:max_messages]
    summary_payload = {
        "profile": artifacts.summary.get("profile"),
        "relevant_protocols": artifacts.summary.get("relevant_protocols", []),
        "conversations": artifacts.summary.get("conversations", []),
        "packet_message_counts": artifacts.summary.get("packet_message_counts", {}),
        "anomalies": artifacts.summary.get("anomalies", []),
        "anomaly_counts_by_layer": artifacts.summary.get("anomaly_counts_by_layer", {}),
        "deterministic_findings": artifacts.summary.get("deterministic_findings", []),
        "probable_notable_findings": artifacts.summary.get("probable_notable_findings", []),
        "coverage": artifacts.summary.get("coverage", {}),
        "timing_stats": artifacts.summary.get("timing_stats", {}),
        "burst_periods": artifacts.summary.get("burst_periods", []),
        "privacy_modes": artifacts.summary.get("privacy_modes", {}),
    }
    detail_payload = {
        "artifact_role": artifacts.detail.get("artifact_role"),
        "coverage": artifacts.detail.get("coverage", {}),
        "messages": selected_messages,
    }
    prompt = "\n".join(
        [
            "# Telecom Trace Troubleshooting Request",
            "",
            f"Capture: `{capture.name}`",
            f"Selected profile: `{profile_name}`",
            f"Privacy profile: `{privacy_profile_name}`",
            "",
            "## Task",
            question.strip(),
            "",
            "## Instructions",
            "- Explain the observed protocol sequence in plain technical language.",
            "- Identify the likely failure point or abnormal behavior.",
            "- Separate direct evidence from hypotheses.",
            "- If evidence is insufficient, say what is missing.",
            "",
            "## Summary Artifact",
            "```json",
            json.dumps(summary_payload, indent=2, ensure_ascii=True),
            "```",
            "",
            "## Detail Artifact Excerpt",
            f"Included messages: {len(selected_messages)} of {len(detail_messages)}",
            "```json",
            json.dumps(detail_payload, indent=2, ensure_ascii=True),
            "```",
        ]
    )
    metadata = {
        "included_messages": len(selected_messages),
        "available_messages": len(detail_messages),
        "detail_excerpt_truncated": not included_all_messages,
    }
    return prompt, metadata


def request_chatgpt_response(
    *,
    model: str,
    prompt: str,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    api_key_env: str = "OPENAI_API_KEY",
    timeout_seconds: int = 120,
    base_url: str | None = None,
) -> dict[str, Any]:
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise RuntimeError(f"{api_key_env} is not set.")

    endpoint_base = (base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": [{"type": "input_text", "text": system_prompt}],
            },
            {
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            },
        ],
    }
    req = request.Request(
        f"{endpoint_base}/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API request failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"OpenAI API request failed: {exc.reason}") from exc

    raw = json.loads(body)
    return {
        "raw": raw,
        "text": extract_response_text(raw),
    }


def extract_response_text(payload: dict[str, Any]) -> str:
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    parts: list[str] = []
    for item in payload.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue
            text_value = content.get("text")
            if isinstance(text_value, str) and text_value.strip():
                parts.append(text_value.strip())
    if parts:
        return "\n\n".join(parts)
    raise RuntimeError("OpenAI response did not contain readable output text.")


def write_chatgpt_handoff_files(
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
        action="chatgpt",
        capture_path=capture,
        start_packet_number=first_packet_number,
        first_seen=first_seen,
        version=version,
        extension=".md",
        artifact_kind="prompt",
    )
    response_md_path = out_dir / semantic_artifact_filename(
        action="chatgpt",
        capture_path=capture,
        start_packet_number=first_packet_number,
        first_seen=first_seen,
        version=version,
        extension=".md",
        artifact_kind="response",
    )
    response_json_path = out_dir / semantic_artifact_filename(
        action="chatgpt",
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
