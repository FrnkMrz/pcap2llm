from __future__ import annotations

from typing import Any


def map_error(exc: Exception) -> tuple[str, dict[str, Any]]:
    message = str(exc)

    if "exceeds --max-capture-size-mb" in message:
        return "capture_too_large", {}
    if "tshark was not found in PATH" in message:
        return "tshark_missing", {}
    if "tshark output is not valid JSON" in message:
        return "invalid_tshark_json", {}
    if "Unexpected tshark JSON structure" in message or "unknown tshark error" in message:
        return "tshark_failed", {}
    if "PCAP2LLM_VAULT_KEY is not a valid Fernet key" in message:
        return "invalid_vault_key", {}
    if "requires PCAP2LLM_VAULT_KEY" in message:
        return "missing_vault_key", {}
    if "Failed to write artifacts" in message or "Cannot create output directory" in message:
        return "artifact_write_failed", {}
    if "detail export would be truncated" in message:
        return "detail_truncated_and_disallowed", {}
    return "runtime_error", {}
