from __future__ import annotations

import base64
import hashlib
import os
from collections import defaultdict
from typing import Any

from pcap2llm.config import normalize_mode
from pcap2llm.privacy_policy import PrivacyPolicyEngine


class ProtectionError(RuntimeError):
    """Raised when privacy enforcement fails."""


class Protector:
    def __init__(self, modes: dict[str, str], policy: PrivacyPolicyEngine | None = None) -> None:
        self.modes = {key: normalize_mode(value) for key, value in modes.items()}
        self.pseudonyms: dict[str, dict[str, str]] = defaultdict(dict)
        self._fernet = None
        self._key_source: str | None = None
        self.policy = policy or PrivacyPolicyEngine()

    def validate_vault_key(self) -> None:
        """Fail fast if encrypt mode is requested but the key is missing or invalid.

        Call this before starting packet processing so the user gets a clear
        error message rather than a crash mid-pipeline.
        """
        if "encrypt" not in self.modes.values():
            return
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise ProtectionError(
                "Encryption mode requires the optional 'cryptography' dependency."
            ) from exc
        key = os.getenv("PCAP2LLM_VAULT_KEY")
        if not key:
            raise ProtectionError(
                "Encryption mode requires PCAP2LLM_VAULT_KEY to be set explicitly. "
                "pcap2llm does not generate or store recovery keys for you."
            )
        try:
            Fernet(key.encode("utf-8"))
        except Exception as exc:
            raise ProtectionError(
                f"PCAP2LLM_VAULT_KEY is not a valid Fernet key: {exc}"
            ) from exc

    def _load_fernet(self) -> Any:
        if self._fernet is not None:
            return self._fernet
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise ProtectionError(
                "Encryption mode requires the optional 'cryptography' dependency."
            ) from exc

        key = os.getenv("PCAP2LLM_VAULT_KEY")
        if not key:
            raise ProtectionError(
                "Encryption mode requires PCAP2LLM_VAULT_KEY to be set explicitly. "
                "The vault sidecar contains metadata only and cannot recover encrypted values."
            )

        self._key_source = "env:PCAP2LLM_VAULT_KEY"
        try:
            self._fernet = Fernet(key.encode("utf-8"))
        except Exception as exc:
            raise ProtectionError(
                f"PCAP2LLM_VAULT_KEY is not a valid Fernet key: {exc}"
            ) from exc
        return self._fernet

    def _pseudonym(self, data_class: str, original: str) -> str:
        existing = self.pseudonyms[data_class].get(original)
        if existing:
            return existing
        # Hash-based pseudonym: stable across runs, no counter collisions.
        # BLAKE2s with 4-byte digest gives a 8-character hex suffix; the
        # 2^32 space comfortably covers realistic subscriber counts.
        h = hashlib.blake2s(
            f"{data_class}:{original}".encode("utf-8"), digest_size=4
        ).hexdigest()
        alias = f"{data_class.upper()}_{h}"
        self.pseudonyms[data_class][original] = alias
        return alias

    @staticmethod
    def _mask_imei_keep_tac(value: Any) -> Any:
        text = str(value)
        if len(text) <= 8:
            return "[redacted]"
        return f"{text[:8]}{'X' * (len(text) - 8)}"

    def _protect_scalar(self, data_class: str, value: Any) -> Any:
        mode = self.modes.get(data_class, "keep")
        if value is None or mode == "keep":
            return value
        if mode == "keep_tac_mask_serial":
            if data_class == "imei":
                return self._mask_imei_keep_tac(value)
            return "[redacted]"
        if mode == "mask":
            return "[redacted]"
        if mode == "remove":
            return None
        if mode == "pseudonymize":
            return self._pseudonym(data_class, str(value))
        if mode == "encrypt":
            token = self._load_fernet().encrypt(str(value).encode("utf-8"))
            return base64.urlsafe_b64encode(token).decode("utf-8")
        return value

    def _walk(self, obj: Any, path: str = "", packet: dict[str, Any] | None = None) -> Any:
        if isinstance(obj, dict):
            output: dict[str, Any] = {}
            for key, value in obj.items():
                child_path = f"{path}.{key}" if path else key
                protected = self._walk(value, child_path, packet=packet)
                if protected is not None:
                    output[key] = protected
            return output
        if isinstance(obj, list):
            return [item for item in (self._walk(value, path, packet=packet) for value in obj) if item is not None]
        data_class = self.policy.classify(path, obj, packet=packet)
        if data_class:
            return self._protect_scalar(data_class, obj)
        return obj

    def protect_packets(self, packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self._walk(packet, packet=packet) for packet in packets]

    def vault_metadata(self) -> dict[str, Any] | None:
        if self._key_source is None:
            return None
        return {
            "key_source": self._key_source,
            "notes": [
                "Encrypted values are stored inline in detail.json.",
                "vault.json contains metadata only; it never contains the decryption secret.",
                "Keep PCAP2LLM_VAULT_KEY separate from shared artifacts; without it the values are not recoverable.",
            ],
        }

    def pseudonym_audit(self) -> dict[str, int]:
        """Return the number of unique values pseudonymized per data class."""
        return {cls: len(mapping) for cls, mapping in self.pseudonyms.items() if mapping}

    def policy_metadata(self) -> dict[str, Any]:
        return self.policy.metadata()
