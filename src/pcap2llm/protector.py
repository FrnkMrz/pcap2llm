from __future__ import annotations

import base64
import os
import re
from collections import defaultdict
from typing import Any

from pcap2llm.config import normalize_mode

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _looks_like_data_class(path: str, value: Any) -> str | None:
    key = path.lower()
    text = "" if value is None else str(value)
    if key.endswith(".ip") or ".ip" in key:
        return "ip"
    if "hostname" in key:
        return "hostname"
    if "imsi" in key:
        return "imsi"
    if "msisdn" in key:
        return "msisdn"
    if "imei" in key:
        return "imei"
    if "email" in key or EMAIL_RE.match(text):
        return "email"
    if "token" in key or "bearer" in key or "cookie" in key:
        return "token"
    if key.endswith(".uri") or " url" in key or "uri" in key:
        return "uri"
    if "apn" in key or "dnn" in key:
        return "apn_dnn"
    if "realm" in key or "origin_host" in key or "destination_host" in key:
        return "diameter_identity"
    if "distinguished" in key or key.endswith(".dn"):
        return "distinguished_name"
    if "payload" in key or key.endswith(".text"):
        return "payload_text"
    if "subscriber" in key or key.endswith(".id"):
        return "subscriber_id"
    return None


class ProtectionError(RuntimeError):
    """Raised when privacy enforcement fails."""


class Protector:
    def __init__(self, modes: dict[str, str]) -> None:
        self.modes = {key: normalize_mode(value) for key, value in modes.items()}
        self.pseudonyms: dict[str, dict[str, str]] = defaultdict(dict)
        self._counters: dict[str, int] = defaultdict(int)
        self._fernet = None
        self._key_source: str | None = None

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
        if key:
            self._key_source = "PCAP2LLM_VAULT_KEY"
            self._fernet = Fernet(key.encode("utf-8"))
            return self._fernet

        generated = Fernet.generate_key()
        self._key_source = "generated"
        os.environ["PCAP2LLM_VAULT_KEY"] = generated.decode("utf-8")
        self._fernet = Fernet(generated)
        return self._fernet

    def _pseudonym(self, data_class: str, original: str) -> str:
        existing = self.pseudonyms[data_class].get(original)
        if existing:
            return existing
        self._counters[data_class] += 1
        alias = f"{data_class.upper()}_{self._counters[data_class]:04d}"
        self.pseudonyms[data_class][original] = alias
        return alias

    def _protect_scalar(self, data_class: str, value: Any) -> Any:
        mode = self.modes.get(data_class, "keep")
        if value is None or mode == "keep":
            return value
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

    def _walk(self, obj: Any, path: str = "") -> Any:
        if isinstance(obj, dict):
            output: dict[str, Any] = {}
            for key, value in obj.items():
                child_path = f"{path}.{key}" if path else key
                protected = self._walk(value, child_path)
                if protected is not None:
                    output[key] = protected
            return output
        if isinstance(obj, list):
            return [item for item in (self._walk(value, path) for value in obj) if item is not None]
        data_class = _looks_like_data_class(path, obj)
        if data_class:
            return self._protect_scalar(data_class, obj)
        return obj

    def protect_packets(self, packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self._walk(packet) for packet in packets]

    def vault_metadata(self) -> dict[str, Any] | None:
        if self._key_source is None:
            return None
        return {
            "key_source": self._key_source,
            "notes": [
                "Encrypted values are stored inline in detail.json.",
                "Keep the local vault key private; without it the values are not recoverable.",
            ],
        }
