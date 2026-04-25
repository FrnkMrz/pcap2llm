from __future__ import annotations

import base64
import hashlib
import os
import re
from collections import defaultdict
from typing import Any

from pcap2llm.config import normalize_mode
from pcap2llm.models import ProtectionMode
from pcap2llm.privacy_policy import PrivacyPolicyEngine


class ProtectionError(RuntimeError):
    """Raised when privacy enforcement fails."""


_PARTIAL_ENCRYPT_MODES = {
    ProtectionMode.KEEP_MCC_MNC_ENCRYPT_MSIN.value,
    ProtectionMode.KEEP_CC_NDC_ENCRYPT_SUBSCRIBER.value,
}
_DIGITS_RE = re.compile(r"^\+?\d+$")
_E164_COUNTRY_CODES = {
    "1", "7", "20", "27", "30", "31", "32", "33", "34", "36", "39", "40",
    "41", "43", "44", "45", "46", "47", "48", "49", "51", "52", "53",
    "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65",
    "66", "81", "82", "84", "86", "90", "91", "92", "93", "94", "95",
    "98", "212", "213", "216", "218", "220", "221", "222", "223", "224",
    "225", "226", "227", "228", "229", "230", "231", "232", "233", "234",
    "235", "236", "237", "238", "239", "240", "241", "242", "243", "244",
    "245", "246", "248", "249", "250", "251", "252", "253", "254", "255",
    "256", "257", "258", "260", "261", "262", "263", "264", "265", "266",
    "267", "268", "269", "290", "291", "297", "298", "299", "350", "351",
    "352", "353", "354", "355", "356", "357", "358", "359", "370", "371",
    "372", "373", "374", "375", "376", "377", "378", "380", "381", "382",
    "383", "385", "386", "387", "389", "420", "421", "423", "500", "501",
    "502", "503", "504", "505", "506", "507", "508", "509", "590", "591",
    "592", "593", "594", "595", "596", "597", "598", "599", "670", "672",
    "673", "674", "675", "676", "677", "678", "679", "680", "681", "682",
    "683", "685", "686", "687", "688", "689", "690", "691", "692", "850",
    "852", "853", "855", "856", "880", "886", "960", "961", "962", "963",
    "964", "965", "966", "967", "968", "970", "971", "972", "973", "974",
    "975", "976", "977", "992", "993", "994", "995", "996", "998",
}
_ISO_COUNTRY_NAMES_BY_E164_CC = {
    # +1 is intentionally omitted: it is a shared North American numbering plan.
    "49": "Germany",
}
_ISO_COUNTRY_NAMES_BY_MCC = {
    "262": "Germany",
    "310": "United States of America",
    "311": "United States of America",
    "312": "United States of America",
    "313": "United States of America",
    "314": "United States of America",
    "315": "United States of America",
    "316": "United States of America",
}
_GERMANY_E164_NDCS = (
    # Bundesnetzagentur mobile ranges: (0)15, (0)160, (0)162, (0)163,
    # and (0)17. Stored without the national trunk prefix for +49 format.
    "160",
    "162",
    "163",
    "170",
    "171",
    "172",
    "173",
    "174",
    "175",
    "176",
    "177",
    "178",
    "179",
    "15",
)
_DEFAULT_E164_NDC_PREFIXES = {"49": _GERMANY_E164_NDCS}


class Protector:
    def __init__(
        self,
        modes: dict[str, str],
        policy: PrivacyPolicyEngine | None = None,
        *,
        imsi_mnc_lengths: dict[str, int] | None = None,
        msisdn_ndc_lengths: dict[str, int] | None = None,
        msisdn_ndc_prefixes: dict[str, list[str]] | None = None,
    ) -> None:
        self.modes = {key: normalize_mode(value) for key, value in modes.items()}
        self.pseudonyms: dict[str, dict[str, str]] = defaultdict(dict)
        self._fernet = None
        self._key_source: str | None = None
        self.policy = policy or PrivacyPolicyEngine()
        self.imsi_mnc_lengths = {
            str(mcc): int(length) for mcc, length in (imsi_mnc_lengths or {}).items()
        }
        self.msisdn_ndc_prefixes = {
            cc: tuple(prefixes) for cc, prefixes in _DEFAULT_E164_NDC_PREFIXES.items()
        }
        for cc, prefixes in (msisdn_ndc_prefixes or {}).items():
            self.msisdn_ndc_prefixes[str(cc)] = tuple(str(prefix) for prefix in prefixes)
        for cc, length in (msisdn_ndc_lengths or {}).items():
            # Backward-compatible shorthand for local configs that only know a
            # fixed NDC length. Prefer msisdn_ndc_prefixes for real partner plans.
            self.msisdn_ndc_prefixes[str(cc)] = ("?" * int(length),)

    def validate_vault_key(self) -> None:
        """Fail fast if encrypt mode is requested but the key is missing or invalid.

        Call this before starting packet processing so the user gets a clear
        error message rather than a crash mid-pipeline.
        """
        if not any(
            mode == ProtectionMode.ENCRYPT.value or mode in _PARTIAL_ENCRYPT_MODES
            for mode in self.modes.values()
        ):
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

    def _encrypt_text(self, value: str) -> str:
        token = self._load_fernet().encrypt(value.encode("utf-8"))
        return base64.urlsafe_b64encode(token).decode("utf-8")

    @staticmethod
    def _with_country(value: str, country_name: str | None) -> str:
        if not country_name:
            return value
        return f"{value} ({country_name})"

    def _protect_suffix(
        self,
        data_class: str,
        prefix: str,
        suffix: str,
        mode: str,
        *,
        country_name: str | None = None,
    ) -> str:
        if not suffix:
            return self._with_country(prefix, country_name)
        if mode.endswith("_mask_msin") or mode.endswith("_mask_subscriber"):
            return self._with_country(f"{prefix}{'X' * len(suffix)}", country_name)
        if mode.endswith("_pseudonymize_msin") or mode.endswith("_pseudonymize_subscriber"):
            alias = self._pseudonym(f"{data_class}_suffix", f"{prefix}:{suffix}")
            return self._with_country(f"{prefix}{alias}", country_name)
        if mode.endswith("_encrypt_msin") or mode.endswith("_encrypt_subscriber"):
            return self._with_country(f"{prefix}{self._encrypt_text(suffix)}", country_name)
        return self._with_country(f"{prefix}{suffix}", country_name)

    def _imsi_network_prefix_length(self, digits: str) -> int:
        mcc = digits[:3]
        mnc_length = self.imsi_mnc_lengths.get(mcc)
        if mnc_length is None:
            # Project heuristic: North American/Caribbean MCCs (3xx) use
            # three-digit MNCs; all other MCCs default to two-digit MNCs.
            mnc_length = 3 if mcc.startswith("3") else 2
        return 3 + mnc_length

    def _protect_imsi_keep_network(self, value: Any, mode: str) -> Any:
        text = str(value)
        if not text.isdigit() or not (6 < len(text) <= 15):
            return "[redacted]"
        prefix_len = self._imsi_network_prefix_length(text)
        if len(text) <= prefix_len:
            return "[redacted]"
        country_name = _ISO_COUNTRY_NAMES_BY_MCC.get(text[:3])
        return self._protect_suffix(
            "imsi",
            text[:prefix_len],
            text[prefix_len:],
            mode,
            country_name=country_name,
        )

    def _split_msisdn_routing_prefix(self, value: Any) -> tuple[str, str, str | None] | None:
        text = str(value).strip()
        if not _DIGITS_RE.fullmatch(text):
            return None
        plus = "+" if text.startswith("+") else ""
        digits = text[1:] if plus else text
        if not (4 < len(digits) <= 15):
            return None

        cc = next(
            (candidate for candidate in sorted(_E164_COUNTRY_CODES, key=len, reverse=True)
             if digits.startswith(candidate)),
            None,
        )
        if cc is None:
            cc = digits[:1]

        national = digits[len(cc):]
        ndc = ""
        for candidate in sorted(self.msisdn_ndc_prefixes.get(cc, ()), key=len, reverse=True):
            if "?" in candidate:
                length = len(candidate)
                if len(national) > length:
                    ndc = national[:length]
                    break
            elif national.startswith(candidate):
                ndc = candidate
                break

        prefix_len = len(cc) + len(ndc)
        if len(digits) <= prefix_len:
            return None
        country_name = _ISO_COUNTRY_NAMES_BY_E164_CC.get(cc)
        return f"{plus}{digits[:prefix_len]}", digits[prefix_len:], country_name

    def _protect_msisdn_keep_routing(self, value: Any, mode: str) -> Any:
        parts = self._split_msisdn_routing_prefix(value)
        if parts is None:
            return "[redacted]"
        prefix, subscriber, country_name = parts
        return self._protect_suffix(
            "msisdn",
            prefix,
            subscriber,
            mode,
            country_name=country_name,
        )

    def _protect_scalar(self, data_class: str, value: Any) -> Any:
        mode = self.modes.get(data_class, "keep")
        if value is None or mode == "keep":
            return value
        if mode == "keep_tac_mask_serial":
            if data_class == "imei":
                return self._mask_imei_keep_tac(value)
            return "[redacted]"
        if mode.startswith("keep_mcc_mnc_"):
            if data_class == "imsi":
                return self._protect_imsi_keep_network(value, mode)
            return "[redacted]"
        if mode.startswith("keep_cc_ndc_"):
            if data_class == "msisdn":
                return self._protect_msisdn_keep_routing(value, mode)
            return "[redacted]"
        if mode == "mask":
            return "[redacted]"
        if mode == "remove":
            return None
        if mode == "pseudonymize":
            return self._pseudonym(data_class, str(value))
        if mode == "encrypt":
            return self._encrypt_text(str(value))
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

    def protect_artifact_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Protect summary/discovery-style payloads without packet context."""
        return self._walk(payload)

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
