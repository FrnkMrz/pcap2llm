import re

import pytest

from pcap2llm.protector import Protector

_PSEUDONYM_RE = re.compile(r"^[A-Z_]+_[0-9a-f]{8}$")


def test_protector_masks_and_pseudonymizes() -> None:
    protector = Protector(
        {
            "ip": "mask",
            "hostname": "keep",
            "imsi": "pseudonymize",
            "token": "remove",
        }
    )
    packets = [
        {
            "src": {"ip": "10.0.0.1"},
            "message": {
                "fields": {
                    "diameter.imsi": "001010123456789",
                    "auth.token": "secret",
                }
            },
        }
    ]
    protected = protector.protect_packets(packets)
    assert protected[0]["src"]["ip"] == "[redacted]"
    alias = protected[0]["message"]["fields"]["diameter.imsi"]
    assert alias.startswith("IMSI_")
    assert _PSEUDONYM_RE.match(alias), f"Unexpected pseudonym format: {alias!r}"
    assert "auth.token" not in protected[0]["message"]["fields"]


def test_protect_artifact_payload_pseudonymizes_conversation_ips_consistently() -> None:
    protector = Protector({"ip": "pseudonymize", "hostname": "pseudonymize"})
    packet_alias = protector.protect_packets([{"src": {"ip": "10.0.0.1"}, "dst": {"ip": "10.0.0.2"}}])

    artifact = protector.protect_artifact_payload(
        {
            "conversations": [
                {"src": "10.0.0.1", "dst": "10.0.0.2", "src_name": "mme.internal", "packet_count": 2}
            ],
            "privacy_modes": {"ip": "pseudonymize", "hostname": "pseudonymize"},
        }
    )

    assert artifact["conversations"][0]["src"] == packet_alias[0]["src"]["ip"]
    assert artifact["conversations"][0]["dst"] == packet_alias[0]["dst"]["ip"]
    assert artifact["conversations"][0]["src_name"].startswith("HOSTNAME_")
    assert protector.pseudonym_audit()["ip"] == 2


def test_pseudonym_is_stable_across_calls() -> None:
    """Same input must produce the same pseudonym regardless of call order."""
    p1 = Protector({"imsi": "pseudonymize"})
    p2 = Protector({"imsi": "pseudonymize"})
    packets = [{"message": {"fields": {"diameter.imsi": "001010123456789"}}}]
    alias1 = p1.protect_packets(packets)[0]["message"]["fields"]["diameter.imsi"]
    alias2 = p2.protect_packets(packets)[0]["message"]["fields"]["diameter.imsi"]
    assert alias1 == alias2, "Pseudonym must be stable across Protector instances"


def test_pseudonym_differs_for_different_values() -> None:
    p = Protector({"imsi": "pseudonymize"})
    packets = [
        {"message": {"fields": {"diameter.imsi": "001010000000001"}}},
        {"message": {"fields": {"diameter.imsi": "001010000000002"}}},
    ]
    protected = p.protect_packets(packets)
    a1 = protected[0]["message"]["fields"]["diameter.imsi"]
    a2 = protected[1]["message"]["fields"]["diameter.imsi"]
    assert a1 != a2


def test_pseudonym_audit_counts_unique_values() -> None:
    p = Protector({"imsi": "pseudonymize", "msisdn": "pseudonymize"})
    packets = [
        {"message": {"fields": {"diameter.imsi": "001010000000001", "diameter.msisdn": "491700000001"}}},
        {"message": {"fields": {"diameter.imsi": "001010000000001"}}},  # same imsi
        {"message": {"fields": {"diameter.imsi": "001010000000002"}}},  # new imsi
    ]
    p.protect_packets(packets)
    audit = p.pseudonym_audit()
    assert audit["imsi"] == 2  # two unique IMSI values
    assert audit["msisdn"] == 1


def test_encrypt_requires_explicit_env_key(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("cryptography")
    monkeypatch.delenv("PCAP2LLM_VAULT_KEY", raising=False)
    protector = Protector({"imsi": "encrypt"})
    with pytest.raises(RuntimeError, match="requires PCAP2LLM_VAULT_KEY"):
        protector.validate_vault_key()


def test_encrypt_uses_supplied_env_key_and_vault_is_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("PCAP2LLM_VAULT_KEY", key)
    protector = Protector({"imsi": "encrypt"})
    protector.validate_vault_key()
    packets = [{"message": {"protocol": "diameter", "fields": {"diameter.imsi": "001010123456789"}}}]
    protected = protector.protect_packets(packets)

    encrypted = protected[0]["message"]["fields"]["diameter.imsi"]
    assert encrypted != "001010123456789"

    vault = protector.vault_metadata()
    assert vault is not None
    assert vault["key_source"] == "env:PCAP2LLM_VAULT_KEY"
    assert all("secret" not in note.lower() or "never" in note.lower() for note in vault["notes"])


def test_free_text_payload_with_email_uri_and_token_is_masked() -> None:
    protector = Protector({"payload_text": "mask"})
    packets = [
        {
            "top_protocol": "http2",
            "message": {
                "protocol": "http2",
                "fields": {
                    "payload.blob": "Contact ops@example.com via https://core.local using Bearer abc123",
                },
            },
        }
    ]

    protected = protector.protect_packets(packets)
    assert protected[0]["message"]["fields"]["payload.blob"] == "[redacted]"


def test_imei_keep_tac_mask_serial_mode_preserves_tac_prefix() -> None:
    protector = Protector({"imei": "keep_tac_mask_serial"})
    packets = [
        {
            "message": {
                "protocol": "ngap",
                "fields": {
                    "ngap.pei": "490154203237518",
                },
            },
        }
    ]

    protected = protector.protect_packets(packets)
    assert protected[0]["message"]["fields"]["ngap.pei"] == "49015420XXXXXXX"


def test_mixed_case_nested_dns_hostname_is_caught() -> None:
    protector = Protector({"hostname": "mask"})
    packets = [
        {
            "top_protocol": "dns",
            "message": {
                "protocol": "dns",
                "fields": {
                    "Outer": {
                        "Dns.Qry.Name": "subscriber.core.local",
                    }
                },
            },
        }
    ]

    protected = protector.protect_packets(packets)
    assert protected[0]["message"]["fields"]["Outer"]["Dns.Qry.Name"] == "[redacted]"
