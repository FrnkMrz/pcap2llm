import re

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
