from pcap2llm.protector import Protector


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
    assert protected[0]["message"]["fields"]["diameter.imsi"] == "IMSI_0001"
    assert "auth.token" not in protected[0]["message"]["fields"]
