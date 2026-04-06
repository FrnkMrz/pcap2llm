from pathlib import Path

from pcap2llm.resolver import EndpointResolver


def test_mapping_file_overrides_hosts(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("10.10.1.11 mme-fra-a\n", encoding="utf-8")
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(
        """
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: fra
""".strip(),
        encoding="utf-8",
    )
    resolver = EndpointResolver(hosts_file=hosts, mapping_file=mapping)
    endpoint = resolver.resolve("10.10.1.11")
    assert endpoint.alias == "MME_FRA_A"
    assert endpoint.role == "mme"
    assert endpoint.site == "fra"
