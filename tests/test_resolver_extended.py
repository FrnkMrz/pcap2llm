"""Extended resolver tests for CIDR matching, case-insensitive hostname, and port inference."""
from __future__ import annotations

from pathlib import Path

from pcap2llm.resolver import EndpointResolver, _PORT_ROLE_MAP


class TestCidrMatching:
    def test_cidr_match_resolves_ip_in_subnet(self, tmp_path: Path) -> None:
        mapping = tmp_path / "mapping.yaml"
        mapping.write_text(
            """
nodes:
  - cidr: 10.10.0.0/16
    alias: EPC_CORE
    role: epc
    site: Frankfurt
""".strip(),
            encoding="utf-8",
        )
        resolver = EndpointResolver(mapping_file=mapping)
        ep = resolver.resolve("10.10.5.20")
        assert ep.alias == "EPC_CORE"
        assert ep.role == "epc"
        assert ep.site == "Frankfurt"
        assert ep.ip == "10.10.5.20"

    def test_cidr_match_not_triggered_for_ip_outside_subnet(self, tmp_path: Path) -> None:
        mapping = tmp_path / "mapping.yaml"
        mapping.write_text(
            """
nodes:
  - cidr: 10.10.0.0/24
    alias: SUBNET_A
    role: core
""".strip(),
            encoding="utf-8",
        )
        resolver = EndpointResolver(mapping_file=mapping)
        ep = resolver.resolve("10.11.0.1")
        assert ep.alias is None

    def test_exact_ip_takes_priority_over_cidr(self, tmp_path: Path) -> None:
        mapping = tmp_path / "mapping.yaml"
        mapping.write_text(
            """
nodes:
  - ip: 10.10.0.1
    alias: SPECIFIC_NODE
    role: mme
  - cidr: 10.10.0.0/16
    alias: GENERIC_SUBNET
    role: epc
""".strip(),
            encoding="utf-8",
        )
        resolver = EndpointResolver(mapping_file=mapping)
        ep = resolver.resolve("10.10.0.1")
        assert ep.alias == "SPECIFIC_NODE"
        assert ep.role == "mme"

    def test_invalid_cidr_is_skipped_without_crash(self, tmp_path: Path) -> None:
        mapping = tmp_path / "mapping.yaml"
        mapping.write_text(
            """
nodes:
  - cidr: not-a-valid-cidr
    alias: BAD
  - ip: 10.0.0.1
    alias: GOOD
""".strip(),
            encoding="utf-8",
        )
        resolver = EndpointResolver(mapping_file=mapping)
        ep = resolver.resolve("10.0.0.1")
        assert ep.alias == "GOOD"

    def test_cidr_ipv6_match(self, tmp_path: Path) -> None:
        mapping = tmp_path / "mapping.yaml"
        mapping.write_text(
            """
nodes:
  - cidr: 2001:db8::/32
    alias: IPV6_CORE
    role: core
""".strip(),
            encoding="utf-8",
        )
        resolver = EndpointResolver(mapping_file=mapping)
        ep = resolver.resolve("2001:db8::1")
        assert ep.alias == "IPV6_CORE"

    def test_subnets_file_resolves_ip_in_subnet(self, tmp_path: Path) -> None:
        subnets = tmp_path / "Subnets"
        subnets.write_text(
            "10.10.0.0/16 EPC_CORE\n",
            encoding="utf-8",
        )
        resolver = EndpointResolver(subnets_file=subnets)
        ep = resolver.resolve("10.10.5.20")
        assert ep.alias == "EPC_CORE"
        assert ep.ip == "10.10.5.20"

    def test_hosts_exact_ip_takes_priority_over_subnets_file(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text("10.10.5.20 mme-exact\n", encoding="utf-8")
        subnets = tmp_path / "Subnets"
        subnets.write_text("10.10.0.0/16 EPC_CORE\n", encoding="utf-8")
        resolver = EndpointResolver(hosts_file=hosts, subnets_file=subnets)
        ep = resolver.resolve("10.10.5.20")
        assert ep.alias == "mme-exact"

    def test_invalid_subnets_line_is_skipped_without_crash(self, tmp_path: Path) -> None:
        subnets = tmp_path / "Subnets"
        subnets.write_text(
            "not-a-cidr BROKEN\n10.10.0.0/16 EPC_CORE\n",
            encoding="utf-8",
        )
        resolver = EndpointResolver(subnets_file=subnets)
        ep = resolver.resolve("10.10.1.1")
        assert ep.alias == "EPC_CORE"

    def test_ss7_point_code_fallback_resolves_alias(self, tmp_path: Path) -> None:
        ss7pcs = tmp_path / "ss7pcs"
        ss7pcs.write_text("0-5093 VZB\n", encoding="utf-8")
        resolver = EndpointResolver(ss7pcs_file=ss7pcs)
        ep = resolver.resolve("10.10.5.20", point_code="0-5093")
        assert ep.alias == "VZB"
        assert ep.role == "ss7"
        assert ep.labels["ss7_point_code"] == "0-5093"

    def test_exact_ip_takes_priority_over_ss7_point_code_fallback(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text("10.10.5.20 mme-exact\n", encoding="utf-8")
        ss7pcs = tmp_path / "ss7pcs"
        ss7pcs.write_text("0-5093 VZB\n", encoding="utf-8")
        resolver = EndpointResolver(hosts_file=hosts, ss7pcs_file=ss7pcs)
        ep = resolver.resolve("10.10.5.20", point_code="0-5093")
        assert ep.alias == "mme-exact"
        assert ep.labels["ss7_point_code_alias"] == "VZB"


class TestCaseInsensitiveHostname:
    def test_hostname_lookup_is_case_insensitive(self, tmp_path: Path) -> None:
        mapping = tmp_path / "mapping.yaml"
        mapping.write_text(
            """
nodes:
  - hostname: MME.Example.COM
    alias: MME_NODE
    role: mme
""".strip(),
            encoding="utf-8",
        )
        resolver = EndpointResolver(mapping_file=mapping)
        # Lookup with different case
        ep = resolver.resolve(None, hostname="mme.example.com")
        assert ep.alias == "MME_NODE"
        ep2 = resolver.resolve(None, hostname="MME.EXAMPLE.COM")
        assert ep2.alias == "MME_NODE"

    def test_hosts_file_hostname_lookup_is_case_insensitive(self, tmp_path: Path) -> None:
        hosts = tmp_path / "hosts"
        hosts.write_text("192.168.1.1 HSS.Core.Net\n", encoding="utf-8")
        resolver = EndpointResolver(hosts_file=hosts)
        # Looking up by hostname should be case-insensitive
        ep = resolver.resolve(None, hostname="hss.core.net")
        assert ep.alias == "HSS.Core.Net"


class TestPortBasedRoleInference:
    def test_diameter_port_infers_role(self) -> None:
        resolver = EndpointResolver()
        ep = resolver.resolve("10.0.0.1", service_port=3868)
        assert ep.role == "diameter"

    def test_gtpc_port_infers_role(self) -> None:
        resolver = EndpointResolver()
        ep = resolver.resolve("10.0.0.2", service_port=2123)
        assert ep.role == "gtpc"

    def test_pfcp_port_infers_role(self) -> None:
        resolver = EndpointResolver()
        ep = resolver.resolve("10.0.0.3", service_port=8805)
        assert ep.role == "pfcp"

    def test_unknown_port_produces_no_role(self) -> None:
        resolver = EndpointResolver()
        ep = resolver.resolve("10.0.0.4", service_port=12345)
        assert ep.role is None

    def test_mapped_role_takes_priority_over_port_inference(self, tmp_path: Path) -> None:
        mapping = tmp_path / "mapping.yaml"
        mapping.write_text(
            """
nodes:
  - ip: 10.0.0.1
    alias: HSS_NODE
    role: hss
""".strip(),
            encoding="utf-8",
        )
        resolver = EndpointResolver(mapping_file=mapping)
        ep = resolver.resolve("10.0.0.1", service_port=3868)
        # Mapping role wins over port inference
        assert ep.role == "hss"
        assert ep.alias == "HSS_NODE"

    def test_port_role_map_covers_expected_ports(self) -> None:
        expected = {3868, 2123, 2152, 36422, 38412, 8805, 2905, 53, 443, 80}
        assert expected.issubset(set(_PORT_ROLE_MAP.keys()))


class TestResolverNoMappings:
    def test_unknown_ip_returns_bare_endpoint(self) -> None:
        resolver = EndpointResolver()
        ep = resolver.resolve("1.2.3.4")
        assert ep.ip == "1.2.3.4"
        assert ep.alias is None
        assert ep.role is None

    def test_none_ip_returns_empty_endpoint(self) -> None:
        resolver = EndpointResolver()
        ep = resolver.resolve(None)
        assert ep.ip is None
