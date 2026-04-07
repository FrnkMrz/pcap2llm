from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

from pcap2llm.config import load_yaml_or_json
from pcap2llm.models import ResolvedEndpoint

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Port → protocol role inference
# Covers common telecom and network service ports.
# ---------------------------------------------------------------------------

_PORT_ROLE_MAP: dict[int, str] = {
    53: "dns",
    80: "http",
    443: "tls",
    2123: "gtpc",
    2152: "gtpu",
    2905: "m3ua-ss7",
    3868: "diameter",
    8805: "pfcp",
    36422: "s1ap",
    38412: "ngap",
}


# ---------------------------------------------------------------------------
# File readers
# ---------------------------------------------------------------------------

def _read_hosts_file(path: Path) -> dict[str, dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, hostname = parts[0], parts[1]
        hosts[ip] = {"ip": ip, "hostname": hostname, "alias": hostname}
    return hosts


def _read_mapping_file(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[tuple[Any, dict[str, Any]]]]:
    """Parse a YAML/JSON mapping file.

    Returns ``(by_ip, by_hostname_lower, cidr_entries)`` where:

    - ``by_ip`` maps exact IP strings to entry dicts
    - ``by_hostname_lower`` maps lowercase hostname strings to entry dicts
    - ``cidr_entries`` is a list of ``(network_object, entry)`` pairs
    """
    payload = load_yaml_or_json(path)
    by_ip: dict[str, dict[str, Any]] = {}
    by_hostname: dict[str, dict[str, Any]] = {}
    cidr_entries: list[tuple[Any, dict[str, Any]]] = []

    for node in payload.get("nodes", []):
        if not isinstance(node, dict):
            continue
        entry = {
            "ip": node.get("ip"),
            "hostname": node.get("hostname"),
            "alias": node.get("alias"),
            "role": node.get("role"),
            "site": node.get("site"),
            "labels": {
                key: value
                for key, value in node.items()
                if key not in {"ip", "hostname", "alias", "role", "site", "cidr"}
            },
        }
        if node.get("ip"):
            by_ip[str(node["ip"])] = entry
        if node.get("hostname"):
            by_hostname[str(node["hostname"]).lower()] = entry
        if node.get("cidr"):
            try:
                net = ipaddress.ip_network(str(node["cidr"]), strict=False)
                cidr_entries.append((net, entry))
            except ValueError:
                logger.warning("Invalid CIDR in mapping file, skipping: %s", node["cidr"])

    return by_ip, by_hostname, cidr_entries


# ---------------------------------------------------------------------------
# EndpointResolver
# ---------------------------------------------------------------------------

class EndpointResolver:
    """Resolves IP addresses and hostnames to enriched :class:`ResolvedEndpoint` objects.

    Resolution order:
    1. Exact IP match in ``by_ip`` table
    2. Exact hostname match (case-insensitive) in ``by_hostname`` table
    3. CIDR/prefix match (first matching subnet wins)
    4. Port-based role inference using well-known telecom service ports
    """

    def __init__(self, hosts_file: Path | None = None, mapping_file: Path | None = None) -> None:
        self._by_ip: dict[str, dict[str, Any]] = {}
        self._by_hostname: dict[str, dict[str, Any]] = {}  # keys are lowercase
        self._cidr_entries: list[tuple[Any, dict[str, Any]]] = []

        if hosts_file:
            for ip, entry in _read_hosts_file(hosts_file).items():
                self._by_ip[ip] = entry
                if entry.get("hostname"):
                    self._by_hostname[entry["hostname"].lower()] = entry

        if mapping_file:
            by_ip, by_hostname, cidr_entries = _read_mapping_file(mapping_file)
            self._by_ip.update(by_ip)
            self._by_hostname.update(by_hostname)
            self._cidr_entries.extend(cidr_entries)

    def _match_cidr(self, ip: str) -> dict[str, Any] | None:
        """Return the first CIDR entry whose network contains *ip*, or ``None``."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, entry in self._cidr_entries:
            if addr in net:
                return entry
        return None

    def _infer_role_from_port(self, service_port: int | None) -> str | None:
        """Return a protocol role string for a known service port, or ``None``."""
        if service_port is None:
            return None
        return _PORT_ROLE_MAP.get(service_port)

    def resolve(
        self,
        ip: str | None,
        hostname: str | None = None,
        service_port: int | None = None,
    ) -> ResolvedEndpoint:
        """Resolve *ip* (and optionally *hostname*) to a :class:`ResolvedEndpoint`.

        Args:
            ip: IP address string (IPv4 or IPv6).
            hostname: Optional DNS hostname for the endpoint.
            service_port: Well-known port for this endpoint (used for role
                inference when no mapping entry is found).
        """
        entry: dict[str, Any] = {}

        if ip and ip in self._by_ip:
            entry = self._by_ip[ip]
        elif hostname and hostname.lower() in self._by_hostname:
            entry = self._by_hostname[hostname.lower()]
        elif ip:
            entry = self._match_cidr(ip) or {}

        # Port-based role inference as final fallback
        role = entry.get("role") or self._infer_role_from_port(service_port)

        return ResolvedEndpoint(
            ip=ip,
            hostname=hostname or entry.get("hostname"),
            alias=entry.get("alias"),
            role=role,
            site=entry.get("site"),
            labels=entry.get("labels", {}),
        )
