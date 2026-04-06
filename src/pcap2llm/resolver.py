from __future__ import annotations

from pathlib import Path
from typing import Any

from pcap2llm.config import load_yaml_or_json
from pcap2llm.models import ResolvedEndpoint


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


def _read_mapping_file(path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    payload = load_yaml_or_json(path)
    by_ip: dict[str, dict[str, Any]] = {}
    by_hostname: dict[str, dict[str, Any]] = {}
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
                if key not in {"ip", "hostname", "alias", "role", "site"}
            },
        }
        if entry["ip"]:
            by_ip[str(entry["ip"])] = entry
        if entry["hostname"]:
            by_hostname[str(entry["hostname"])] = entry
    return by_ip, by_hostname


class EndpointResolver:
    def __init__(self, hosts_file: Path | None = None, mapping_file: Path | None = None) -> None:
        self._by_ip: dict[str, dict[str, Any]] = {}
        self._by_hostname: dict[str, dict[str, Any]] = {}

        if hosts_file:
            self._by_ip.update(_read_hosts_file(hosts_file))
        if mapping_file:
            by_ip, by_hostname = _read_mapping_file(mapping_file)
            self._by_ip.update(by_ip)
            self._by_hostname.update(by_hostname)

    def resolve(self, ip: str | None, hostname: str | None = None) -> ResolvedEndpoint:
        entry: dict[str, Any] = {}
        if ip and ip in self._by_ip:
            entry = self._by_ip[ip]
        elif hostname and hostname in self._by_hostname:
            entry = self._by_hostname[hostname]
        return ResolvedEndpoint(
            ip=ip,
            hostname=hostname or entry.get("hostname"),
            alias=entry.get("alias"),
            role=entry.get("role"),
            site=entry.get("site"),
            labels=entry.get("labels", {}),
        )
