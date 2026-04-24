from __future__ import annotations

import csv
from datetime import datetime, timezone
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

_SUPPORTED_NETWORK_ELEMENT_TYPES: set[str] = {
    "HSS",
    "UDM",
    "DRA",
    "GGSN",
    "PGW",
    "SGW",
    "MME",
    "AMF",
    "SMF",
    "UPF",
    "MSS",
    "MSC",
    "eNodeB",
    "gNodeB",
    "DNS",
    "Firewall",
    "Router",
}

_CANONICAL_NETWORK_ELEMENT: dict[str, str] = {
    item.lower(): item for item in _SUPPORTED_NETWORK_ELEMENT_TYPES
}

_HOSTNAME_PATTERNS: list[tuple[str, str]] = [
    ("hss", "HSS"),
    ("udm", "UDM"),
    ("dra", "DRA"),
    ("ggsn", "GGSN"),
    ("pgw", "PGW"),
    ("sgw", "SGW"),
    ("mme", "MME"),
    ("amf", "AMF"),
    ("smf", "SMF"),
    ("upf", "UPF"),
    ("mss", "MSS"),
    ("msc", "MSC"),
    ("enb", "eNodeB"),
    ("gnb", "gNodeB"),
    ("dns", "DNS"),
    ("firewall", "Firewall"),
    ("fw", "Firewall"),
    ("router", "Router"),
]

_PORT_NETWORK_ELEMENT_MAP: dict[int, tuple[str, list[str]]] = {
    53: ("DNS", ["DNS"]),
    3868: ("DRA", ["DRA", "HSS"]),
    2123: ("SGW", ["SGW", "PGW", "MME"]),
    2152: ("UPF", ["UPF"]),
    36412: ("MME", ["MME", "eNodeB"]),
    38412: ("AMF", ["AMF", "gNodeB"]),
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


def _read_subnets_file(path: Path) -> list[tuple[Any, dict[str, Any]]]:
    """Parse a local tabular subnet file into CIDR resolver entries.

    Expected format per non-comment line::

        <cidr> <alias>

    Whitespace between both columns may be spaces or tabs. Additional text after
    the first whitespace is treated as part of the alias.
    """
    cidr_entries: list[tuple[Any, dict[str, Any]]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            logger.warning("Invalid subnet line in %s:%d; expected '<cidr> <alias>'", path, line_number)
            continue
        cidr, alias = parts[0], parts[1].strip()
        if not alias:
            logger.warning("Invalid subnet line in %s:%d; alias is empty", path, line_number)
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("Invalid CIDR in subnet file %s:%d: %s", path, line_number, cidr)
            continue
        cidr_entries.append(
            (
                net,
                {
                    "ip": None,
                    "hostname": None,
                    "alias": alias,
                    "role": None,
                    "site": None,
                    "labels": {},
                },
            )
        )
    return cidr_entries


def _normalize_point_code(value: Any) -> str | None:
    if value in (None, ""):
        return None
    normalized = str(value).strip().upper()
    return normalized or None


def _read_ss7pcs_file(path: Path) -> dict[str, dict[str, Any]]:
    """Parse a local point-code mapping file.

    Expected format per non-comment line::

        <point-code> <alias>
    """
    by_point_code: dict[str, dict[str, Any]] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            logger.warning("Invalid SS7 point-code line in %s:%d; expected '<point-code> <alias>'", path, line_number)
            continue
        point_code = _normalize_point_code(parts[0])
        alias = parts[1].strip()
        if not point_code or not alias:
            logger.warning("Invalid SS7 point-code line in %s:%d; missing point code or alias", path, line_number)
            continue
        by_point_code[point_code] = {
            "ip": None,
            "hostname": None,
            "alias": alias,
            "role": "ss7",
            "site": None,
            "labels": {"ss7_point_code": point_code},
        }
    return by_point_code


def _load_network_element_mapping_csv(path: Path) -> tuple[dict[str, str], list[tuple[Any, str]]]:
    """Load strict network element mappings from CSV.

    Expected columns: ``type,value,network_element_type``
    where ``type`` is ``ip`` or ``subnet``.
    """
    by_ip: dict[str, str] = {}
    by_subnet: list[tuple[Any, str]] = []

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        expected = {"type", "value", "network_element_type"}
        if not reader.fieldnames or set(reader.fieldnames) != expected:
            raise ValueError(
                "Invalid network element mapping header. Expected: type,value,network_element_type"
            )

        for idx, row in enumerate(reader, start=2):
            kind = str(row.get("type", "")).strip().lower()
            value = str(row.get("value", "")).strip()
            element_raw = str(row.get("network_element_type", "")).strip()
            element = _CANONICAL_NETWORK_ELEMENT.get(element_raw.lower())

            if kind not in {"ip", "subnet"}:
                raise ValueError(f"Invalid type at line {idx}: {kind}")
            if not value:
                raise ValueError(f"Missing value at line {idx}")
            if not element:
                raise ValueError(f"Unsupported network_element_type at line {idx}: {element_raw}")

            if kind == "ip":
                try:
                    ip = str(ipaddress.ip_address(value))
                except ValueError as exc:
                    raise ValueError(f"Invalid IP at line {idx}: {value}") from exc
                by_ip[ip] = element
            else:
                try:
                    net = ipaddress.ip_network(value, strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid CIDR at line {idx}: {value}") from exc
                by_subnet.append((net, element))

    return by_ip, by_subnet


def _hostname_pattern_match(hostname: str | None) -> str | None:
    if not hostname:
        return None
    lowered = hostname.lower()
    for pattern, element in _HOSTNAME_PATTERNS:
        if pattern in lowered:
            return element
    return None


def _protocol_port_match(ports: list[int]) -> tuple[str, str | None] | None:
    for port in ports:
        mapping = _PORT_NETWORK_ELEMENT_MAP.get(port)
        if not mapping:
            continue
        detected, candidates = mapping
        warning = None
        if len(candidates) > 1:
            warning = f"Protocol-port heuristic is ambiguous ({'/'.join(candidates)})"
        return detected, warning
    return None


def _detect_network_element(
    *,
    ip: str | None,
    hostname: str | None,
    ports: list[int],
    by_ip: dict[str, str],
    by_subnet: list[tuple[Any, str]],
    override: str | None,
) -> dict[str, Any]:
    """Detect network element type with strict priority and conflict warning."""
    canonical_override = _CANONICAL_NETWORK_ELEMENT.get((override or "").lower())
    if canonical_override:
        return {
            "type": canonical_override,
            "confidence": 100,
            "source": "manual_override",
            "warning": None,
            "overridden": True,
        }

    signals: list[dict[str, Any]] = []
    ip_norm: str | None = None
    if ip:
        try:
            ip_norm = str(ipaddress.ip_address(ip))
        except ValueError:
            ip_norm = ip

    # Step 1: exact IP mapping
    if ip_norm and ip_norm in by_ip:
        signals.append({"type": by_ip[ip_norm], "confidence": 100, "source": "ip_mapping"})

    # Step 2: subnet mapping
    if ip_norm:
        try:
            addr = ipaddress.ip_address(ip_norm)
            for net, element in by_subnet:
                if addr in net:
                    signals.append({"type": element, "confidence": 90, "source": "subnet_mapping"})
                    break
        except ValueError:
            pass

    # Step 3: hostname pattern
    host_match = _hostname_pattern_match(hostname)
    if host_match:
        signals.append({"type": host_match, "confidence": 80, "source": "hostname_pattern"})

    # Step 4: protocol/port heuristic
    protocol_match = _protocol_port_match(ports)
    protocol_warning = None
    if protocol_match:
        detected, protocol_warning = protocol_match
        signals.append({"type": detected, "confidence": 50, "source": "protocol"})

    if not signals:
        return {
            "type": "unknown",
            "confidence": 0,
            "source": "unknown",
            "warning": None,
            "overridden": False,
        }

    primary = signals[0]
    warning: str | None = protocol_warning
    for alt in signals[1:]:
        if alt["type"] != primary["type"]:
            warning = "Conflicting detection signals"
            break

    return {
        "type": primary["type"],
        "confidence": primary["confidence"],
        "source": primary["source"],
        "warning": warning,
        "overridden": False,
    }


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

    def __init__(
        self,
        hosts_file: Path | None = None,
        mapping_file: Path | None = None,
        subnets_file: Path | None = None,
        ss7pcs_file: Path | None = None,
        network_element_mapping_file: Path | None = None,
    ) -> None:
        self._by_ip: dict[str, dict[str, Any]] = {}
        self._by_hostname: dict[str, dict[str, Any]] = {}  # keys are lowercase
        self._cidr_entries: list[tuple[Any, dict[str, Any]]] = []
        self._by_point_code: dict[str, dict[str, Any]] = {}
        self._network_element_by_ip: dict[str, str] = {}
        self._network_element_by_subnet: list[tuple[Any, str]] = []

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

        if subnets_file:
            self._cidr_entries.extend(_read_subnets_file(subnets_file))

        if ss7pcs_file:
            self._by_point_code.update(_read_ss7pcs_file(ss7pcs_file))

        if network_element_mapping_file is None:
            default_path = Path("network_element_mapping.csv")
            if default_path.exists():
                network_element_mapping_file = default_path

        if network_element_mapping_file:
            try:
                by_ip, by_subnet = _load_network_element_mapping_csv(network_element_mapping_file)
                self._network_element_by_ip.update(by_ip)
                self._network_element_by_subnet.extend(by_subnet)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to parse network element mapping CSV %s: %s", network_element_mapping_file, exc)

    def _match_point_code(self, point_code: Any) -> dict[str, Any] | None:
        normalized = _normalize_point_code(point_code)
        if not normalized:
            return None
        return self._by_point_code.get(normalized)

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
        point_code: Any = None,
        observed_ports: list[int] | None = None,
        network_element_override: str | None = None,
    ) -> ResolvedEndpoint:
        """Resolve *ip* (and optionally *hostname*) to a :class:`ResolvedEndpoint`.

        Args:
            ip: IP address string (IPv4 or IPv6).
            hostname: Optional DNS hostname for the endpoint.
            service_port: Well-known port for this endpoint (used for role
                inference when no mapping entry is found).
            point_code: Optional SS7 point code for MTP3/SCCP signaling context.
        """
        entry: dict[str, Any] = {}
        point_code_entry = self._match_point_code(point_code)
        normalized_point_code = _normalize_point_code(point_code)

        if ip and ip in self._by_ip:
            entry = self._by_ip[ip]
        elif hostname and hostname.lower() in self._by_hostname:
            entry = self._by_hostname[hostname.lower()]
        elif ip:
            entry = self._match_cidr(ip) or {}
        if not entry and point_code_entry:
            entry = point_code_entry

        # Port-based role inference as final fallback
        role = entry.get("role") or self._infer_role_from_port(service_port)
        labels = dict(entry.get("labels", {}))
        if normalized_point_code:
            labels.setdefault("ss7_point_code", normalized_point_code)
        if point_code_entry and point_code_entry.get("alias"):
            labels.setdefault("ss7_point_code_alias", point_code_entry["alias"])

        ports: list[int] = []
        if isinstance(service_port, int):
            ports.append(service_port)
        if observed_ports:
            ports.extend([port for port in observed_ports if isinstance(port, int)])
        # Preserve order while deduplicating.
        dedup_ports = list(dict.fromkeys(ports))
        override = network_element_override or entry.get("network_element_override")
        detection_context = bool(
            self._network_element_by_ip
            or self._network_element_by_subnet
            or override
            or hostname
            or entry.get("hostname")
        )
        if detection_context:
            detection = _detect_network_element(
                ip=ip,
                hostname=hostname or entry.get("hostname"),
                ports=dedup_ports,
                by_ip=self._network_element_by_ip,
                by_subnet=self._network_element_by_subnet,
                override=override,
            )
            labels["network_element_type"] = detection["type"]
            labels["network_element_confidence"] = detection["confidence"]
            labels["network_element_source"] = detection["source"]
            if detection.get("warning"):
                labels["network_element_warning"] = detection["warning"]
            if detection.get("overridden") and override:
                labels["network_element_override"] = override

            if ip:
                timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                logger.info(
                    "%s,%s,%s,%s,%s",
                    timestamp,
                    ip,
                    detection["type"],
                    detection["confidence"],
                    detection["source"],
                )

        return ResolvedEndpoint(
            ip=ip,
            hostname=hostname or entry.get("hostname"),
            alias=entry.get("alias"),
            role=role,
            site=entry.get("site"),
            labels=labels,
        )
