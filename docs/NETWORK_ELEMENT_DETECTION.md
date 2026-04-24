# Network Element Detection

## Purpose

Automatic detection of endpoint network-element type for enrichment and filtering.

## Supported Types

- HSS
- UDM
- DRA
- GGSN
- PGW
- SGW
- MME
- AMF
- SMF
- UPF
- MSS
- MSC
- eNodeB
- gNodeB
- DNS
- Firewall
- Router

## Mapping File

File name: `network_element_mapping.csv`

Expected columns (strict):

```csv
type,value,network_element_type
ip,10.10.10.21,HSS
subnet,10.20.30.0/24,DRA
```

Rules:

- `type`: `ip` or `subnet`
- `value`: valid IPv4/IPv6 address or CIDR
- `network_element_type`: one of the supported types

A sample is provided at `examples/network_element_mapping.csv`.

The resolver auto-loads `network_element_mapping.csv` from the current working directory if present.

## Detection Order

1. Exact IP mapping (confidence 100, source `ip_mapping`)
2. Subnet mapping (confidence 90, source `subnet_mapping`)
3. Hostname patterns (confidence 80, source `hostname_pattern`)
4. Protocol/port heuristics (confidence 50, source `protocol`)
5. Fallback unknown (confidence 0, source `unknown`)

## Conflict Handling

If lower-priority signals disagree with the selected type, warning is set to:

- `Conflicting detection signals`

## Manual Override

`EndpointResolver.resolve(..., network_element_override="HSS")`

Override always wins:

- source: `manual_override`
- confidence: `100`

## Output Fields

Detection values are attached under endpoint labels:

- `network_element_type`
- `network_element_confidence`
- `network_element_source`
- `network_element_warning` (optional)
- `network_element_override` (optional)

These fields are also propagated into `capture_metadata.resolved_peers` when available.

## Detection Logging

When detection is active, each resolved endpoint is logged as CSV-style line:

`timestamp,ip,detected_type,confidence,source`
