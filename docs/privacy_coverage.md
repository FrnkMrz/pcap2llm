# Privacy Coverage

This page maps the user-facing privacy controls onto the broader internal
coverage model.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md)
- [`security/threat_model.md`](security/threat_model.md)
- [`REFERENCE.md`](REFERENCE.md)

`pcap2llm` exposes configurable data classes at the CLI/profile level and maps them onto broader canonical privacy classes internally.

## Configurable Data Classes

- `ip`
- `hostname`
- `subscriber_id`
- `msisdn`
- `imsi`
- `imei`
- `email`
- `distinguished_name`
- `token`
- `uri`
- `apn_dnn`
- `diameter_identity`
- `payload_text`

## Canonical Classes

- `network_address`
- `subscriber_identifier`
- `device_identifier`
- `operator_internal_name`
- `application_secret`
- `payload_text`

## Protocol-Aware Coverage

Explicit rules currently cover:

- Diameter identities and selected subscriber-related AVPs
- NGAP / NAS-5GS subscriber and device identifiers
- APN / DNN values in GTPv2, NAS-EPS, NAS-5GS, and PFCP paths
- HTTP/2 authority, path, authorization, and cookie headers
- DNS and hostname-like fields
- free-form payload strings containing emails, URIs, tokens, IMSI-like or MSISDN-like values

## Known Limits

- Some path matching still depends on recognizable field names and protocol aliases.
- Free-text detection is heuristic by nature and should be treated as defense in depth, not perfect semantic understanding.
- Privacy audit output is intentionally compact and does not list sensitive values.
