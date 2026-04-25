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

Most configurable data classes support the standard protection modes
`keep`, `mask`, `pseudonymize`, `encrypt`, and `remove`.

`imei` also supports the specialized mode `keep_tac_mask_serial`, which keeps
the TAC prefix visible and masks the serial suffix. This specialized mode does
not apply to `email`.

`imsi` supports telecom-aware partial modes:

- `keep_mcc_mnc_mask_msin`
- `keep_mcc_mnc_pseudonymize_msin`
- `keep_mcc_mnc_encrypt_msin`

These keep the E.212 MCC/MNC routing context and protect the MSIN suffix. By
default, MCC `3xx` uses a 3-digit MNC and other MCCs use a 2-digit MNC unless
`numbering.imsi_mnc_lengths` overrides the MCC.

`msisdn` supports E.164-aware partial modes:

- `keep_cc_ndc_mask_subscriber`
- `keep_cc_ndc_pseudonymize_subscriber`
- `keep_cc_ndc_encrypt_subscriber`

These keep the E.164 country code visible and protect the subscriber suffix.
Germany is the built-in exception: known German mobile NDCs remain visible.
Use `numbering.msisdn_ndc_prefixes` for roaming-partner-specific CC/NDC plans.

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
