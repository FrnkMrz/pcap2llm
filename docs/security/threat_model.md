# Threat Model

Related docs:

- [`../DOCUMENTATION_MAP.md`](../DOCUMENTATION_MAP.md)
- [`../PRIVACY_SHARING.md`](../PRIVACY_SHARING.md)
- [`../privacy_coverage.md`](../privacy_coverage.md)
- [`encryption_model.md`](encryption_model.md)

`pcap2llm` handles traces that may contain subscriber data, operator-internal topology, credentials, and customer content. The main job of the tool is to transform captures into readable artifacts without leaking data unintentionally.

## Assets To Protect

- IMSI, MSISDN, IMEI, SUPI, SUCI
- APN/DNN values
- Diameter Origin-Host and Destination-Host
- Hostnames, DNS names, URIs, URLs
- Bearer tokens, cookies, authorization headers
- Email addresses
- Free-form payload text and customer content

## Trust Boundaries

- Trusted environment: analyst workstation or controlled CI environment running local TShark
- Untrusted environment: external ticket systems, chat threads, third-party LLM services, shared drives
- Public artifacts must assume the eventual reader may be outside the trusted boundary

## Artifact Rules

What may remain visible depends on the privacy profile, but the following must be explicit and reviewable:

- `detail.json`: primary LLM handoff artifact, privacy-controlled and bounded
- `summary.json`: compact counts, anomalies, and policy metadata only
- `summary.md`: human-readable sidecar derived from `summary.json`

The tool must never silently leak:

- raw bearer tokens or cookies
- authorization headers
- full subscriber identifiers when the selected policy forbids them
- embedded emails or URLs inside free-form payload text when payload protection is enabled

## Encryption Limits

- Inline encryption is only meaningful if the key is stored separately from the shared artifacts.
- The default workflow must not encourage writing the decryption secret into the same share target as the artifacts.
- Encryption is not a substitute for disciplined handling of exported traces.

## Canonical Privacy Classes

- `network_address`
- `subscriber_identifier`
- `device_identifier`
- `operator_internal_name`
- `application_secret`
- `payload_text`

These map onto the current configurable data classes exposed by the CLI and privacy profiles.
