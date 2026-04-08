# Summary Artifact Schema 1.0

`summary.json` is a compact sidecar artifact for operators, automation, and audit. It is not the primary LLM handoff artifact.

## Stability Guarantee

- Top-level field names in Schema 1.0 are stable unless a documented migration note says otherwise.
- Deprecated fields may remain for compatibility, but new consumers should prefer the non-deprecated names.

## Required Top-Level Fields

- `schema_version`: string, currently `1.0`
- `generated_at`: ISO 8601 UTC timestamp
- `capture_sha256`: string or `null`
- `profile`: analysis profile name
- `artifact_role`: always `summary_sidecar`
- `capture_metadata`: capture file metadata and filter context
- `relevant_protocols`: list of protocol names
- `conversations`: list of summarized conversation rows
- `packet_message_counts`: packet, transport, and top-protocol counters
- `anomalies`: list of deterministic anomaly strings
- `anomaly_counts_by_layer`: layer-tag counter object
- `deterministic_findings`: deterministic summary findings derived from counts/timing only
- `privacy_modes`: effective privacy modes per data class
- `privacy_policy`: policy metadata, rule layers, and canonical privacy classes
- `coverage`: summary/detail coverage and truncation metadata

## Optional Fields

- `timing_stats`
- `burst_periods`
- `dropped_packets`
- `detail_truncated`
- `privacy_audit`
- `probable_notable_findings`

## Deprecated Fields

- `probable_notable_findings`: compatibility alias for `deterministic_findings`

## Notes

- No raw TShark layer dumps belong here.
- Coverage metadata must explain whether the primary `detail.json` handoff artifact is truncated.
