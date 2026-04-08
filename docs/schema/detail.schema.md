# Detail Artifact Schema 1.0

`detail.json` is the primary stable artifact intended for a downstream LLM step.

## Stability Guarantee

- Schema 1.0 defines the public handoff contract.
- Internal TShark extraction may change without changing this artifact structure.

## Required Top-Level Fields

- `schema_version`: string, currently `1.0`
- `generated_at`: ISO 8601 UTC timestamp
- `capture_sha256`: string or `null`
- `profile`: analysis profile name
- `artifact_role`: always `llm_input`
- `coverage`: included vs. available packet counts and truncation status
- `messages`: list of normalized, reduced, protected packet/message objects

## Compatibility Field

- `selected_packets`: deprecated compatibility alias for `messages`

## Message Object Expectations

Each message entry is a reduced, privacy-controlled packet object with:

- packet number and timing context
- top protocol
- reduced transport context
- resolved endpoints
- message protocol and curated message fields
- privacy metadata where applicable

## Exclusions

- No uncontrolled raw TShark layer trees
- No generative analysis or root-cause claims
- No hidden truncation; coverage must make any limit explicit
