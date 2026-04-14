# Current Pipeline

This page explains the current internal stage model behind `inspect`,
`discover`, and `analyze`.

Related docs:

- [`../DOCUMENTATION_MAP.md`](../DOCUMENTATION_MAP.md)
- [`scaling_plan.md`](scaling_plan.md)
- [`../schema/detail.schema.md`](../schema/detail.schema.md)
- [`../schema/summary.schema.md`](../schema/summary.schema.md)

The current processing architecture is intentionally split into explicit stages so the public artifact contract is not coupled directly to raw TShark output.

## Stages

1. `inspect`
   - run TShark export
   - inspect packet count, timestamps, protocols, conversations, anomalies
2. `select`
   - decide how many packets are eligible for the primary `detail.json` artifact
   - keep truncation explicit
3. `normalize`
   - map raw TShark JSON into normalized packet/message structures
4. `summarize`
   - derive deterministic counts, timing summaries, and anomaly summaries
5. `protect`
   - apply privacy-policy classification and selected actions
6. `serialize`
   - validate public `summary.json` and `detail.json` artifacts against Schema 1.0
   - render `summary.md` as a human-readable sidecar

## Design Intent

- `detail.json` is the primary LLM handoff artifact
- `summary.json` and `summary.md` are sidecars
- bounded formatting is explicit
- internal extraction can evolve without changing the public contract
