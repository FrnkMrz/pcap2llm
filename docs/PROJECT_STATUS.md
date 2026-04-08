# Project Status

`pcap2llm` is an early but serious CLI tool for turning focused telecom captures into stable artifacts that can be handed to a downstream LLM.

## Maturity

- Project maturity: early alpha
- Support expectation: best effort
- Change policy: public artifact fields are moving toward a documented Schema 1.0 contract

## Intended Use

- Focused troubleshooting captures for LTE/EPC, 5G core, and related control-plane flows
- Deterministic trace formatting and privacy-controlled artifact generation
- Preparing an artifact for a second-step LLM review

## Not Intended

- Replacing Wireshark for deep packet inspection
- Running generative or agentic AI analysis inside the tool
- Dumping long, noisy, unfiltered rolling captures straight into an LLM workflow

## Security And Privacy Warnings

- Generated artifacts may still contain sensitive telecom metadata unless the privacy policy is configured appropriately.
- Encryption protects values only when the vault key is handled separately and carefully.
- `summary.md` and `summary.json` must be treated as shareable outputs only after verifying the selected privacy profile.

## Known Limits

- Best results come from focused traces and explicit display filters.
- Large captures are bounded for detail export, but the underlying TShark JSON ingestion is still full-load in memory.
- A default pre-export size guard exists to catch accidental large inputs early; disabling it should be an explicit operator decision.
- TShark version drift can affect raw extraction, which is why public serializer contracts are validated.
