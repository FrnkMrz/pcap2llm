# Project Status

`pcap2llm` is an early but serious CLI tool for turning focused telecom captures into stable artifacts that can be handed to a downstream LLM.

## Maturity

- Project maturity: beta — core pipeline, privacy model, discovery, and LLM-mode contract are stable; profile coverage is broad; API surface is hardening
- Support expectation: best effort
- Release posture: suitable for controlled internal and integration use; the artifact contract is stable enough to build downstream consumers against
- Change policy: public artifact fields follow a documented Schema 1.0 contract; `detail.json` is the primary stable handoff surface; `discovery.json` structure is declared stable as of the core-name-resolution release

## Intended Use

- Focused troubleshooting captures for LTE/EPC, 5G core, and related control-plane flows
- Deterministic trace formatting and privacy-controlled artifact generation
- LLM preparation: preparing a stable artifact set for a second-step LLM review
- `--llm-mode` as the current machine-friendly integration path for external agent and orchestration workflows

## Not Intended

- Replacing Wireshark for deep packet inspection
- Running generative or agentic AI analysis inside the tool
- Dumping long, noisy, unfiltered rolling captures straight into an LLM workflow
- Providing a Python SDK, service interface, or MCP integration in the current phase

## Current Public Interface

- Primary artifact contract: `detail.json`
- Context and audit sidecars: `summary.json` and `summary.md`
- Optional machine-readable CLI contract: `pcap2llm analyze ... --llm-mode`
- Artifact structure is part of the product surface; raw TShark JSON is not

## Current Operational Model

- The tool extracts packets with TShark, normalizes selected data, applies privacy policy decisions, and serializes bounded artifacts.
- The product boundary stops at readable artifact generation. Any inference, explanation, or diagnosis happens in a separate downstream step.
- `--llm-mode` does not change artifact semantics. It only changes the CLI return contract so external callers can parse outcomes, warnings, limits, and file paths reliably.

## Security And Privacy Warnings

- Generated artifacts may still contain sensitive telecom metadata unless the privacy policy is configured appropriately.
- Encryption protects values only when the vault key is handled separately and carefully.
- `summary.md` and `summary.json` must be treated as shareable outputs only after verifying the selected privacy profile.
- `vault.json` metadata and mapping sidecars should be treated as sensitive operational material even when the primary artifacts are shareable.

## Known Limits

- Best results come from focused traces and explicit display filters.
- Large captures are bounded for detail export. Pass-1 index records and pass-2 raw JSON are released from memory after each stage completes, so peak memory scales with `--max-packets`, not total capture size — but pass-1 still scans the full capture.
- A default pre-export size guard exists to catch accidental large inputs early; disabling it should be an explicit operator decision.
- TShark version drift can affect raw extraction, which is why public serializer contracts are validated.
- `--llm-mode` is available on `analyze` and `discover`; `inspect` and `session` commands still target human operators first.
- The CLI contract is stable enough for integration work, but still young enough that downstream consumers should pin versions and run contract tests.

## Near-Term Direction

- Keep hardening the artifact contract around deterministic formatting, privacy controls, and explicit coverage metadata.
- Expand regression protection around edge-case captures, truncation, and privacy leak prevention.
- Improve large-capture handling without widening the product scope into built-in AI analysis, service hosting, or full packet-browser workflows.
