# Project Status

`pcap2llm` is a beta-stage telecom capture analysis tool with a stable
CLI-first workflow and an optional local Web GUI for upload-driven review,
reruns, and artifact inspection.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`REFERENCE.md`](REFERENCE.md)
- [`LLM_MODE.md`](LLM_MODE.md)
- [`SUPPORTED_ENVIRONMENTS.md`](SUPPORTED_ENVIRONMENTS.md)

## Maturity

- Project maturity: beta — core pipeline, privacy model, discovery, flow rendering,
  Web GUI, and LLM-mode contract are all usable; public interfaces are still
  being tightened and documented
- Support expectation: best effort
- Release posture: suitable for controlled internal and integration use; the
  artifact contract is stable enough to build downstream consumers against
- Change policy: public artifact fields follow a documented Schema 1.0 contract;
  `detail.json` is the primary stable handoff surface; `discovery.json`
  structure is declared stable as of the core-name-resolution release

## Intended Use

- Focused troubleshooting captures for LTE/EPC, 5G core, and related control-plane flows
- Deterministic trace formatting and privacy-controlled artifact generation
- LLM preparation: preparing a stable artifact set for a second-step LLM review
- `--llm-mode` as the current machine-friendly integration path for external agent and orchestration workflows
- Optional local browser-based workflow for analysts who prefer uploads,
  per-job review pages, inline flow previews, and local privacy-profile management

## Not Intended

- Replacing Wireshark for deep packet inspection
- Running generative or agentic AI analysis inside the tool
- Dumping long, noisy, unfiltered rolling captures straight into an LLM workflow
- Providing a Python SDK, hosted service interface, or MCP integration in the current phase
- Treating the Web GUI as an internet-facing production application without
  additional hardening

## Current Public Interface

- Primary CLI commands: `inspect`, `discover`, `recommend-profiles`, `analyze`,
  `visualize`, and session-oriented helpers
- Primary artifact contract: `detail.json`
- Context and audit sidecars: `summary.json` and `summary.md`
- Optional visual flow sidecars: `flow.json` and `flow.svg` from
  `analyze --render-flow-svg`
- Optional machine-readable CLI contract: `pcap2llm analyze ... --llm-mode`
- Optional local Web GUI for uploads, job reruns, downloads, inline flow review,
  logs, and local privacy-profile management
- Artifact structure is part of the product surface; raw TShark JSON is not

## Current Operational Model

- The tool extracts packets with TShark, normalizes selected data, applies privacy policy decisions, and serializes bounded artifacts.
- Optional flow rendering derives a deterministic endpoint/event/phase model from the protected detail packets; it does not add AI analysis.
- The optional Web GUI wraps the same local CLI-driven workflow and job
  workspace model; it is an operator convenience layer, not a second analysis engine.
- The product boundary stops at readable artifact generation. Any inference, explanation, or diagnosis happens in a separate downstream step.
- `--llm-mode` does not change artifact semantics. It only changes the CLI return contract so external callers can parse outcomes, warnings, limits, and file paths reliably.

## Security And Privacy Warnings

- Generated artifacts may still contain sensitive telecom metadata unless the privacy policy is configured appropriately.
- Encryption protects values only when the vault key is handled separately and carefully.
- `summary.md` and `summary.json` must be treated as shareable outputs only after verifying the selected privacy profile.
- `vault.json` metadata and mapping sidecars should be treated as sensitive operational material even when the primary artifacts are shareable.
- `flow.svg` and `flow.json` are derived artifacts, not inherently safe ones;
  their labels and hover text still need privacy review before sharing.
- The Web GUI is intended for local use by default and still has documented
  security gaps that matter for remote deployment.

## Known Limits

- Best results come from focused traces and explicit display filters.
- Large captures are bounded for detail export. Pass-1 index records and pass-2 raw JSON are released from memory after each stage completes, so peak memory scales with `--max-packets`, not total capture size — but pass-1 still scans the full capture.
- A default pre-export size guard exists to catch accidental large inputs early; disabling it should be an explicit operator decision.
- TShark version drift can affect raw extraction, which is why public serializer contracts are validated.
- `--llm-mode` is currently available on `analyze`; `inspect`, `discover`, and `session` commands still target human operators first.
- The CLI contract is stable enough for integration work, but still young enough that downstream consumers should pin versions and run contract tests.
- The Web GUI is local-first. Missing CSRF protection, authentication, and rate
  limiting mean it should not be treated as remotely exposed production software
  without follow-up hardening.

## Near-Term Direction

- Keep hardening the artifact contract around deterministic formatting, privacy controls, and explicit coverage metadata.
- Expand regression protection around edge-case captures, truncation, and privacy leak prevention.
- Improve large-capture handling without widening the product scope into built-in
  AI analysis, hosted service behavior, or full packet-browser workflows.
- Continue tightening the Web GUI documentation and local UX while keeping it a
  thin layer over the same deterministic pipeline.
