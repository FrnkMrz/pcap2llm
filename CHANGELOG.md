# Changelog

All notable changes to `pcap2llm` are documented in this file.

The format is intentionally simple and optimized for humans reading repo history during an early project phase.

## Unreleased

### Added

- Public Schema 1.0 documentation for the primary `detail.json` handoff artifact and the `summary.json` sidecar.
- Runtime-validated public artifact models for summary and detail outputs.
- Dedicated serializer layer so public artifacts are no longer shaped directly by raw TShark structures.
- Privacy policy engine with canonical privacy classes, protocol-aware classification, and policy metadata surfaced in artifacts.
- Threat model and project status documentation.
- Focused quickstarts for LTE/EPC, 5G core, HTTP/2/SBI, and privacy-safe sharing.
- Golden corpus fixtures, snapshot tests, and a `scripts/update_golden.py` helper to refresh expected artifacts intentionally.
- GitHub Actions CI workflow for linting, tests, build verification, and failure-artifact upload.
- `--fail-on-truncation` CLI option for workflows that must reject partial detail exports.
- `--llm-mode` for `analyze`, returning strict JSON on stdout for external agent and orchestration workflows.
- Stable CLI result payloads for success, dry-run, warnings, and errors, including machine-readable file paths, coverage, limits, and schema versions.
- Structured error-code mapping for common operational failures such as missing `tshark`, size-guard rejection, vault-key issues, truncation rejection, and artifact write failures.
- Dedicated tests for the `--llm-mode` contract, including sidecars, warnings, dry-run behavior, and error-path coverage.
- Standalone `docs/LLM_MODE.md` documentation for the machine-friendly CLI integration path.

### Changed

- Reframed the product boundary: `pcap2llm` is now documented as a deterministic trace formatter and artifact generator for a downstream LLM step, not as an AI analysis tool itself.
- `detail.json` is treated as the primary LLM handoff artifact; `summary.json` and `summary.md` are documented as sidecars.
- Artifact schema metadata moved to `schema_version = "1.0"` with explicit coverage/truncation information in public outputs.
- Summary findings are now documented and emitted as deterministic findings rather than probabilistic-sounding tool analysis.
- The processing pipeline is split conceptually into explicit stages: inspect, select, normalize, summarize, protect, and serialize.
- Package metadata now reflects Apache-2.0, the real maintainer, and project URLs.
- The CLI now has two explicit interaction styles:
  - human-oriented default output
  - `--llm-mode` machine-oriented output without changing the generated artifact set

### Privacy

- Free-form payload text can now be classified and protected through policy rules, not only field-name heuristics.
- Protocol-aware handling was added for Diameter identities, 5G identifiers, HTTP/2 authority/path/authorization headers, and related telecom-sensitive fields.
- Privacy behavior is documented more explicitly, including encryption boundaries and safe-sharing guidance.

### Tests

- Added schema contract tests for public artifact roles and required metadata.
- Added golden-corpus regression tests for LTE, Diameter, 5GC, HTTP/2, and mixed bounded captures.
- Hardened CLI help tests against ANSI/Rich output differences in CI environments.
