# Changelog

All notable changes to `pcap2llm` are documented in this file.

The format is intentionally simple and optimized for humans reading repo history during an early project phase.

## Unreleased

### Added — 2026-04-10

- **Oversize-ratio guard** (`--oversize-factor`, default 10×): after TShark export, if `total_exported > max_packets × factor` the pipeline fails fast with a clear error and a `-Y` hint. Fires after the inspection stage so `summary.json` statistics remain accurate; fires before the expensive normalization and protection stages. Set `--oversize-factor 0` to disable.
- New error code `capture_oversize` in `error_codes.py` and in the LLM-mode error contract for machine consumers.
- New warning code `oversize_guard_disabled` when `--oversize-factor 0` is used explicitly.
- `oversize_factor` added to the `limits` block in the LLM-mode success payload and dry-run payload.
- 10 new tests: unit tests for `_check_oversize_ratio` (passes within factor, raises at threshold, message content, disabled at 0, disabled when unlimited); two pipeline-integration tests (guard fires and stops normalization, guard bypass allows run); two CLI contract tests (warning appears, field present in limits).
- **LLM_MODE.md** warning model expanded into a full table: each warning code mapped to a concrete suggested next action for orchestrators.
- **LLM_MODE.md** error-code table expanded to cover all canonical codes: `capture_oversize`, `invalid_tshark_json`, `tshark_failed`, `invalid_vault_key`, `artifact_write_failed`.
- **`docs/architecture/scaling_plan.md`** rewritten: current behavior documented as a table, all three scaling options compared, two-pass design specified concretely as the recommended next step with prerequisites, current implementation status table.

### Changed — 2026-04-10

- `REFERENCE.md` and `CLAUDE.md` updated with `--oversize-factor` option.

### Added — 2026-04-09

- `verbatim_protocols` support in analysis profiles: protocols listed there bypass `full_detail_fields` field selection and `_flatten`; the complete raw TShark layer dict is kept as-is (only `_ws.*` keys stripped). Takes priority over `full_detail_fields` for the same protocol. Documented in `docs/PROFILES.md` and `docs/REFERENCE.md`.
- Output filenames now always include a timestamp prefix from the first packet in the capture (`YYYYMMDD_HHMMSS_<stem>_V_NN.ext`). The `_V_NN` suffix is always present and auto-increments on collision.
- Full English reference documentation at `docs/REFERENCE.md`.
- `docs/WORKFLOWS.md` consolidating LTE, 5G Core, and SS7/GERAN step-by-step workflows, protocol-specific troubleshooting tables, and a "When to stop and re-filter" guide with decision helpers.
- Expanded `docs/PRIVACY_SHARING.md`: scenario-to-profile recommendation table, what-to-share guidance per artifact, 5-step safe-sharing workflow, encryption vs. pseudonymization guidance, and three concrete examples.
- `docs/LLM_MODE.md` now includes a "Typical automation flow" section with step-by-step pattern, annotated result payload, per-error-code response table, and inspect-vs-analyze decision guide.
- `docs/REFERENCE.md` and `docs/LLM_MODE.md` explicitly document what `--max-packets` does **not** do (no streaming, no proportional memory, no substitute for focused captures).
- Additional `--llm-mode` CLI contract tests: always-present `full_load_ingestion_applies` warning, `no_relevant_protocols_detected` trigger, payload field completeness (`profile`, `privacy_profile`, `capture.sha256`, `schema_versions`), generic `runtime_error` fallback, dry-run machine mode fields.

### Fixed — 2026-04-09

- Artifact filename timestamp prefix was silently dropped (`artifact_prefix: null`) when running against TShark ≥ 4.6. TShark 4.6 changed `frame.time_epoch` from a Unix epoch float string (`"1712390000.123"`) to ISO 8601 with nanoseconds (`"2025-10-14T10:44:16.046652117Z"`). `_artifact_timestamp_prefix` now tries float parsing first, then falls back to ISO 8601 with nanosecond truncation. Both formats are covered by regression tests.

### Changed — 2026-04-09

- README `Full CLI Reference` section (65 lines) replaced with a 3-line pointer to `docs/REFERENCE.md` to avoid duplication.

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
