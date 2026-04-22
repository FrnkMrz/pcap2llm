# Changelog

All notable changes to `pcap2llm` are documented in this file.

The format is intentionally simple and optimized for humans reading repo history during an early project phase.

## Unreleased

### Added — 2026-04-22 (signaling flow visualization)

- **Optional signaling-flow artifacts for `analyze`**:
  - `pcap2llm analyze ... --render-flow-svg` now writes `flow.json` and
    `flow.svg` sidecars next to `detail.json`, `summary.json`, and `summary.md`.
  - `flow.json` carries endpoint lanes, rendered events, phase blocks,
    request/response correlation, rendered/truncated event counts, warnings, and
    repeat-collapse metadata (`repeat_count`, first/last packet number, and
    relative timing).
  - `flow.svg` renders a telecom sequence diagram with role-aware lane ordering,
    above-arrow labels, browser hover tooltips, accessible SVG title/description,
    request/response coloring, and red error highlighting.

- **Standalone flow re-rendering**:
  - added `pcap2llm visualize <flow.json>` to regenerate an SVG from an existing
    flow model without rerunning TShark or the analysis pipeline.
  - supports custom output path and SVG width.

- **Richer protocol-aware flow labels**:
  - Diameter answers include `Result-Code` in labels and result codes >= 3000
    mark the event as an error.
  - GTPv2 labels use message names, avoid request/response double suffixes, add
    response cause values, and mark cause >= 64 as an error.
  - NGAP procedures and NAS-EPS/NAS-5GS message types are named when their codes
    are present, including fields nested inside verbatim TShark trees.
  - HTTP/2 labels prefer request method/path or response status.
  - DNS events show query type/name, response rcode, answer count, and use
    `dns.id` as a correlation key; non-zero rcode marks the event as an error.
  - fallback labeling now recovers app-layer names from `frame_protocols` for
    SIP, NGAP, NAS-5GS, S1AP, PFCP, GTPv1/GTPv2, Diameter, RADIUS, SCCP, MAP,
    and ISUP when profile extraction did not surface richer fields.

- **Documentation refreshed for visualization**:
  - README, English reference, German quickstart/practical guide, workflow docs,
    LLM workflow/mode docs, project status, pipeline internals, documentation
    map, and contributor notes now describe the new flow sidecars and
    `visualize` command.

### Added — 2026-04-12 (repo-owned local batch runner)

- **Repo-owned local batch execution tooling**:
  - added `scripts/run_local_batches.py` plus a committed TOML batch catalog at `batches/local_examples.toml`
  - the runner executes local `discover`, `inspect`, and `analyze` cases while keeping captures and generated outputs outside Git tracking
  - supports case selection, dry-run mode, output-root override, and concise per-case/end-of-run summaries

- **Local workflow docs and git hygiene were updated**:
  - README, workflow docs, and `.local/README.md` now describe the repo-owned runner and the intended local-only storage pattern
  - `.gitignore` now also reserves `batches/*.local.toml` and `batches/*.private.toml` for untracked local overrides

### Changed — 2026-04-12 (inspect cleanup and S6a consistency)

- **Inspect JSON metadata is cleaner and more canonical**:
  - `run`, `capture`, and `artifact` are now the authoritative top-level metadata blocks for inspect outputs.
  - redundant capture-path / first-packet / timestamp fields were removed from `metadata`; inspect-specific context stays under `metadata`.

- **Inspect candidate semantics are clearer for clean S6a traces**:
  - downranked IMS Diameter fallbacks in strong LTE S6a cases now surface as low-confidence fallback matches instead of looking like strong IMS matches.
  - clearly identified S6a inspect results now keep next-step hints focused on `lte-s6a` instead of presenting unrelated LTE interfaces as equally likely.

### Changed — 2026-04-12 (semantic artifact filenames)

- **Artifact output filenames now use semantic ordering instead of timestamp-first naming**:
  - filenames now lead with action, capture filename, start packet, and artifact version
  - examples: `discover_trace_start_1_V_01.json`, `analyze_trace_start_120_V_01_summary.json`
  - this improves readability and makes repeated runs easier to compare at a glance

### Changed — 2026-04-12 (ordered output metadata across inspect / discover / analyze)

- **Artifact outputs now carry explicit ordered run metadata across all three commands**:
  - `inspect`, `discover`, and `analyze` now expose `run.action`, `capture.filename`, `capture.first_packet_number`, and `artifact.version` directly in their public outputs.
  - Human-readable Markdown reports now present those fields in the same fixed order: action, capture file, start packet, artifact version.
  - `analyze` artifacts now also expose `selection.start_packet_number` / `selection.end_packet_number` when the detail window is a bounded subset.
  - `capture.path` remains available alongside `capture.filename`, so short human scanning and full-path traceability both stay intact.

- **Docs and tests were updated accordingly**:
  - README, discovery/reference/schema/workflow docs now describe the explicit metadata block and its ordering.
  - Regression coverage now checks JSON presence, Markdown header order, explicit version emission, and selection-range packet numbering.

### Changed — 2026-04-12 (final comprehensive Discovery correction pass)

- **Narrower GTPv2/EPS candidate fan-out**: `2g3g-gp` is now gated the same way as
  `2g3g-gn` — zeroed when no GTPv1 evidence exists, or when `gtpv2` is the active
  control plane. `5g-n26` is suppressed to × 0.1 in clear EPS traces without any
  5GC indicators (`ngap`, `nas-5gs`, `http+json`) or N26 peer hints.

- **Tighter IMS/voice Discovery separation**:
  - All `vonr-*` profiles now require 5G SA context (`ngap`/`nas-5gs`) beyond generic
    IMS/SIP presence — without it they receive an additional × 0.3 gate
  - `volte-ims-core` and `vonr-ims-core` now require `diameter` or IMS peer hints;
    SIP alone is no longer sufficient to keep them prominently ranked
  - `-sip-register` profiles are more aggressively downranked (× 0.25) without
    registrar/auth-style context

- **Legacy SS7 side profiles fully suppressed without evidence**: `2g3g-bssap`,
  `2g3g-geran`, `2g3g-gs`, and `2g3g-ss7-geran` are now fully zeroed (score = 0)
  when no BSSAP/DTAP/GSM-A evidence exists, instead of applying a multiplier that
  the domain bonus could overcome. `2g3g-isup` is likewise zeroed without `isup`
  evidence. `2g3g-map-core` and `2g3g-sccp-mtp` remain the clear primary SS7
  candidates for MAP+TCAP+SCCP traces.

- **Stronger telecom naming extraction**: Added `topon.` (3GPP TS 29.303 node
  resolution prefix) as a strong naming hit. Added EPC/LTE node names (`pgw.`,
  `sgw.`, `mme.`, `hss.`) and base-station names (`enb.`, `gnb.`) as supporting
  evidence hits.

- **Further DNS-only clutter reduction**: DNS family profile suppression factor
  lowered from 0.45 to 0.3; family-core profile suppression lowered from 0.55 to
  0.35 when `core-name-resolution` clearly dominates.

- **Calmer 5G SA side noise**: Voice profiles (`vonr-*`, `volte-*`) are now
  suppressed to × 0.2 in strong 5G SA traces (top domain score ≥ 0.75) when no
  voice evidence (SIP/SDP/RTP/RTCP) is present.

- **19 new regression tests** covering all correction areas; `docs/DISCOVERY.md`
  updated for GTPv2/EPS fan-out, VoNR gate semantics, TOPON naming, and legacy SS7
  side-profile behavior.

### Changed — 2026-04-12 (final scoring correction pass)

- **Corrected GTPv1 domain inference**: TShark reports GTPv1 packets as `gtp`
  (not `gtpv1`). Discovery now correctly detects `gtp + udp` without `gtpv2` as
  a GTPv1-only packet-core trace and promotes `legacy-2g3g-gprs` as the primary
  domain. When `gtpv2` is also present, `gtp` is treated as LTE GTP-U
  (user-plane) and legacy `2g3g-gn` profiles are suppressed.

- **Removed misleading legacy residue in EPS / GTPv2 traces**: `2g3g-gn` is now
  zeroed out whenever `gtpv2` is present, even if `gtp` (user-plane) also appears.
  Similarly, `lte-s5` / `lte-s8` are heavily downranked when GTP is present
  without a GTPv2 control plane — that combination points to legacy Gn/Gp, not
  LTE S5/S8.

- **Cleaner 5G SA side-signal handling**: LTE profiles in a strongly 5G SA
  dominated trace are now suppressed more aggressively. Profiles without any
  LTE anchor signal (`s1ap`, `diameter`, `gtpv2`) are multiplied down to 0.15
  rather than appearing as near-peers of the 5G candidates.

- **VoNR / hybrid voice gate tightened**: DNS is no longer treated as a voice
  indicator. `vonr-n1-n2-voice` and `vonr-ims-core` are now only promoted when
  real IMS/SIP-family signals (`sip`, `sdp`, `rtp`, `rtcp`) are present. This
  prevents 5G SA + DNS traces from spuriously raising voice profiles.

- **Stronger telecom naming support in DNS discovery**: Supporting evidence
  patterns (IMS CSCF names, 5G NF hostnames, generic `3gpp` context) now
  emit explicit summary and per-pattern reasons instead of silently contributing
  to the score. The fan-out suppression threshold for family-specific DNS profiles
  was lowered from 5.0 to 4.0 so that single-strong-hit telecom naming traces
  also benefit. Family-level core profiles (`lte-core`, `5g-core`) are now also
  downranked alongside the `*-dns` profiles when `core-name-resolution` dominates.

- **Improved protocol count presentation**: `dominant_signaling_protocols` now
  consistently uses `strength: "supporting"` (not `"strong"`) for protocols
  recovered only from raw header presence without a decoded packet count. The
  Markdown report renders these entries as `[raw signal]` to make the distinction
  visually explicit.

- **Tests and docs updated**: New and updated regression tests for all six
  correction areas; `docs/DISCOVERY.md` updated for GTPv1 interpretation, fan-out
  suppression threshold, VoNR gate semantics, and protocol strength labels.

### Changed — 2026-04-11 (discovery hardening and ranking cleanup)

- **Discovery output is now cleaner and more explicit**:
  - `dominant_signaling_protocols` no longer emits misleading `count: 0` entries. If a protocol is only inferred from strong raw presence and no trustworthy decoded count exists, the `count` field is omitted.
  - `top_protocols` remains the raw count-oriented packet view, while discovery now exposes a more useful `relevant_protocols` view for orchestration and first-pass human triage.
  - Discovery markdown now calls out the raw nature of `top_protocols` more clearly so humans do not confuse packet-count dominance with domain-signaling dominance.

- **Discovery recommendation heuristics were tightened across 5G, LTE, DNS, Diameter, and mixed cases**:
  - Generic Diameter-over-SCTP traces now keep `lte-s6a` / `lte-core` clearly ahead of IMS / VoLTE Diameter profiles unless IMS-specific peer or signaling hints are present.
  - DNS-only traces no longer pull SIP / SBC / REGISTER-style voice profiles to the top; DNS-focused profiles remain visible while SIP-specific voice profiles require stronger IMS evidence.
  - Generic HTTP/JSON SBI traces now favor broader `5g-sbi` / `5g-core` candidates before many narrowly named SBI interfaces when no NF-specific hints are available.
  - `5g-n26` is now more conservative and requires interworking-style evidence instead of rising early on plain GTPv2 presence.

- **Host resolution is now used more effectively as a supporting discovery signal**:
  - Resolved peer names and roles can now gently strengthen interface ranking for cases such as LTE S5/S8, S11, S6a, and mixed EPC↔5GC interworking.
  - Host-resolution hints remain additive only; they do not replace decoded protocol evidence and continue to be surfaced transparently in discovery output.

- **Discovery now reuses the lightweight inspect-enrichment layer**:
  - Discovery inherits the cheap anomaly and trace-shape hints already used by `inspect`, improving first-pass triage without turning discovery into a full analysis mode.

- **Analyze summaries remain schema-stable**:
  - Discovery-specific metadata such as host-resolution usage and resolved peers is kept out of general `analyze` summary artifacts, preventing unintended schema drift in golden-corpus and downstream summary consumers.

- **Tests and docs were expanded accordingly**:
  - Added / updated regression coverage for DNS-only, generic Diameter, host-informed GTPv2 ranking, generic SBI bundling, null-count suppression, and host-resolution transparency.
  - `docs/DISCOVERY.md` now documents the stricter DNS / Diameter behavior, host-resolution as a supporting signal, and the absence of null-count artifacts in dominant-signaling output.

### Added — 2026-04-10 (orchestration + local hosts)

- **Orchestration layer** — three new CLI commands for staged, agent-driven workflows:
  - `pcap2llm discover` — broad scout pass that builds a combined profile from all installed profiles, runs an inspect pass, and writes `discovery.json` + `discovery.md` with protocol summary, domain detection, and ranked profile recommendations.
  - `pcap2llm recommend-profiles` — standalone recommender; accepts a discovery JSON or a raw capture; returns ranked profile suggestions with confidence score and rationale.
  - `pcap2llm session` — multi-run session manager for external orchestrators: `start`, `run-discovery`, `run-profile`, `finalize` subcommands; writes a `session_manifest.json` and a final Markdown report.
  - New `SelectorMetadata` model (family / domain / interface / trigger / confidence metadata) for profile recommendation.
  - New helpers `list_profile_names()` and `load_all_profiles()` in `profiles/__init__.py`.
  - New docs: `docs/DISCOVERY.md`, `docs/PROFILE_SELECTION.md`, `docs/SESSIONS.md`.
  - New tests: `tests/test_orchestration.py`.

- **Local-only hosts file** — automatic discovery of `.local/hosts` without requiring a CLI argument:
  - The tool checks `.local/hosts` on every `analyze` run. If the file exists it is loaded automatically (logged at INFO). If absent the run continues without mapping (logged at DEBUG).
  - Lookup order: `--hosts-file` CLI arg → `hosts_file` in config → `.local/hosts` → none.
  - `.local/` is a reserved local-only directory, never committed. `.gitignore` ignores all real contents; only `.local/.gitkeep` and `.local/README.md` are tracked.
  - `scripts/git-hooks/pre-commit` blocks accidental staging of `.local/` files. Install with `bash scripts/install-git-hooks.sh`.
  - CI `local-files-guard` job fails if disallowed files under `.local/` are tracked, even after a `git add -f`.
  - `docs/REFERENCE.md`: new "Local-only sensitive files" section; Endpoint Mapping updated with default path.
  - `docs/ANLEITUNG_DE.md` and `docs/WORKFLOWS.md` updated accordingly.
  - `tests/test_local_hosts.py`: 7 tests covering all lookup-precedence cases.

### Added — 2026-04-10

- Focused LTE / EPC interface profile family: `lte-s1`, `lte-s1-nas`, `lte-s6a`, `lte-s11`, `lte-s10`, `lte-sgs`, `lte-s5`, `lte-s8`, `lte-dns`, `lte-sbc-cbc`.
- Focused 2G/3G core and GERAN profile family: `2g3g-gn`, `2g3g-gp`, `2g3g-gr`, `2g3g-gs`, `2g3g-geran`, `2g3g-dns`, `2g3g-map-core`, `2g3g-cap`, `2g3g-bssap`, `2g3g-isup`, `2g3g-sccp-mtp`.
- Focused 5G SA core profile family: `5g-n1-n2`, `5g-n2`, `5g-nas-5gs`, `5g-sbi`, `5g-sbi-auth`, `5g-n8`, `5g-n10`, `5g-n11`, `5g-n12`, `5g-n13`, `5g-n14`, `5g-n15`, `5g-n16`, `5g-n22`, `5g-n26`, `5g-n40`, `5g-dns`, `5g-cbc-cbs`.
- Focused Voice-over-IMS family for VoLTE and VoNR: `volte-sip`, `volte-sip-register`, `volte-sip-call`, `volte-diameter-cx`, `volte-diameter-rx`, `volte-diameter-sh`, `volte-dns`, `volte-rtp-signaling`, `volte-sbc`, `volte-ims-core`, `vonr-sip`, `vonr-sip-register`, `vonr-sip-call`, `vonr-ims-core`, `vonr-policy`, `vonr-dns`, `vonr-n1-n2-voice`, `vonr-sbi-auth`, `vonr-sbi-pdu`, `vonr-sbc`.
- Profile-family regression tests for 5G SA and Voice-over-IMS selections and differentiation (`tests/test_profiles_5g_core_interfaces.py`, `tests/test_profiles_volte_vonr.py`) plus expanded profile/dx coverage.
- Runtime CLI override for `verbatim_protocols`: `--verbatim-protocol` and `--no-verbatim-protocol`, with dry-run and `--llm-mode` reporting of the effective verbatim set and per-run profile overrides.
- **Oversize-ratio guard** (`--oversize-factor`, default 10×): after TShark export, if `total_exported > max_packets × factor` the pipeline fails fast with a clear error and a `-Y` hint. Fires after the inspection stage so `summary.json` statistics remain accurate; fires before the expensive normalization and protection stages. Set `--oversize-factor 0` to disable.
- New error code `capture_oversize` in `error_codes.py` and in the LLM-mode error contract for machine consumers.
- New warning code `oversize_guard_disabled` when `--oversize-factor 0` is used explicitly.
- `oversize_factor` added to the `limits` block in the LLM-mode success payload and dry-run payload.
- 10 new tests: unit tests for `_check_oversize_ratio` (passes within factor, raises at threshold, message content, disabled at 0, disabled when unlimited); two pipeline-integration tests (guard fires and stops normalization, guard bypass allows run); two CLI contract tests (warning appears, field present in limits).
- **LLM_MODE.md** warning model expanded into a full table: each warning code mapped to a concrete suggested next action for orchestrators.
- **LLM_MODE.md** error-code table expanded to cover all canonical codes: `capture_oversize`, `invalid_tshark_json`, `tshark_failed`, `invalid_vault_key`, `artifact_write_failed`.
- **`docs/architecture/scaling_plan.md`** rewritten: current behavior documented as a table, all three scaling options compared, two-pass design specified concretely as the recommended next step with prerequisites, current implementation status table.

### Changed — 2026-04-10

- Profile loading now accepts names with or without `.yaml` suffix (for example `--profile lte-s6a` and `--profile lte-s6a.yaml` now resolve identically).
- Diameter verbatim extraction is substantially deeper and cleaner: repeated `diameter.avp_tree` structures are preserved, nested AVPs are surfaced into flat `diameter.*` fields, and raw AVP / `*_tree` decoder dumps are removed by default unless explicitly kept.
- TShark field-rejection warnings for version-specific index fields are now explained more clearly as compatibility fallback rather than a likely capture problem.
- Redundant top-level `profiles/` directory removed so `src/pcap2llm/profiles/` is the single authoritative built-in profile path.
- Profile documentation refactored from one growing catalog into a navigable structure: `docs/PROFILES.md` now acts as an overview and custom-authoring entry point, with family-specific references in `docs/PROFILES_LTE.md`, `docs/PROFILES_5G.md`, `docs/PROFILES_VOICE.md`, and `docs/PROFILES_2G3G.md`.
- README and DE/EN guidance docs were slimmed down so they act as entry points and navigation aids rather than duplicating large profile catalogs.
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
