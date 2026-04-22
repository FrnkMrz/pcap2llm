# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pcap2llm is a **deterministic trace formatter and artifact generator**. It converts `.pcap`/`.pcapng` network captures into compact, privacy-controlled, LLM-ready JSON artifacts for telecom troubleshooting. It uses TShark for packet dissection and applies profile-driven normalization, reduction, and privacy protection. The tool itself performs no generative AI analysis — it prepares the handoff artifact for a downstream LLM step.

**Sweet spot:** focused captures of specific call flows, error scenarios, or a few hundred signaling packets. Not designed for multi-megabyte rolling dumps.

## Commands

```bash
# Install (editable, with dev tools)
pip install -e .[dev]
# With encryption support
pip install -e .[dev,encrypt]

# Run all tests
pytest

# Run a single test file
pytest tests/test_pipeline.py -v

# Lint
ruff check .

# CLI usage — core commands
pcap2llm inspect sample.pcapng --profile lte-core
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 500 --out ./artifacts
pcap2llm analyze sample.pcapng --profile lte-core --all-packets --out ./artifacts
pcap2llm analyze sample.pcapng --profile lte-core --privacy-profile share --out ./artifacts
pcap2llm analyze sample.pcapng --profile lte-core --llm-mode --out ./artifacts
pcap2llm init-config

# Discovery → profile recommendation → analyze flow
pcap2llm discover sample.pcapng --out ./artifacts
pcap2llm recommend-profiles ./artifacts/<discovery>.json   # also accepts a raw capture

# Flow (sequence-diagram) rendering
pcap2llm analyze sample.pcapng --profile lte-s6a --render-flow-svg --out ./artifacts
pcap2llm visualize ./artifacts/<flow>.json                 # re-render SVG without re-running pipeline

# External-LLM handoff (uses llm-telecom-safe by default — see Documented Agent Workflow)
pcap2llm ask-chatgpt sample.pcapng --question "..."
pcap2llm ask-claude  sample.pcapng --question "..."
pcap2llm ask-gemini  sample.pcapng --question "..."

# Multi-run session orchestration
pcap2llm session start sample.pcapng --out ./artifacts
pcap2llm session run-discovery --session ./artifacts/<session-dir>
pcap2llm session run-profile   --session ./artifacts/<session-dir> --profile lte-s6a
pcap2llm session finalize      --session ./artifacts/<session-dir>

# Local batch runner (reads batches/*.toml; captures not committed)
python3 scripts/run_local_batches.py batches/local_examples.toml
```

## Source Modules

| Module | Purpose |
|---|---|
| `pipeline.py` | Main orchestrator — two-pass pipeline, file naming, capture size guard |
| `cli.py` | Typer CLI — 9 top-level commands + `session` subcommands, privacy resolution, progress display, LLM mode |
| `models.py` | Pydantic v2 data models and schema constants |
| `index_models.py` | `PacketIndexRecord`, `SelectedFrames`, `parse_index_row()` — pass-1 data model |
| `index_inspector.py` | Pass-1 inspection: `inspect_index_records()`, `select_frame_numbers()` |
| `normalizer.py` | TShark JSON → `NormalizedPacket`; verbatim protocol passthrough |
| `inspector.py` | Thin wrapper for inspection with `on_stage` callback support |
| `inspect_enrichment.py` | Domain detection, trace shape, classification state, anomaly enrichment over pass-1 results |
| `reducer.py` | Strips transport fields to profile-specified set |
| `protector.py` | Privacy enforcement — BLAKE2s pseudonyms, Fernet encryption, masking |
| `resolver.py` | IP/hostname → enriched endpoint (hosts file, YAML mapping, CIDR, port inference) |
| `summarizer.py` | Timing stats, burst detection, anomaly classification, protocol counts |
| `serializers.py` | Wraps internal dicts into versioned `SummaryArtifactV1` / `DetailArtifactV1` |
| `app_anomaly.py` | Stateful app-layer anomaly detection (Diameter, GTPv2-C) |
| `privacy_policy.py` | Rule-based field classification into 13 data classes (regex + keywords) |
| `config.py` | Config file loading, privacy mode alias normalization, sample config text |
| `profiles/__init__.py` | Loads analysis profiles by name; emits `DeprecationWarning` for old `default_privacy_modes` |
| `privacy_profiles/__init__.py` | Loads built-in or file-path privacy profiles |
| `cli_result.py` | LLM-mode JSON result payload builders |
| `error_codes.py` | Maps exception messages to machine-readable error codes |
| `tshark_runner.py` | Runs `tshark -n -r <pcap> -T json`, parses and validates output |
| `output_metadata.py` | `semantic_artifact_filename()` — timestamp prefix + `_V_NN[_kind]` naming for every output file |
| `discovery.py` | `discover` command: protocol-family / trace-shape summary used as input to profile selection |
| `recommendation.py` | `recommend-profiles` scoring engine — domain inference, evidence classes, host/peer hints |
| `signaling.py` | Protocol canonicalization + dominant-signaling detection shared by discovery & recommendation |
| `sessions.py` | Session manifest I/O (`start`, `append_run`, `build_session_report`) for multi-run orchestration |
| `visualize.py` | Flow model + SVG renderer — lanes (NEs), events (messages), phases; `build_flow_model()` / `render_flow_svg()` |
| `chatgpt.py` / `claude.py` / `gemini.py` | `ask-*` commands — bundle artifacts + question for external-LLM handoff |
| `local_batch_runner.py` | TOML-driven batch runner for curated local captures (see `batches/*.toml`) |

## Architecture

**Processing pipeline** (`pipeline.py` orchestrates two TShark passes + 5 processing stages):

1. **Size guard** — rejects captures exceeding `max_capture_size_mb` (default 250 MiB) before TShark runs
2. **Pass 1 — lightweight export** (`tshark_runner.export_packet_index()`) — runs `tshark -T fields` with 29 fields and `|` separator; produces `PacketIndexRecord` objects for every packet; no full JSON materialization
3. **Inspection** (`index_inspector.inspect_index_records()`) — extracts metadata, protocol counts, conversations, anomalies from pass-1 records; covers the full capture so `summary.json` stays accurate
4. **Oversize guard + frame selection** — rejects if oversize ratio exceeded; `select_frame_numbers()` derives the bounded frame list from pass-1 records; raises if `fail_on_truncation=True`
5. **Pass 2 — selective export** (`tshark_runner.export_selected_packets()` or `export_packets()`) — runs `tshark -T json -Y "frame.number in {N,...}"` for selected frames only (chunked at 500); memory proportional to `max_packets`
6. **Normalization + Reduction + Protection** (`normalizer.py`, `reducer.py`, `protector.py`) — transforms raw TShark JSON into `NormalizedPacket` objects; strips to profile-specified fields; applies per-class privacy modes
7. **Serialization** (`serializers.py` + `summarizer.py`) — produces versioned `SummaryArtifactV1` and `DetailArtifactV1` with coverage metadata, then writes timestamped, versioned files

**App-layer anomaly detection** (`app_anomaly.py`) — stateful, runs during inspection; detects Diameter (unanswered requests, duplicate hop-by-hop IDs, error result codes ≥ 3000) and GTPv2-C (unanswered Create Session, non-success cause, Error Indications).

**Analysis profiles** (`src/pcap2llm/profiles/*.yaml`) — the authoritative built-in profile path. Profiles define protocol priorities, field extraction rules, `verbatim_protocols`, and TShark options. Built-in families include `lte-core`, the LTE interface profiles (`lte-s1`, `lte-s1-nas`, `lte-s6a`, `lte-s11`, `lte-s10`, `lte-sgs`, `lte-s5`, `lte-s8`, `lte-dns`, `lte-sbc-cbc`), plus `5g-core` and `2g3g-ss7-geran`. Custom profiles: see `docs/PROFILES.md`.

**Privacy profiles** (`src/pcap2llm/privacy_profiles/*.yaml`) — standalone YAML files with per-class privacy modes, fully decoupled from analysis profiles. Built-in: `internal` (all keep), `share` (pseudonymize subscriber IDs), `lab`, `prod-safe` (maximum protection), and `llm-telecom-safe` (external LLM troubleshooting with pseudonymized endpoint relationships). Referenced via `--privacy-profile` or `privacy_profile:` in config.

## Documented Agent Workflow

When the user asks to hand a PCAP-derived result to an external LLM for troubleshooting or explanation, use the documented `LLM-PCAP workflow` from `docs/LLM_TROUBLESHOOTING_WORKFLOW.md`.

Default behavior for that workflow:

1. run `discover`
2. choose a focused profile from discovery evidence
3. run `analyze --privacy-profile llm-telecom-safe`
4. never send the raw PCAP to the LLM
5. never share `pseudonym_mapping.json`, `vault.json`, or vault key material
6. send only the minimum necessary artifact excerpt to the LLM
7. validate the LLM answer against the local artifacts before presenting conclusions

**Data models** (`models.py`) use Pydantic v2. `SCHEMA_VERSION = "1.0"`. Key types:
- `NormalizedPacket`, `InspectResult`, `CaptureMetadata` — internal pipeline types
- `ProfileDefinition` — analysis profile schema (`max_conversations` default 25, `verbatim_protocols` list)
- `PrivacyProfileDefinition` — privacy profile schema (`name`, `description`, `modes`)
- `SummaryArtifactV1`, `DetailArtifactV1` — public output schema (extra="forbid")
- `ArtifactCoverage` — tracks `detail_packets_included`, `detail_packets_available`, `detail_truncated`, `truncation_note`
- `AnalyzeArtifacts` — internal pipeline return value before file writing

**CLI** (`cli.py`) — Typer. 9 top-level commands (`init-config`, `inspect`, `discover`, `recommend-profiles`, `analyze`, `ask-chatgpt`, `ask-claude`, `ask-gemini`, `visualize`) plus the `session` subapp (`start`, `run-discovery`, `run-profile`, `finalize`). Exit code 1 on all errors; errors to stderr. Progress via `rich` on TTYs (spinner + step counter), plain `[N/M] description` on non-TTY. `--llm-mode` (on `analyze`) switches stdout to strict JSON with status, coverage, warnings, and error codes for agent/automation use.

**Endpoint resolution** (`resolver.py`) — lookup order: exact IP → case-insensitive hostname → CIDR subnet → port-based role inference.

**Flow visualization** (`visualize.py`, opt-in via `analyze --render-flow-svg`) — produces `flow.json` + `flow.svg` sidecars. `build_flow_model()` derives lanes (network elements), events (signaling messages), phases (call-flow stages), request/response pairing, collapse metadata, and warnings; `render_flow_svg()` emits an SVG sequence diagram with arrow tooltips and accessibility title/desc. Lane ordering is profile-family aware (5G gNB/AMF/SMF/UPF, LTE eNB/MME/SGW/PGW/HSS, IMS P/I/S-CSCF, …). Endpoint key priority is `alias → ip → hostname → role` — do **not** reorder: `role`-first collides distinct NEs sharing the same protocol role onto one lane. Arrow labels always sit at `y - 8` (uniform above-arrow) to guarantee a full `row_height` gap between consecutive labels. Event labels include Diameter Result-Code, GTPv2 message names and response Cause values, NGAP procedure names, NAS-EPS/NAS-5GS message names, HTTP/2 method/path or status, and DNS query type/name/rcode/answer count when fields are present; Diameter result >= 3000, HTTP >= 400, GTPv2 cause >= 64, and DNS rcode > 0 set error status. A `frame_protocols` fallback map recovers a real protocol name (`SIP`, `NGAP`, `NAS-5GS`, `S1AP`, `PFCP`, `GTPv1/2`, `Diameter`, `RADIUS`, `SCCP`, `MAP`, `ISUP`) when the analysis profile did not extract app-layer fields. The standalone `visualize <flow.json>` command re-renders an SVG without re-running the pipeline.

**Discovery & recommendation** (`discovery.py`, `recommendation.py`, `signaling.py`) — `discover` inspects a capture and writes a discovery JSON/Markdown artifact (protocol families, trace shape, resolved peers, anomalies). `recommend-profiles` scores profiles from either the discovery JSON or a raw capture, using protocol evidence classes, domain inference, peer-role hints, and DNS naming evidence. These power the "Documented Agent Workflow" below.

**Session orchestration** (`sessions.py`) — `session start` creates a session directory with a manifest, captures a SHA-256 of the pcap, and writes a session ID. Subsequent `session run-discovery` / `session run-profile` calls append run records via `append_run()`; `session finalize` marks status and writes a report. Manifest path: `session_manifest_path(session_dir)`.

**External-LLM handoff** (`chatgpt.py`, `claude.py`, `gemini.py`) — the `ask-*` commands generate artifacts, build a prompt via `build_*_prompt()` (using `DEFAULT_CHATGPT_QUESTION` / `DEFAULT_SYSTEM_PROMPT` unless overridden), and write handoff files. The default system prompt constrains the LLM to the supplied artifacts and forbids inventing packets or states.

**Output filenames** (`output_metadata.py`) — every artifact goes through `semantic_artifact_filename()`, which produces `{action}_{capture_stem}_{YYYYMMDD_HHMMSS}_V_NN[_kind].{ext}`. Timestamp comes from the first packet epoch; `_V_01` is always present and auto-increments on collision. `artifact_kind` differentiates sidecars (`flow`, `summary`, `detail`, `mapping`, `vault`, …) within one run.

## Key Design Decisions

- **Profile YAML drives protocol selection** — extending protocols means editing profiles, not Python code
- **Analysis profiles and privacy profiles are fully separated** — `--profile 5g-core` + `--privacy-profile prod-safe` are orthogonal; any combination is valid
- **`verbatim_protocols` in analysis profile** — protocols listed there bypass the normal `full_detail_fields` path and keep minimally transformed protocol detail. Top-level protocol fields remain, repeated nested fields can be surfaced into flat protocol-prefixed keys, and `_ws.*` is stripped. For Diameter, raw AVP dump structures can additionally be suppressed with `keep_raw_avps: false`.
- **Privacy operates on 13 data classes**: ip, hostname, subscriber_id, msisdn, imsi, imei, email, distinguished_name, token, uri, apn_dnn, diameter_identity, payload_text — with per-class mode selection (keep/mask/pseudonymize/encrypt/remove)
- **Privacy resolution order** (highest wins): CLI `--*-mode` flags → config `privacy_modes` overrides → `--privacy-profile` base → deprecated `default_privacy_modes` in analysis profile → `{}`
- **Pseudonyms are hash-based** (BLAKE2s) — stable across runs, format: `IMSI_a3f2b1c4`
- **Encryption** uses `cryptography.fernet` with key from `PCAP2LLM_VAULT_KEY` env var; validated early via `Protector.validate_vault_key()` before packet processing begins
- **`normalize_packets()` returns `(packets, dropped_count)`** — malformed packets are logged and skipped; `dropped_packets` appears in summary if > 0
- **Output artifacts always contain** `schema_version`, `generated_at` (ISO 8601 UTC), `capture_sha256`, and `coverage` block
- **Coverage block** (`ArtifactCoverage`) — present in both `SummaryArtifactV1` and `DetailArtifactV1`; records `detail_packets_included`, `detail_packets_available`, `detail_truncated` (bool), `truncation_note`
- **`analyze_capture()` accepts**:
  - `max_packets` (default 1000, 0 = unlimited) — only normalization onwards is sliced; inspection runs on full export
  - `fail_on_truncation` (default False) — raises `RuntimeError` if truncation would occur
  - `max_capture_size_mb` (default 250) — rejects oversized files before TShark runs; set 0 to disable
- **Output filenames** — always `YYYYMMDD_HHMMSS_<stem>_V_NN.ext`; timestamp from first packet epoch; `_V_01` always present, auto-incremented on collision
- **Progress reporting** uses optional `on_stage(description, step, total)` callback; CLI wires this to `rich.progress` on TTYs
- **`default_privacy_modes` in analysis profile YAML is deprecated** — emits `DeprecationWarning`; migrate to `--privacy-profile share` (or equivalent) in config
- **All processing is local** — no remote transmission

## CLI Options Reference

### `inspect`
```
--profile           analysis profile name (default: lte-core)
--display-filter/-Y tshark display filter
--config            optional YAML config file
--out               write JSON output to file instead of stdout
--dry-run           print planned tshark command only
--two-pass          override two-pass dissection mode
--tshark-path       tshark executable path
--tshark-arg        extra tshark argument (repeatable)
```

### `analyze`
```
--profile               analysis profile name (default: lte-core)
--privacy-profile       privacy profile (built-in: internal, share, lab, prod-safe, llm-telecom-safe)
--display-filter/-Y     tshark display filter
--config                optional YAML config file
--out                   artifact output directory (default: artifacts)
--max-packets           max packets in detail.json (default: 1000)
--all-packets           include all packets, overrides --max-packets
--fail-on-truncation    raise error if detail would be truncated
--max-capture-size-mb   reject capture files larger than N MiB (default: 250, 0=off)
--oversize-factor       reject if exported packets exceed max-packets by this factor (default: 10, 0=off)
--dry-run               print plan only, no tshark execution
--llm-mode              stdout is strict JSON for agent/automation use
--hosts-file            Wireshark-style hosts file
--mapping-file          YAML/JSON alias mapping (supports CIDR)
--two-pass              override two-pass dissection mode
--tshark-path           tshark executable path
--tshark-arg            extra tshark argument (repeatable)
--ip-mode / --hostname-mode / --subscriber-id-mode / --msisdn-mode /
--imsi-mode / --imei-mode / --email-mode / --dn-mode / --token-mode /
--uri-mode / --apn-dnn-mode / --diameter-identity-mode / --payload-text-mode
                        per-class privacy mode: keep|mask|pseudonymize|encrypt|remove
```

### `init-config`
```
[path]   target file (default: pcap2llm.config.yaml)
--force  overwrite existing file
```

### `discover`
```
capture               input .pcap/.pcapng
--out                 artifact output directory (default: artifacts)
--display-filter/-Y   tshark display filter
--config              optional YAML config file
--two-pass / --tshark-path / --tshark-arg
```

### `recommend-profiles`
```
source                discovery JSON file OR raw capture
--display-filter/-Y   only meaningful when source is a capture
--config / --two-pass / --tshark-path / --tshark-arg
```

### `visualize`
```
flow_json             input flow.json from analyze --render-flow-svg
--out                 output SVG path (default: same stem, .svg)
--width               SVG canvas width in px (default: 1600)
```

### `analyze` — additional flags not in the main list above
```
--render-flow-svg     emit flow.json + flow.svg sidecars
```

### `ask-chatgpt` / `ask-claude` / `ask-gemini`
```
capture               input .pcap/.pcapng
--question            question to send with the bundled artifacts
                      (default: DEFAULT_CHATGPT_QUESTION — asks for evidence-first
                      failure analysis with ranked root causes)
# Inherits analyze flags (profile, privacy-profile, out, …).
# Never sends raw PCAP, mapping, or vault material.
```

### `session <start|run-discovery|run-profile|finalize>`
```
session start <capture>      --out <dir>
session run-discovery         --session <session-dir>
session run-profile           --session <session-dir> --profile <name>
session finalize              --session <session-dir> --status completed|failed
```

## Test Suite

32 test modules in `tests/`. Key ones:

| File | What it covers |
|---|---|
| `test_pipeline.py` | Full end-to-end pipeline, write_artifacts, size guard, truncation |
| `test_normalizer.py` | Packet normalization, verbatim protocols, field flattening |
| `test_privacy_profiles.py` | Privacy profile loading, precedence, deprecated path |
| `test_schema_contract.py` | Schema version, artifact contract (SummaryArtifactV1 / DetailArtifactV1) |
| `test_cli.py` | CLI invocation, dry-run, LLM mode |
| `test_cli_llm_mode.py` | LLM mode JSON output contract — primary machine-facing test |
| `test_app_anomaly.py` | Diameter and GTPv2-C anomaly detection |
| `test_dx_quality.py` | Data extraction quality, all CLI option help text |
| `test_golden_corpus.py` | Golden corpus integration tests |
| `test_two_pass.py` | Pass-1 index field extraction, PacketIndexRecord parsing |
| `test_inspect_enrichment.py` | Domain detection, trace shape, classification_state, anomalies |
| `test_recommendation.py` | Profile scoring, domain inference, evidence class, host hints |
| `test_recommendation_dns.py` | DNS discovery, core-name-resolution, dns-support suppression |
| `test_discovery.py` | Discovery artifacts, versioned filenames, JSON/Markdown output |
| `test_orchestration.py` | Session manifests, multi-run orchestration |
| `test_profiles.py` | Profile YAML loading, selector_metadata, verbatim_protocols |
| `test_profiles_5g_core_interfaces.py` / `test_profiles_2g3g_interfaces.py` / `test_profiles_volte_vonr.py` | Per-family profile coverage (5G SBI/N-interfaces, 2G/3G SS7/GERAN, VoLTE/VoNR) |
| `test_visualize.py` | Flow model construction, lane ordering, SVG rendering, label placement |
| `test_protector.py` | Pseudonymization, masking, Fernet encryption, vault-key validation |
| `test_resolver.py` / `test_resolver_extended.py` | Endpoint resolution lookup order, CIDR subnets, role inference |
| `test_summarizer.py` / `test_summarizer_extended.py` | Timing stats, burst detection, protocol counts |
| `test_inspector.py` | Inspector wrapper, `on_stage` callback wiring |
| `test_local_hosts.py` | Wireshark hosts-file parsing (see `examples/wireshark_hosts.sample`) |
| `test_chatgpt.py` / `test_claude.py` / `test_gemini.py` | External-LLM handoff prompt assembly and file layout |
| `test_local_batch_runner.py` | TOML batch definition loading, case selection, path resolution |
| `test_package_metadata_checker.py` | Guards against stale pyproject metadata |

## Dev scripts (`scripts/`)

- `run_local_batches.py` — executes `batches/*.toml` suites against local PCAPs (not committed)
- `benchmark_pipeline.py` — lightweight two-pass pipeline benchmark
- `update_golden.py` — regenerate golden corpus fixtures
- `install-git-hooks.sh` / `git-hooks/` — local git hook setup
