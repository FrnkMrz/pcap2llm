# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pcap2llm converts PCAP/PCAPNG network captures into compact, LLM-friendly JSON artifacts for telecom troubleshooting. It uses TShark for packet dissection and applies profile-driven normalization, reduction, and privacy protection.

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

# CLI usage
pcap2llm inspect sample.pcapng --profile lte-core
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 500 --out ./artifacts
pcap2llm analyze sample.pcapng --profile lte-core --all-packets --out ./artifacts
pcap2llm init-config
```

## Architecture

**Processing pipeline** (`src/pcap2llm/pipeline.py` orchestrates):

1. **TShark export** (`tshark_runner.py`) — runs `tshark -T json` to get raw packets
2. **Inspection** (`inspector.py`) — extracts metadata, detects protocols, finds anomalies
3. **Normalization** (`normalizer.py`) — transforms raw TShark JSON into stable internal schema with resolved endpoints
4. **Reduction** (`reducer.py`) — strips transport fields to profile-specified set, keeps message protocol in full
5. **Protection** (`protector.py`) — applies privacy modes (keep/mask/pseudonymize/encrypt/remove) per data class using heuristic field classification
6. **Summarization** (`summarizer.py`) — builds summary JSON and markdown report

**App-layer anomaly detection** (`app_anomaly.py`) — runs after per-packet inspection; detects Diameter and GTPv2-C state anomalies (unanswered requests, error codes, Error Indications).

**Profiles** (`src/pcap2llm/profiles/*.yaml`) define which protocols to extract, field priorities, privacy defaults, and TShark options. Three built-in: `lte-core`, `5g-core`, `2g3g-ss7-geran`. Custom profiles: see `docs/PROFILES.md`.

**Data models** (`models.py`) use Pydantic v2. Key types: `NormalizedPacket`, `InspectResult`, `ProfileDefinition`, `AnalyzeArtifacts`. `ProfileDefinition.max_conversations` (default 25) controls the conversation table size.

**CLI** (`cli.py`) uses Typer with three commands: `inspect`, `analyze`, `init-config`. Exit code 1 on all errors; error text goes to stderr. Progress is shown via `rich` on TTYs (spinner + step counter); falls back to plain stderr lines in non-interactive environments.

**Endpoint resolution** (`resolver.py`) supports Wireshark hosts files and custom YAML/JSON mapping files. Lookup order: exact IP → case-insensitive hostname → CIDR subnet → port-based role inference.

## Key Design Decisions

- Profile YAML drives protocol selection and privacy — extending protocols means editing profiles, not code
- Privacy operates on 13 data classes (ip, hostname, imsi, msisdn, etc.) with per-class mode selection
- Pseudonyms are **hash-based** (BLAKE2s) — stable across runs, format: `IMSI_a3f2b1c4`
- Encryption uses `cryptography.fernet` with key from `PCAP2LLM_VAULT_KEY` env var; validated early via `Protector.validate_vault_key()` before packet processing begins
- `normalize_packets()` returns `(packets, dropped_count)` — malformed packets are logged and skipped
- `summary.json` always contains `schema_version`, `generated_at`, and `capture_sha256`
- `analyze_capture()` accepts `max_packets` (default 1000, 0 = unlimited) — inspection runs on all packets, only normalization onwards is sliced; truncation is recorded in `summary["detail_truncated"]`
- Progress reporting uses an optional `on_stage(description, step, total)` callback; the CLI wires this to `rich.progress` on TTYs
- All processing is local; no remote transmission
