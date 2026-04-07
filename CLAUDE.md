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

# Run tests
pytest

# Lint
ruff check .

# CLI usage
pcap2llm inspect sample.pcapng --profile lte-core
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
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

**Profiles** (`src/pcap2llm/profiles/*.yaml`) define which protocols to extract, field priorities, privacy defaults, and TShark options. Three built-in: `lte-core`, `5g-core`, `2g3g-ss7-geran`.

**Data models** (`models.py`) use Pydantic v2. Key types: `NormalizedPacket`, `InspectResult`, `ProfileDefinition`, `AnalyzeArtifacts`.

**CLI** (`cli.py`) uses Typer with three commands: `inspect`, `analyze`, `init-config`.

**Endpoint resolution** (`resolver.py`) supports Wireshark hosts files and custom YAML/JSON mapping files for IP→alias/role/site enrichment.

## Key Design Decisions

- Profile YAML drives protocol selection and privacy — extending protocols means editing profiles, not code
- Privacy operates on 13 data classes (ip, hostname, imsi, msisdn, etc.) with per-class mode selection
- Encryption uses `cryptography.fernet` with key from `PCAP2LLM_VAULT_KEY` env var
- TShark field extraction handles both flat and nested JSON structures for resilience across TShark versions
- All processing is local; no remote transmission
