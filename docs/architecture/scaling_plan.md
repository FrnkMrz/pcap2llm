# Scaling Plan

`pcap2llm` now bounds the public `detail.json` artifact, but the current TShark ingestion path still loads full JSON into memory before packet selection.

## Current Limitation

- `detail.json` is bounded
- `summary.json` remains explicit about coverage and truncation
- raw `tshark -T json` export is still full-load in memory

This means the tool is still best for focused captures.

## Options Considered

### 1. Full-load JSON only

Keep the current architecture and rely on documentation alone.

- Simple
- Not sufficient for accidental large captures

### 2. Two-pass design

- Pass 1 for metadata/summary
- Pass 2 for bounded detail export

This is structurally promising, but still requires careful TShark extraction design and more implementation work than this round should absorb.

### 3. Size guard plus staged policy

- detect oversized captures before TShark JSON export
- fail fast unless the operator explicitly raises or disables the size guard
- keep bounded detail export and honest docs

## Recommended Next Step

The practical next step is **Option 3**.

It does not solve streaming ingestion yet, but it prevents the most common accidental misuse: sending very large captures into a full-load JSON pipeline without realizing the cost.

## Implemented In This Round

- `--max-capture-size-mb` guard added to the CLI
- default fail-fast threshold before TShark JSON export
- docs updated to explain that bounded output does not yet mean bounded ingestion

## Future Direction

The next structural upgrade should be a true summary/detail extraction split or two-pass architecture so that large captures can be handled more intentionally without full in-memory JSON materialization.
