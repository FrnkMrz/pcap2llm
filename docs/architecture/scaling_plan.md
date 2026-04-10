# Scaling Plan

`pcap2llm` bounds the public `detail.json` artifact, but the current TShark
ingestion path still loads the full exported JSON into memory before packet
selection.

---

## Current Behavior (as implemented)

| Stage | What happens |
|---|---|
| Size guard | Rejects captures above `--max-capture-size-mb` (default 250 MiB) before TShark runs |
| TShark export | Full capture → JSON in memory, no streaming |
| Inspection | Runs on all exported packets — summary stats are always accurate |
| Oversize guard | Rejects if `total_exported > max_packets × oversize_factor` (default 10×) |
| Packet selection | Slices to `max_packets` |
| Normalization / protection | Runs only on the selected slice |
| Serialization | Writes bounded `detail.json` + full-coverage `summary.json` |

**What the current guards protect against:**

- `--max-capture-size-mb`: prevents importing very large files before TShark even runs
- `--oversize-factor`: prevents silently discarding 95%+ of an export (e.g. 50 000 packets exported, 1 000 written — a 50× ratio is now an explicit error, not a silent truncation)

**What this round also improved:**

- After packet selection, `raw_packets` (the full TShark export) is now explicitly released from memory before normalization and protection run. This means the peak memory held during the expensive processing stages is proportional to `max_packets`, not to `total_exported`. For a 10 000-packet export with `--max-packets 1000`, this eliminates 9 000 packet dicts from memory during stages 3–5.

**What the current implementation does NOT solve:**

- The full TShark JSON export still materializes in memory during inspection — memory cost at that stage is still proportional to `total_exported`
- A 50 000-packet export still requires full TShark JSON materialization before inspection can run

---

## Options for Future Improvement

### Option 1: Two-pass extraction

- **Pass 1**: TShark export with `-T fields` or a lightweight filter to collect metadata, protocol counts, timestamps, and conversation tuples only — no full JSON materialization
- **Pass 2**: Second TShark run with a narrower display filter or frame-number selection for the bounded detail extraction

**Pros**: memory usage becomes proportional to the detail artifact, not the full capture  
**Cons**: two TShark invocations per run; frame-number selection across large captures requires careful filter construction; inspect and detail must stay consistent  
**Verdict**: right long-term direction, not yet justified by the current tool scope

### Option 2: TShark PDML/EK streaming

- Use `tshark -T ek` (Elasticsearch JSON, line-delimited) instead of `-T json`
- Parse line-by-line, maintain a sliding window

**Pros**: true streaming ingestion  
**Cons**: EK format diverges from JSON field names; significant normalizer rewrite  
**Verdict**: too disruptive for current architecture; revisit when the tool usage patterns are clearer

### Option 3: Stronger defensive policy (current round — implemented)

- Pre-export size guard (already existed)
- Post-export oversize-ratio guard (added in this round)
- Explicit `capture_oversize` error code for machine consumers
- Documentation of what limits mean and don't mean

**Pros**: no architecture change; fails fast and clearly; machine-readable  
**Cons**: does not reduce actual memory or processing cost on large captures  
**Verdict**: right next step for the current maturity level; prevents the most common accidental misuse

---

## Recommended Next Step

**Option 1 (two-pass)** is the correct long-term direction.

The concrete design would be:

1. Run TShark pass 1 with `-T fields -e frame.number -e frame.time_epoch -e frame.protocols` — lightweight, produces one line per packet
2. Use pass 1 output to build the inspection result (protocol counts, timestamps, conversations)
3. Select the target frame numbers for the detail artifact (e.g. first N, or frames matching an additional filter)
4. Run TShark pass 2 with `-T json -Y "frame.number in {1,2,3,...}"` for only the selected frames
5. Normalize and protect only the pass 2 result

This would make memory use proportional to the detail artifact size and would
make `--max-packets` a real processing bound, not just an output bound.

**Prerequisite before starting**: validate that TShark frame-number filtering
is reliable and consistent across TShark versions (4.0, 4.2, 4.6) on both
macOS and Linux. A failing TShark filter at this stage would silently produce
wrong summary statistics.

---

## Current Status

| Guard / Improvement | Status |
|---|---|
| `--max-capture-size-mb` | ✅ Implemented |
| `--oversize-factor` (post-export ratio guard) | ✅ Implemented |
| `capture_oversize` error code | ✅ Implemented |
| Early release of `raw_packets` after selection | ✅ Implemented |
| Two-pass extraction | ⬜ Future work |
| Streaming ingestion | ⬜ Future work |
