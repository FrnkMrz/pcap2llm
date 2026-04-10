# Scaling Plan

`pcap2llm` uses a two-pass TShark extraction pipeline. Memory cost during
normalization and protection is proportional to `--max-packets`, not to the
full capture size.

---

## Current Behavior (as implemented)

| Stage | What happens |
|---|---|
| Size guard | Rejects captures above `--max-capture-size-mb` (default 250 MiB) before TShark runs |
| **Pass 1 — lightweight export** | TShark `-T fields` with `\|` separator: 29 fields per packet, one line per packet; no full JSON materialization |
| Inspection | Runs on all pass-1 records — summary stats always cover the full capture |
| Oversize guard | Rejects if `total_exported > max_packets × oversize_factor` (default 10×) |
| Frame selection | Derives bounded set of frame numbers from pass-1 records |
| **Pass 2 — selective export** | TShark `-T json -Y "frame.number in {N1,N2,...}"` for selected frames only; chunked at 500 frames per invocation |
| Normalization / protection | Runs only on the pass-2 output — memory proportional to `max_packets` |
| Serialization | Writes bounded `detail.json` + full-coverage `summary.json` |

**What this makes true:**

- `--max-packets` is now a real processing bound, not just an output bound
- Normalization and protection memory is proportional to the detail artifact, not the full capture
- Inspection accuracy is preserved: pass-1 covers all packets, so `summary.json` stats are always complete
- Anomaly detection (Diameter, GTPv2-C) runs over all pass-1 records — stateful detectors remain correct

**What still applies:**

- Pass 1 still scans the entire capture — a 50 000-packet capture still requires a full pass-1 scan
- A large rolling trace remains a poor fit; the first remedy is a tighter `-Y` display filter
- `--oversize-factor` catches extreme mismatches before pass 2 starts

---

## Remaining Scaling Limits

### Pass 1 is still full-capture

Pass 1 uses `-T fields` which is lightweight (no JSON parsing, no full dissection tree), but it still visits every packet. A 50 000-packet capture needs 50 000 pass-1 lines. The memory cost is negligible (each line is ~200 bytes), but the wall-clock time scales linearly with capture size.

**Mitigation**: always apply a `-Y` display filter when the capture contains background traffic unrelated to the event under investigation.

### TShark PDML/EK streaming

- Use `tshark -T ek` (Elasticsearch JSON, line-delimited) instead of `-T json` for pass 2
- Parse line-by-line, maintain a sliding window

**Pros**: true streaming ingestion for pass 2  
**Cons**: EK format diverges from JSON field names; significant normalizer rewrite  
**Verdict**: too disruptive for the current architecture; revisit when usage patterns require it

---

## Current Status

| Guard / Improvement | Status |
|---|---|
| `--max-capture-size-mb` | ✅ Implemented |
| `--oversize-factor` (post-export ratio guard) | ✅ Implemented |
| `capture_oversize` error code | ✅ Implemented |
| Two-pass extraction (pass 1 lightweight, pass 2 selective) | ✅ Implemented |
| `--max-packets` as real processing bound | ✅ Implemented |
| Early release of pass-1 index after frame selection | ✅ Implemented |
| Streaming ingestion (pass 2 line-by-line) | ⬜ Future work |
