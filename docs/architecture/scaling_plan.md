# Scaling Plan

This page explains how the current two-pass pipeline behaves for large or
bounded captures and where the remaining scaling limits still are.

Related docs:

- [`../DOCUMENTATION_MAP.md`](../DOCUMENTATION_MAP.md)
- [`current_pipeline.md`](current_pipeline.md)
- [`../REFERENCE.md`](../REFERENCE.md)
- [`../PROJECT_STATUS.md`](../PROJECT_STATUS.md)

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
| Serialization | Writes bounded `detail.json` + full-coverage `summary.json`; optionally derives `flow.json` + `flow.svg` from the protected bounded packet set |

**What this makes true:**

- `--max-packets` is now a real processing bound, not just an output bound
- Normalization and protection memory is proportional to the detail artifact, not the full capture
- Inspection accuracy is preserved: pass-1 covers all packets, so `summary.json` stats are always complete
- Anomaly detection (Diameter, GTPv2-C) runs over all pass-1 records — stateful detectors remain correct
- Flow rendering is bounded by the protected detail packet set and `--flow-max-events`; it is not a second full-capture pass

**What still applies:**

- Pass 1 still scans the entire capture — a 50 000-packet capture still requires a full pass-1 scan
- A large rolling trace remains a poor fit; the first remedy is a tighter `-Y` display filter
- `--oversize-factor` catches extreme mismatches before pass 2 starts

---

## Pass-2 Consistency: Bounded vs. Unlimited Runs

Pass-2 behavior is split on `max_packets`:

| `max_packets` value | Pass-2 path | Why |
|---|---|---|
| `> 0` (bounded) | `export_selected_packets()` always — truncated **and** non-truncated | Consistent two-pass behavior; both paths use the same code |
| `0` (unlimited / `--all-packets`) | `export_packets()` full export | Avoids building a huge frame-number filter string for many thousands of frames |

The bounded path is the common path.  `--all-packets` is a deliberate opt-out.

---

## Frame-Number Filtering: Compatibility Notes

Pass 2 relies on TShark's `frame.number in {N1,N2,...}` display filter syntax.

**What is validated:**
- Filter syntax is correct for TShark ≥ 3.6 (all versions tested in CI: macOS TShark 4.x)
- Large frame sets are chunked at 500 per invocation to keep filter strings manageable
- Empty frame lists short-circuit before TShark is called
- Ordering within each chunk preserves pass-1 insertion order; chunks are merged in order

**Known assumptions:**
- `frame.number` is a reliable stable field in all TShark versions ≥ 3.6
- The `in {...}` set syntax is supported from TShark 2.x onward
- Frame numbers are 1-based and match the index values TShark emits in pass 1

**Validation:** `scripts/benchmark_pipeline.py` can be run against a real capture to
sanity-check that pass-2 frame selection returns the expected frame count.

**If you encounter a TShark version where frame-number filtering behaves differently:**
please open an issue with `tshark --version` output and the filter string that failed.

---

## Summary Semantics: Capture-wide vs. Detail-derived

`summary.json` contains two categories of facts:

**Capture-wide (pass 1, always accurate for the full capture):**
- `capture_metadata` — packet count, first/last seen, raw protocols
- `relevant_protocols`, `conversations`
- `packet_message_counts.total_packets`, `packet_message_counts.transport`
- `anomalies`, `anomaly_counts_by_layer`

**Detail-derived (pass 2, reflects selected packet window only):**
- `packet_message_counts.top_protocols` — counted from normalized detail packets
- `timing_stats`, `burst_periods` — computed from detail timing only
- Protocol-count sentences in `deterministic_findings`

When `detail_truncated` is true, detail-derived fields describe the selected window,
not the full capture.  Capture-wide fields remain accurate regardless.

---

## Performance Validation

`scripts/benchmark_pipeline.py` provides a lightweight reproducible measurement:

```bash
python scripts/benchmark_pipeline.py           # synthetic fixtures only (no TShark)
python scripts/benchmark_pipeline.py trace.pcapng --rounds 3   # real capture, 3 rounds
```

Output columns: `scenario`, `pkts_in` (pass-1 total), `pkts_out` (detail size),
`summ_total` (must equal `pkts_in`), `wall_s`, `rss_mib`, `truncated`.

Key invariant the benchmark verifies: `pkts_in == summ_total` — capture-wide packet
count in `summary.json` is always the full pass-1 total, not the truncated slice.

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
| Early release of pass-1 index after frame selection (`del index_records`) | ✅ Implemented |
| Early release of pass-2 raw JSON before normalization (`del detail_raw`) | ✅ Implemented |
| Streaming ingestion (pass 2 line-by-line) | ⬜ Future work |
