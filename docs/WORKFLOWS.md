# Workflows by Protocol

Step-by-step analysis workflows for the three built-in profiles.
General rule: always run `inspect` first, then narrow with `-Y` before running `analyze`.

---

## LTE / EPC

**Relevant protocols:** Diameter, GTPv2-C, S1AP, NAS-EPS, DNS

### Typical workflow

```bash
# Step 1 — understand what is in the capture
pcap2llm inspect trace.pcapng --profile lte-core

# Step 2 — full analysis, filtered to signaling only
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  -Y "diameter || gtpv2 || s1ap || nas-eps" \
  --privacy-profile share \
  --mapping-file ./mapping.yaml \
  --out ./artifacts
```

### Common display filters

```bash
# Diameter only (e.g. HSS ↔ MME)
-Y "diameter"

# Failed sessions (Diameter error codes)
-Y "diameter.resultcode >= 3000"

# GTPv2 session setup
-Y "gtpv2.message_type == 32 || gtpv2.message_type == 33"

# Combined signaling
-Y "diameter || gtpv2 || s1ap"
```

### Privacy recommendation

Use `--privacy-profile share` for internal tickets. Use `--privacy-profile prod-safe` before sharing with a vendor or external party.

### LTE-specific notes

- Enable `--two-pass` if captures contain IP fragmentation or TCP reassembly
- If TShark decodes a port as the wrong protocol, force it:
  ```bash
  --tshark-arg "-d" --tshark-arg "tcp.port==3868,diameter"
  ```

### If something goes wrong — LTE

| Symptom | Next step |
|---|---|
| Diameter messages missing from output | Check port: add `--tshark-arg "-d" --tshark-arg "sctp.port==3868,diameter"`. Run inspect without filter to verify the protocol appears at all. |
| GTPv2-C output too noisy | Narrow to specific message types: `-Y "gtpv2.message_type == 32"` (Create Session Request) or `gtpv2.message_type == 33` (Response). |
| `detail_truncated: true` | Refine the display filter to the specific call flow. Most LTE issues involve ≤ 100 signaling messages. |
| No relevant protocols detected | Check that `--profile lte-core` matches the traffic. Run inspect without `-Y` to see what protocols are present. |

---

## 5G Core

**Relevant protocols:** PFCP, NGAP, NAS-5GS, HTTP/2 SBI

### Typical workflow

```bash
# Step 1 — understand what is in the capture
pcap2llm inspect trace-5g.pcapng --profile 5g-core

# Step 2 — full analysis
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-core \
  -Y "ngap || pfcp || http2" \
  --privacy-profile share \
  --two-pass \
  --out ./artifacts
```

### Common display filters

```bash
# NGAP only (gNB ↔ AMF)
-Y "ngap"

# PFCP session management (SMF ↔ UPF)
-Y "pfcp"

# HTTP/2 SBI (NF-to-NF interfaces)
-Y "http2"

# Full control plane
-Y "ngap || pfcp || http2 || diameter"
```

### HTTP/2 SBI notes

SBI traffic (Nudm, Namf, Nsmf, etc.) runs over HTTP/2. Use `--two-pass` for reliable HTTP/2 reassembly. Authorization headers and tokens are common — use `--privacy-profile prod-safe` before sharing:

```bash
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-core \
  -Y "http2" \
  --privacy-profile prod-safe \
  --two-pass \
  --out ./artifacts
```

### Verbatim PFCP (all fields, no filtering)

If you need every PFCP field exactly as TShark reports it, add `verbatim_protocols` to a custom profile:

```yaml
# my-5g-verbose.yaml
name: my-5g-verbose
description: 5G core with verbatim PFCP
verbatim_protocols:
  - pfcp
# ... rest copied from 5g-core.yaml
```

### Privacy recommendation

Use `--privacy-profile prod-safe` for SBI captures — they often contain tokens, SUPIs, and GPSIs in HTTP headers.

### If something goes wrong — 5G

| Symptom | Next step |
|---|---|
| HTTP/2 SBI data looks incomplete or fragmented | Add `--two-pass`. HTTP/2 over TLS requires reassembly to decode correctly. |
| NGAP / PFCP mix too large | Split by interface: analyze NGAP and PFCP in separate runs with `-Y "ngap"` and `-Y "pfcp"`. |
| Tokens or subscriber IDs appear in headers | Switch to `--privacy-profile prod-safe`. HTTP/2 SBI headers routinely carry Authorization and SUPI. |
| No relevant protocols detected | Verify `--profile 5g-core` is set. Run inspect without filter to check what TShark sees. |

---

## Legacy 2G/3G — SS7 / GERAN

**Relevant protocols:** M3UA, SCCP, TCAP, MAP, CAP, ISUP, BSSAP

### Typical workflow

```bash
# Step 1 — understand what is in the capture
pcap2llm inspect trace-ss7.pcapng --profile 2g3g-ss7-geran

# Step 2 — full analysis
pcap2llm analyze trace-ss7.pcapng \
  --profile 2g3g-ss7-geran \
  -Y "gsm_map || cap || isup || bssap" \
  --privacy-profile share \
  --out ./artifacts
```

### Common display filters

```bash
# MAP only (HLR ↔ MSC/VLR)
-Y "gsm_map"

# ISUP call control
-Y "isup"

# CAP (CAMEL application)
-Y "cap"

# Combined
-Y "gsm_map || cap || isup || bssap"
```

### Protocol aliases

TShark uses internal names that differ from common names. The profile maps them automatically:

| Common name | TShark layer name |
|---|---|
| map | gsm_map |
| nas-eps | nas-eps, nas_eps |
| gtpv2 | gtpv2, gtpv2-c, gtp |

### Privacy recommendation

MAP traffic contains IMSI, MSISDN, and location data. Use `--privacy-profile share` as a minimum; consider `--privacy-profile lab` for captures with subscriber movements.

### If something goes wrong — SS7

| Symptom | Next step |
|---|---|
| Too many layers, output is very large | Narrow to the relevant protocol: `-Y "gsm_map"` or `-Y "isup"` instead of a combined filter. |
| Subscriber or location data visible in output | Switch to `--privacy-profile lab` or `prod-safe`. MAP traffic commonly carries IMSI and MSISDN. |
| TCAP or SCCP not decoded | Verify TShark version (≥ 3.6 recommended). Check that M3UA port assignment is correct. |

---

## General Tips

### Inspect before analyze

Always run `inspect` on an unknown capture first. It shows you protocol distribution, conversation count, and anomalies — without writing any files. Use this to decide whether to narrow the filter before `analyze`.

### Capture size matters

The `--max-packets` default (1 000) is a safety rail. A tightly filtered capture with 200 signaling messages produces a much more useful `detail.json` than a 50 000-packet dump trimmed to 1 000.

### Check coverage

After `analyze`, check `summary.json` for the `coverage` block:
```json
"coverage": {
  "detail_packets_included": 1000,
  "detail_packets_available": 47312,
  "detail_truncated": true
}
```
If `detail_truncated` is `true`, refine your filter or use `--max-packets` to capture the relevant range.

### Config file for repeated use

```bash
pcap2llm init-config
```
Edit `pcap2llm.config.yaml` to persist profile, mapping, hosts file, and privacy settings.

---

## Operator Triage — Start Here

| Situation | Right action |
|---|---|
| Unfamiliar capture, unknown content | `inspect` first — no files written, immediate protocol overview |
| Known focused flow, sensible packet count | `analyze` directly with appropriate `-Y` filter |
| Large or noisy output, `detail_truncated: true` | Re-filter with a tighter `-Y` — do **not** raise `--max-packets` |
| No relevant protocols in output | Check `--profile` matches the traffic; run `inspect` without `-Y` to confirm protocols present |
| HTTP/2, GTP, or SCTP looks incomplete | Add `--two-pass` |

---

## When Things Go Wrong

### Common situations and next steps

| Symptom | Next step |
|---|---|
| `detail_truncated: true` in summary | Refine the display filter to isolate the relevant call flow, then re-run. Do not just raise `--max-packets`. |
| No relevant protocols detected | Run `inspect` without `-Y` to see what protocols appear. Check that the profile matches the traffic type. |
| Empty `detail.json` (zero packets) | Your display filter is filtering out everything. Run without `-Y` first to confirm packets exist, then narrow. |
| Output too large to hand to an LLM | Tighten the filter to one call flow or one conversation. Split by stream if needed: `-Y "sctp.stream == 3"`. |
| HTTP/2 looks incomplete | Add `--two-pass`. Required for correct HTTP/2 reassembly over TCP. |
| Diameter or PFCP decoding appears wrong | Check TShark port assignments. Add explicit protocol decoder: `--tshark-arg "-d" --tshark-arg "sctp.port==3868,diameter"`. |

### When to stop and re-filter

**Raising `--max-packets` is not the answer.** A tighter filter is almost always the right response to a large or noisy output.

Stop the current analysis and re-filter when:

- `summary.json` shows `detail_truncated: true` on an unfiltered run with `detail_packets_available` far exceeding `detail_packets_included`. The detail artifact is a random slice of the export, not a focused call flow. No amount of packet-cap tuning changes this.
- `inspect` returns 10 000+ packets. No useful LLM analysis is possible on a packet set that large. Narrow with `-Y` to the specific event — a failing session, a rejected Diameter request, a specific NGAP procedure.
- The output is large but the anomalies section in `summary.json` is empty. The real failure is probably not in this part of the capture at all.
- You are about to raise `--max-packets` above 1 000. This is a signal to stop and filter instead.

**Workflow when re-filtering:**

```bash
# 1 — see what you have
pcap2llm inspect trace.pcapng --profile lte-core

# 2 — narrow to the specific event (example: Diameter errors only)
pcap2llm inspect trace.pcapng --profile lte-core -Y "diameter.resultcode >= 3000"

# 3 — if the filtered count is reasonable (dozens to low hundreds), run analyze
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  -Y "diameter.resultcode >= 3000" \
  --privacy-profile share \
  --out ./artifacts
```

A focused 50-packet capture with the actual failure is more useful to an LLM than 1 000 packets of background traffic.
