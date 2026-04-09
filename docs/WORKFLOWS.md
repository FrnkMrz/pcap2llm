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
