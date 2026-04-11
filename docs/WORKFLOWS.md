# Workflows by Protocol

Step-by-step analysis workflows for the built-in profile families.
General rule: always run `inspect` first, then narrow with `-Y` before running `analyze`.

---

## LTE / EPC

**Recommended profiles:** `lte-core`, `lte-s1`, `lte-s1-nas`, `lte-s6a`, `lte-s11`, `lte-s10`, `lte-sgs`, `lte-s5`, `lte-s8`, `lte-dns`, `lte-sbc-cbc`

### Pick the right LTE profile

| Situation | Best profile |
|---|---|
| Broad EPC overview, unknown signaling mix | `lte-core` |
| S1AP procedures and UE context handling | `lte-s1` |
| Attach, TAU, NAS reject causes | `lte-s1-nas` |
| MME ↔ HSS Diameter | `lte-s6a` |
| MME ↔ SGW bearer control | `lte-s11` |
| Inter-MME relocation | `lte-s10` |
| CS fallback / SGs paging | `lte-sgs` |
| SGW ↔ PGW inside EPC | `lte-s5` |
| Roaming-oriented SGW ↔ PGW context | `lte-s8` |
| EPC-adjacent DNS issues | `lte-dns` |
| Cell Broadcast / public warning via SBc | `lte-sbc-cbc` |

### Typical workflow

```bash
# Step 1 — understand what is in the capture
pcap2llm inspect trace.pcapng --profile lte-s6a

# Step 2 — full analysis, filtered to the interface you actually care about
pcap2llm analyze trace.pcapng \
  --profile lte-s6a \
  -Y "diameter && sctp" \
  --privacy-profile share \
  --mapping-file ./mapping.yaml \
  --out ./artifacts
```

### Common display filters

```bash
# Diameter on S6a (e.g. HSS ↔ MME)
-Y "diameter"

# Failed sessions (Diameter error codes)
-Y "diameter.resultcode >= 3000"

# GTPv2 session setup on S11
-Y "gtpv2.message_type == 32 || gtpv2.message_type == 33"

# NAS-centric S1 analysis
-Y "nas-eps && s1ap"

# SBc / Cell Broadcast
-Y "sbcap && sctp"
```

### Privacy recommendation

Use `--privacy-profile share` for internal tickets. Use `--privacy-profile prod-safe` before sharing with a vendor or external party.

### LTE-specific notes

- Enable `--two-pass` if captures contain fragmentation or incomplete dissector output that benefits from two-pass decoding
- If TShark decodes a port as the wrong protocol, force it:
  ```bash
  --tshark-arg "-d" --tshark-arg "tcp.port==3868,diameter"
  ```
- `lte-s6a` keeps surfaced Diameter AVPs but removes raw AVP dump structures by default to keep artifacts smaller and less noisy for LLMs

### If something goes wrong — LTE

| Symptom | Next step |
|---|---|
| Diameter messages missing from output | Use `lte-s6a`, check port with `--tshark-arg "-d" --tshark-arg "sctp.port==3868,diameter"`, and run inspect without filter to verify the protocol appears at all. |
| GTPv2-C output too noisy | Use `lte-s11`, `lte-s10`, `lte-s5`, or `lte-s8` instead of `lte-core`, then narrow to specific message types such as `gtpv2.message_type == 32`. |
| `detail_truncated: true` | Refine the display filter to the specific call flow. Most LTE issues involve ≤ 100 signaling messages. |
| No relevant protocols detected | Check that the interface-specific profile matches the traffic. Run inspect without `-Y` to see what protocols are present. |

---

## 5G SA Core

**Recommended profiles:** `5g-core`, `5g-n1-n2`, `5g-n2`, `5g-nas-5gs`, `5g-sbi`, `5g-sbi-auth`, `5g-n8`, `5g-n10`, `5g-n11`, `5g-n12`, `5g-n13`, `5g-n14`, `5g-n15`, `5g-n16`, `5g-n22`, `5g-n26`, `5g-n40`, `5g-dns`, `5g-cbc-cbs`

### Pick the right 5G SA profile

| Situation | Best profile |
|---|---|
| Unknown mixed 5GC signaling, first pass | `5g-core` |
| Combined AMF-facing registration picture | `5g-n1-n2` |
| gNB ↔ AMF NGAP procedures only | `5g-n2` |
| NAS-5GS registration, mobility, and SM sequencing | `5g-nas-5gs` |
| Broad HTTP/2 SBI troubleshooting | `5g-sbi` |
| Token/header/identity-heavy SBI captures | `5g-sbi-auth` |
| UDM-facing SBI on N8 | `5g-n8` |
| UDM ↔ AUSF authentication on N10 | `5g-n10` |
| SMF-facing control on N11 | `5g-n11` |
| AUSF ↔ UDM identity/auth data on N12 | `5g-n12` |
| UDM ↔ UDR subscriber data access on N13 | `5g-n13` |
| AMF ↔ AMF mobility/context coordination | `5g-n14` |
| PCF policy interactions on N15 | `5g-n15` |
| SMF ↔ PCF policy/session control on N16 | `5g-n16` |
| NSSF / selection / roaming-oriented SBI context | `5g-n22` |
| Hybrid EPC ↔ 5GC interworking | `5g-n26` |
| Charging-related SMF ↔ CHF signaling | `5g-n40` |
| 5GC-adjacent DNS issues | `5g-dns` |
| Public-warning / cell-broadcast signaling | `5g-cbc-cbs` |

### Typical workflow

```bash
# Step 1 — understand what is in the capture
pcap2llm inspect trace-5g.pcapng --profile 5g-n11

# Step 2 — full analysis
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-n11 \
  -Y "http2" \
  --privacy-profile share \
  --two-pass \
  --out ./artifacts
```

### Common display filters

```bash
# NGAP only (gNB ↔ AMF)
-Y "ngap"

# NAS-5GS inside AMF-facing signaling
-Y "nas-5gs || nas_5gs"

# PFCP session management (SMF ↔ UPF)
-Y "pfcp"

# HTTP/2 SBI (NF-to-NF interfaces)
-Y "http2"

# N26-style interworking / mixed EPC-5GC context
-Y "gtpv2 || http2 || ngap || nas-5gs || nas_5gs"
```

### HTTP/2 SBI notes

SBI traffic (Nudm, Namf, Nsmf, etc.) runs over HTTP/2. Use `--two-pass` for reliable HTTP/2 reassembly. Authorization headers and tokens are common — use `--privacy-profile prod-safe` before sharing:

```bash
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-sbi-auth \
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
# ... rest copied from 5g-core.yaml or a narrower 5G interface profile
```

### Privacy recommendation

Use `--privacy-profile prod-safe` for SBI captures — they often contain tokens, SUPIs, and GPSIs in HTTP headers.

### 5G-specific notes

- `5g-core` is still useful as a broad first-pass overview, but the focused 5G SA profiles usually produce cleaner protocol ranking and smaller artifacts once the interface is known.
- `5g-n26` is intentionally hybrid because EPC/5GC interworking evidence often spans HTTP/2, NGAP, NAS-5GS, and EPC-era control traffic in the same capture.
- Use `5g-sbi-auth` rather than generic `5g-sbi` when the troubleshooting question is about identity, tokens, or authorization failures.

### If something goes wrong — 5G

| Symptom | Next step |
|---|---|
| HTTP/2 SBI data looks incomplete or fragmented | Add `--two-pass` and switch from `5g-core` to a narrower SBI profile such as `5g-sbi`, `5g-sbi-auth`, or `5g-n11`. |
| NGAP / NAS evidence is mixed and too large | Split by intent: use `5g-n2` for NGAP or `5g-nas-5gs` for NAS-centric work, then narrow with `-Y "ngap"` or `-Y "nas-5gs || nas_5gs"`. |
| Hybrid 4G/5G mobility is confusing | Use `5g-n26` rather than pure 5G or pure EPC profiles; it is intentionally framed for mixed interworking context. |
| Tokens or subscriber IDs appear in headers | Switch to `--privacy-profile prod-safe`. HTTP/2 SBI headers routinely carry Authorization and SUPI. |
| No relevant protocols detected | Verify that the chosen 5G profile matches the interface. Run inspect without filter to check what TShark sees, then fall back to `5g-core` for a broad first pass. |

---

## Legacy 2G/3G — SS7 / GERAN

**Recommended profiles:** `2g3g-ss7-geran`, `2g3g-gn`, `2g3g-gp`, `2g3g-gr`, `2g3g-gs`, `2g3g-geran`, `2g3g-dns`, `2g3g-map-core`, `2g3g-cap`, `2g3g-bssap`, `2g3g-isup`, `2g3g-sccp-mtp`

### Pick the right 2G/3G profile

| Situation | Best profile |
|---|---|
| Unknown legacy SS7 mix, broad first pass | `2g3g-ss7-geran` |
| SGSN ↔ GGSN inside one PLMN | `2g3g-gn` |
| GPRS roaming / inter-PLMN GTPv1 | `2g3g-gp` |
| SGSN ↔ HLR MAP signaling | `2g3g-gr` |
| SGSN ↔ MSC/VLR combined CS/PS coordination | `2g3g-gs` |
| Core-side GERAN/A-interface signaling | `2g3g-geran` |
| Legacy/core DNS behavior | `2g3g-dns` |
| Broad MAP-core troubleshooting | `2g3g-map-core` |
| CAP / CAMEL service logic | `2g3g-cap` |
| Focused BSSAP/BSSMAP/DTAP mechanics | `2g3g-bssap` |
| Legacy voice/circuit signaling | `2g3g-isup` |
| SCCP or MTP routing/transport faults | `2g3g-sccp-mtp` |

### Typical workflow

```bash
# Step 1 — understand what is in the capture
pcap2llm inspect trace-ss7.pcapng --profile 2g3g-gr

# Step 2 — full analysis
pcap2llm analyze trace-ss7.pcapng \
  --profile 2g3g-gr \
  -Y "gsm_map || tcap || sccp" \
  --privacy-profile share \
  --out ./artifacts
```

### Common display filters

```bash
# MAP only (HLR ↔ MSC/VLR)
-Y "gsm_map"

# Gn / Gp GTPv1 control plane
-Y "gtp && udp.port == 2123"

# ISUP call control
-Y "isup"

# CAP (CAMEL application)
-Y "cap"

# Combined legacy sweep
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
| GTPv1 roaming vs intra-PLMN context is unclear | Split the run into `2g3g-gn` and `2g3g-gp`; the protocol is similar, but the heuristics and interpretation differ on purpose. |
| MAP output is too broad | Use `2g3g-gr` for SGSN ↔ HLR or `2g3g-map-core` for broader MAP-only analysis instead of the broad legacy bundle. |
| Too many layers, output is very large | Narrow to the relevant protocol: `-Y "gsm_map"` or `-Y "isup"` instead of a combined filter. |
| Subscriber or location data visible in output | Switch to `--privacy-profile lab` or `prod-safe`. MAP traffic commonly carries IMSI and MSISDN. |
| TCAP or SCCP not decoded | Verify TShark version (≥ 3.6 recommended). Check that M3UA port assignment is correct. |

---

## Voice Over IMS — VoLTE and VoNR

**Recommended profiles:** `volte-sip`, `volte-sip-register`, `volte-sip-call`, `volte-diameter-cx`, `volte-diameter-rx`, `volte-diameter-sh`, `volte-dns`, `volte-rtp-signaling`, `volte-sbc`, `volte-ims-core`, `vonr-sip`, `vonr-sip-register`, `vonr-sip-call`, `vonr-ims-core`, `vonr-policy`, `vonr-dns`, `vonr-n1-n2-voice`, `vonr-sbi-auth`, `vonr-sbi-pdu`, `vonr-sbc`

### Pick the right voice profile

| Situation | Best profile |
|---|---|
| Broad VoLTE SIP troubleshooting | `volte-sip` |
| VoLTE IMS registration issue | `volte-sip-register` |
| VoLTE call setup or release issue | `volte-sip-call` |
| VoLTE IMS subscriber / registration Diameter | `volte-diameter-cx` |
| VoLTE policy or media authorization issue | `volte-diameter-rx` |
| VoLTE service-data/profile access issue | `volte-diameter-sh` |
| VoLTE IMS DNS discovery | `volte-dns` |
| VoLTE signaling plus RTP or SDP support view | `volte-rtp-signaling` |
| VoLTE Session Border Controller boundary | `volte-sbc` |
| Broad mixed VoLTE IMS-core incident | `volte-ims-core` |
| Broad VoNR SIP troubleshooting | `vonr-sip` |
| VoNR IMS registration issue | `vonr-sip-register` |
| VoNR call setup or release issue | `vonr-sip-call` |
| Broad mixed VoNR IMS + 5GS incident | `vonr-ims-core` |
| VoNR policy / QoS / session-control issue | `vonr-policy` |
| VoNR discovery or IMS DNS issue | `vonr-dns` |
| VoNR voice-relevant NGAP / NAS-5GS state | `vonr-n1-n2-voice` |
| VoNR auth-related SBI issue | `vonr-sbi-auth` |
| VoNR voice-relevant PDU / session SBI issue | `vonr-sbi-pdu` |
| VoNR Session Border Controller boundary | `vonr-sbc` |

### Typical REGISTER workflow

```bash
# VoLTE registration
pcap2llm inspect trace-ims.pcapng --profile volte-sip-register
pcap2llm analyze trace-ims.pcapng \
  --profile volte-sip-register \
  -Y "sip.Method == \"REGISTER\" || sip.CSeq.method == \"REGISTER\" || dns" \
  --privacy-profile share \
  --two-pass \
  --out ./artifacts

# VoNR registration with 5GS context nearby
pcap2llm analyze trace-ims-5gs.pcapng \
  --profile vonr-sip-register \
  -Y "sip.Method == \"REGISTER\" || sip.CSeq.method == \"REGISTER\" || dns" \
  --privacy-profile share \
  --two-pass \
  --out ./artifacts
```

### Typical call-setup workflow

```bash
# VoLTE call setup
pcap2llm analyze trace-call.pcapng \
  --profile volte-sip-call \
  -Y "sip.Method == \"INVITE\" || sip.CSeq.method == \"INVITE\" || sip.Status-Code >= 180" \
  --privacy-profile share \
  --two-pass \
  --out ./artifacts

# VoNR call setup
pcap2llm analyze trace-vonr-call.pcapng \
  --profile vonr-sip-call \
  -Y "sip.Method == \"INVITE\" || sip.CSeq.method == \"INVITE\" || sip.Status-Code >= 180" \
  --privacy-profile share \
  --two-pass \
  --out ./artifacts
```

### Diameter, DNS, SBC, and 5GS support views

```bash
# VoLTE Cx / subscriber context
-Y "diameter"

# VoLTE Rx policy flows
-Y "diameter"

# IMS discovery support
-Y "dns"

# Session Border Controller edge issues
-Y "sip"

# Voice-relevant 5GS state
-Y "ngap || nas-5gs || nas_5gs"

# VoNR auth or policy SBI
-Y "http2"
```

### Voice-specific notes

- Use `volte-*` only when the operational context is LTE / EPS IMS voice service; do not use them as generic SIP profiles.
- Use `vonr-*` when voice over 5GS depends on 5GS registration, N1/N2 state, or SBI policy and session control.
- `volte-sbc` and `vonr-sbc` mean Session Border Controller, not Cell Broadcast `SBc`.
- Keep `--two-pass` enabled for SIP-heavy traces whenever TCP segmentation or HTTP/2 reassembly could hide the real sequence.

### If something goes wrong — Voice over IMS

| Symptom | Next step |
|---|---|
| REGISTER loops without stable success | Use `volte-sip-register` or `vonr-sip-register` and include DNS in the filter so discovery and challenge flow stay visible together. |
| INVITE fails but registration looked normal | Switch from the register profile to `volte-sip-call` or `vonr-sip-call`; do not mix readiness and call execution into one conclusion. |
| SIP looks fine but policy or subscriber context seems wrong | Move to `volte-diameter-cx`, `volte-diameter-rx`, `volte-diameter-sh`, `vonr-policy`, `vonr-sbi-auth`, or `vonr-sbi-pdu` depending on the network context. |
| RTP suspicion exists but this is still a signaling problem | Use `volte-rtp-signaling` to keep SDP, RTP, and RTCP as supporting evidence rather than switching to a full media-quality workflow. |
| VoNR failure seems tied to paging, service request, or mobility | Use `vonr-n1-n2-voice` or broaden to `vonr-ims-core` so NGAP and NAS-5GS state is visible next to IMS symptoms. |

---

## General Tips

### Inspect before analyze

Always run `inspect` on an unknown capture first. It shows you protocol distribution, conversation count, and anomalies — without writing any files. Use this to decide whether to narrow the filter before `analyze`.

### Capture size matters

The `--max-packets` default (1 000) is a safety rail. The pipeline runs in **two passes**: pass 1 scans all packets as lightweight field data (low memory); pass 2 exports full JSON only for the selected N packets — memory is proportional to `--max-packets`, not the full capture. **Pass 1 still scans the entire capture.** A large rolling trace with a 500-packet limit still requires a full pass-1 scan and produces only the first 500 packets as output. The remedy is a tighter `-Y` filter, not a bigger limit. A tightly filtered capture with 200 signaling messages produces a much more useful `detail.json` than a 50 000-packet dump trimmed to 1 000.

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

For the hosts file, the simplest approach is to place it at `.local/hosts` — the tool loads it automatically without any config entry or CLI flag. See `docs/REFERENCE.md` → "Local-only sensitive files".

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
