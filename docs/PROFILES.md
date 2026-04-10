# Analysis Profiles

Profiles are YAML files that tell pcap2llm which protocols to extract, which fields to keep, and how to run TShark. You can create a custom profile without changing any Python code.

> **Note:** Profiles control protocol analysis only. Privacy settings are separate — use `--privacy-profile` on the command line or in your config file.

## Where to Put a Profile

Drop the YAML file into `src/pcap2llm/profiles/` and reference it by its filename stem:

```bash
# File: src/pcap2llm/profiles/voip-sip.yaml
pcap2llm analyze capture.pcapng --profile voip-sip
```

## Built-In LTE Interface Profiles

The LTE family includes focused interface profiles so you can choose a profile
that matches the actual troubleshooting question instead of always using one
generic EPC bundle.

| Profile | Best used for |
|---|---|
| `lte-core` | Broad EPC overview across Diameter, GTPv2-C, S1AP, NAS-EPS, DNS |
| `lte-s1` | General S1-MME control-plane troubleshooting |
| `lte-s1-nas` | NAS-centric Attach, TAU, authentication, and ESM analysis |
| `lte-s6a` | Diameter on S6a between MME and HSS |
| `lte-s11` | MME ↔ SGW GTPv2-C control-plane procedures |
| `lte-s10` | Inter-MME relocation and context transfer |
| `lte-sgs` | SGsAP paging, CS fallback, and legacy interworking |
| `lte-s5` | SGW ↔ PGW EPC context with control-plane emphasis |
| `lte-s8` | Roaming-oriented SGW ↔ PGW / inter-PLMN context |
| `lte-dns` | LTE/EPC/IMS-adjacent DNS issues |
| `lte-sbc-cbc` | SBc between MME and CBC for Cell Broadcast / ETWS / CMAS |

Important distinctions:

- `lte-s1` vs `lte-s1-nas`: use `lte-s1` when the main question is procedure flow or S1AP cause handling; use `lte-s1-nas` when NAS sequencing and reject causes are the main signal.
- `lte-s5` vs `lte-s8`: both are GTP-heavy, but `lte-s8` is intentionally documented for roaming and inter-PLMN interpretation rather than pure intra-EPC handling.
- `lte-sbc-cbc` means Cell Broadcast SBc, not Session Border Controller traffic.

## Built-In 2G/3G Core and GERAN Profiles

The 2G/3G family is intentionally split by interface and troubleshooting goal
instead of collapsing everything into one generic legacy SS7 profile.

| Profile | Best used for |
|---|---|
| `2g3g-ss7-geran` | Broad legacy bundle across MAP, CAP, ISUP, BSSAP, and GERAN |
| `2g3g-gn` | Intra-PLMN Gn GTPv1 control plane |
| `2g3g-gp` | Roaming/inter-PLMN Gp GTPv1 control plane |
| `2g3g-gr` | Gr MAP signaling between SGSN and HLR |
| `2g3g-gs` | Gs paging and combined CS/PS coordination |
| `2g3g-geran` | Broader GERAN/A-interface-adjacent core-side view |
| `2g3g-dns` | Legacy/core DNS troubleshooting |
| `2g3g-map-core` | Generic MAP-core analysis beyond one interface |
| `2g3g-cap` | CAP/CAMEL service-control flows |
| `2g3g-bssap` | Focused BSSAP/BSSMAP/DTAP technical analysis |
| `2g3g-isup` | Voice/circuit-signaling call flows |
| `2g3g-sccp-mtp` | Lower-layer SCCP/MTP routing and transport issues |

Important distinctions:

- `2g3g-gn` vs `2g3g-gp`: both use GTPv1, but `2g3g-gp` is documented and heuristically framed for roaming and inter-PLMN interpretation.
- `2g3g-gr` vs `2g3g-map-core`: use `2g3g-gr` when you know the path is SGSN ↔ HLR; use `2g3g-map-core` when the MAP question spans mixed HLR/VLR/SGSN roles.
- `2g3g-geran` vs `2g3g-bssap`: use `2g3g-geran` for the broader core-side 2G signaling picture; use `2g3g-bssap` when the technical A-interface mechanics matter more than the broader context.
- `2g3g-isup` vs `2g3g-sccp-mtp`: use `2g3g-isup` for call sequence and release-cause interpretation; use `2g3g-sccp-mtp` when routing and lower-layer SS7 delivery are the real issue.

## Minimal Working Example

Start here, then add what you need:

```yaml
name: voip-sip
description: "SIP/RTP troubleshooting profile"

relevant_protocols: [sip, rtp]

top_protocol_priority:
  - sip
  - rtp
  - udp
  - ip

protocol_aliases:
  sip: [sip]
  rtp: [rtp]

full_detail_fields:
  sip:
    - sip.Method
    - sip.Status-Code
    - sip.From
    - sip.To
    - sip.Call-ID
  rtp:
    - rtp.ssrc
    - rtp.seq
    - rtp.timestamp

verbatim_protocols: []

reduced_transport_fields: [proto, src_port, dst_port, stream, anomaly, notes]

tshark:
  two_pass: false
  extra_args: []
```

Save this to `src/pcap2llm/profiles/voip-sip.yaml` and run:
```bash
pcap2llm analyze capture.pcapng --profile voip-sip
```

---

## Full Schema Reference

```yaml
name: my-profile          # required — must match the file stem
description: "..."        # required — shown in dry-run output

# Protocols counted as "relevant" in summary.json
relevant_protocols:
  - diameter
  - gtpv2

# Priority order for selecting the top-layer protocol per packet.
# First match wins. Always end with ip as the fallback.
top_protocol_priority:
  - diameter
  - gtpv2
  - dns
  - sctp
  - tcp
  - udp
  - ip

# Maps your canonical protocol name to the TShark layer key(s) to look for.
# Needed when TShark uses a different internal name.
protocol_aliases:
  diameter: [diameter]
  gtpv2: [gtpv2, gtpv2-c, gtp]
  map: [gsm_map, map]       # TShark calls it gsm_map

# Fields extracted with priority for each top protocol.
# Fields not listed here are still included via a catch-all pass
# (everything in the TShark layer except _ws.* keys).
full_detail_fields:
  diameter:
    - diameter.cmd.code
    - diameter.Result-Code
    - diameter.origin_host
    - diameter.imsi
  gtpv2:
    - gtpv2.message_type
    - gtpv2.cause

# Protocols retained with minimal transformation. Top-level protocol fields
# are kept, repeated nested protocol fields can be surfaced into flat
# protocol-prefixed keys, and _ws.* keys are stripped.
# Takes priority over full_detail_fields for the same protocol.
verbatim_protocols: []

# Optional: keep raw AVP or decoder-tree dump structures for protocols such as
# Diameter. Default false keeps output smaller and less noisy for LLM use.
keep_raw_avps: false

# TransportContext fields kept in the reduced output.
# Available: proto, src_port, dst_port, stream, sctp_stream, anomaly, notes
reduced_transport_fields:
  - proto
  - src_port
  - dst_port
  - stream
  - sctp_stream
  - anomaly
  - notes

# TShark execution settings
tshark:
  two_pass: false      # true = two-pass dissection (better reassembly for HTTP/fragmented IP)
  extra_args: []       # e.g. ["-d", "tcp.port==8805,pfcp"]

# Informational hints included in the summary (free text)
summary_heuristics:
  - Flag retransmissions and transport analysis warnings.

# Max conversation rows in inspection output (default: 25)
max_conversations: 25
```

---

## Tips

### Finding TShark Field Names

```bash
# List all fields for a dissector
tshark -G fields | grep "^F" | grep sip | awk '{print $2}' | head -30

# Inspect the raw JSON for a specific protocol
tshark -r sample.pcap -T json | python3 -m json.tool | grep -A5 '"sip"'
```

### Verbatim Protocols

By default pcap2llm applies `_flatten` (collapses single-element lists) and filters fields. `verbatim_protocols` is the escape hatch for protocols where you want near-raw dissector coverage with minimal transformation:

```yaml
verbatim_protocols:
  - gtpv2
  - pfcp
```

`full_detail_fields` for the same protocol is ignored.

Important nuance:

- `verbatim` does not magically create fields that TShark did not dissect.
- For some protocols, especially Diameter, pcap2llm may still surface nested fields into flat `diameter.*` keys for usability.
- Raw decoder dump structures such as `diameter.avp`, `diameter.avp_tree`, and related `*_tree` blocks can be suppressed with `keep_raw_avps: false` to reduce LLM noise.

Use this when:
- You are unsure which fields you need and want everything
- TShark uses nested dicts that `_flatten` would modify
- You are building a custom downstream analysis on the raw output

### Two-Pass Mode

Enable for captures with IP fragmentation or TCP reassembly (e.g. HTTP/2, fragmented GTP):

```yaml
tshark:
  two_pass: true
```

### Custom TShark Port Decoders

Force a non-standard port to be decoded as a specific protocol:

```yaml
tshark:
  extra_args:
    - "-d"
    - "tcp.port==8443,http2"
```

### CIDR Endpoint Mapping

Pair your profile with a mapping file for dynamic IP ranges:

```yaml
# mapping.yaml
nodes:
  - cidr: 192.168.10.0/24
    alias: SBC_CLUSTER
    role: sbc
```

```bash
pcap2llm analyze capture.pcapng --profile voip-sip --mapping-file mapping.yaml
```
