# Custom Analysis Profiles

Profiles are YAML files that tell pcap2llm which protocols to extract, which fields to keep, and how to run TShark. You can create a custom profile without changing any Python code.

> **Note:** Profiles control protocol analysis only. Privacy settings are separate — use `--privacy-profile` on the command line or in your config file.

## Where to Put a Profile

Drop the YAML file into `src/pcap2llm/profiles/` and reference it by its filename stem:

```bash
# File: src/pcap2llm/profiles/voip-sip.yaml
pcap2llm analyze capture.pcapng --profile voip-sip
```

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

# Protocols passed through completely without any field selection or
# _flatten transformation. Only _ws.* keys are stripped.
# Takes priority over full_detail_fields for the same protocol.
# Use when you want every TShark field exactly as dissected.
verbatim_protocols: []

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

By default pcap2llm applies `_flatten` (collapses single-element lists) and filters fields. To get a protocol's layer exactly as TShark dissects it:

```yaml
verbatim_protocols:
  - gtpv2
  - pfcp
```

The complete layer dict goes into `message.fields` as-is. `full_detail_fields` for the same protocol is ignored.

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
