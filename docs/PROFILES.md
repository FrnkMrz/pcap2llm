# Custom Profile Creation Guide

Profiles are YAML files that tell pcap2llm which protocols to extract, which fields to keep, and what privacy defaults to apply. You can create a custom profile without changing any Python code.

## Profile File Location

Place your profile YAML anywhere and reference it by its full path, **or** drop it into `src/pcap2llm/profiles/` to make it available by name:

```bash
# By name (must be in src/pcap2llm/profiles/)
pcap2llm analyze capture.pcapng --profile my-profile

# By path — not yet supported; copy to the profiles directory
```

> **Note**: Currently only profiles inside the package's `profiles/` directory are loadable by name. This is a known limitation.

## Profile Schema

```yaml
name: my-profile                        # must match file stem
description: "Short description"

# Protocols to flag as 'relevant' in the summary
relevant_protocols:
  - diameter
  - gtpv2

# Priority order for picking the top-layer protocol per packet
# The first match wins
top_protocol_priority:
  - diameter
  - gtpv2
  - dns
  - sctp
  - tcp
  - udp
  - ip

# Maps canonical protocol names to the TShark layer key(s) to look for
protocol_aliases:
  diameter: [diameter]
  gtpv2: [gtpv2, gtpv2-c, gtp]
  dns: [dns]

# Fields to extract verbatim for each top protocol
# Any field present in the TShark layer but not listed here is still
# included via the catch-all pass (unless it starts with "_ws.")
full_detail_fields:
  diameter:
    - diameter.cmd.code
    - diameter.Result-Code
    - diameter.origin_host
    - diameter.imsi
  gtpv2:
    - gtpv2.message_type
    - gtpv2.cause
    - gtpv2.imsi
  dns:
    - dns.qry.name
    - dns.a

# TransportContext fields to keep in the reduced output
# Available fields: proto, src_port, dst_port, stream, sctp_stream, anomaly, notes
reduced_transport_fields:
  - proto
  - src_port
  - dst_port
  - stream
  - sctp_stream
  - anomaly
  - notes

# Default privacy mode for each of the 13 data classes
# Modes: keep | mask | pseudonymize | encrypt | remove
default_privacy_modes:
  ip: keep
  hostname: keep
  subscriber_id: pseudonymize
  msisdn: pseudonymize
  imsi: pseudonymize
  imei: mask
  email: mask
  distinguished_name: pseudonymize
  token: remove
  uri: mask
  apn_dnn: keep
  diameter_identity: pseudonymize
  payload_text: mask

# TShark execution hints
tshark:
  two_pass: false        # enable two-pass dissection for better reassembly
  extra_args: []         # additional tshark arguments, e.g. ["-d", "tcp.port==8805,pfcp"]

# Free-text hints used in summary_heuristics (informational only)
summary_heuristics:
  - Flag retransmissions and transport analysis warnings.

# Maximum conversation rows in the inspection result (default: 25)
max_conversations: 50
```

## Step-by-Step: Minimal Working Profile

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

reduced_transport_fields: [proto, src_port, dst_port, stream, anomaly, notes]

default_privacy_modes:
  ip: keep
  hostname: keep
  subscriber_id: pseudonymize
  msisdn: pseudonymize
  imsi: pseudonymize
  imei: mask
  email: mask
  distinguished_name: pseudonymize
  token: remove
  uri: mask
  apn_dnn: keep
  diameter_identity: pseudonymize
  payload_text: mask

tshark:
  two_pass: false
  extra_args: []
```

Save this to `src/pcap2llm/profiles/voip-sip.yaml` and use it with `--profile voip-sip`.

## Tips

### Finding TShark Field Names

```bash
# List all fields for a dissector
tshark -G fields | grep "^F" | grep sip | awk '{print $2}' | head -30

# Capture to file and inspect JSON
tshark -r sample.pcap -T json | python3 -m json.tool | grep -A2 '"sip"'
```

### Protocol Aliases

If TShark uses a different internal layer name than your canonical protocol name, add an alias:

```yaml
protocol_aliases:
  map: [gsm_map, map]       # TShark calls it "gsm_map", you call it "map"
  nas-eps: [nas-eps, nas_eps]
```

### Two-Pass Mode

Enable `two_pass: true` for captures where TShark needs to read the file twice for proper reassembly (e.g. fragmented IP, TCP reassembly for HTTP):

```yaml
tshark:
  two_pass: true
```

### Custom TShark Decoders

Force a port to be decoded as a specific protocol:

```yaml
tshark:
  extra_args:
    - "-d"
    - "tcp.port==8443,http"
```

### CIDR Endpoint Mapping

When using custom profiles with dynamic IP ranges, pair them with a CIDR mapping file:

```yaml
# mapping.yaml
nodes:
  - cidr: 192.168.10.0/24
    alias: SBC_CLUSTER
    role: sbc
    site: DataCenter1
```

```bash
pcap2llm analyze capture.pcap --profile voip-sip --mapping-file mapping.yaml
```
