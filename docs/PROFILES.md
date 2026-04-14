# Analysis Profiles

Profiles are YAML files that tell `pcap2llm` which protocols to extract, which
fields to keep, and how to run TShark. This page is the entry point for
built-in profile selection and custom profile authoring.

> Profiles control protocol analysis only. Privacy settings are separate — use
> `--privacy-profile` on the command line or in your config file.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`WORKFLOWS.md`](WORKFLOWS.md)
- [`PROFILE_SELECTION.md`](PROFILE_SELECTION.md)
- [`REFERENCE.md`](REFERENCE.md)

## Choose A Built-In Profile Family

Use the family guide that matches the network domain you are troubleshooting:

| Family | Covers | Guide |
|---|---|---|
| LTE / EPC | EPC overview, S1, S6a, S11, S10, SGs, S5/S8, DNS, Cell Broadcast SBc | [`PROFILES_LTE.md`](PROFILES_LTE.md) |
| 5G SA Core | 5GC overview, N1/N2, SBI, UDM/AUSF/UDR, policy, charging, DNS, public warning | [`PROFILES_5G.md`](PROFILES_5G.md) |
| VoLTE / VoNR / IMS | SIP, Diameter, IMS DNS, Session Border Controller, 5GS voice state, auth/policy SBI | [`PROFILES_VOICE.md`](PROFILES_VOICE.md) |
| 2G/3G Core / GERAN | Gn/Gp, Gr, Gs, GERAN, MAP, CAP, ISUP, SCCP/MTP, legacy DNS | [`PROFILES_2G3G.md`](PROFILES_2G3G.md) |

Quick rule:

- Start with the broad family overview profile if the failing interface is still unclear.
- Move to the narrower interface profile as soon as the real signaling path is known.
- Prefer the voice family over generic SIP-like thinking when the problem is really IMS voice service.

## Where to Put a Custom Profile

Drop the YAML file into `src/pcap2llm/profiles/` and reference it by its
filename stem:

```bash
# File: src/pcap2llm/profiles/voip-sip.yaml
pcap2llm analyze capture.pcapng --profile voip-sip
```

The loader accepts both:

```bash
pcap2llm analyze capture.pcapng --profile voip-sip
pcap2llm analyze capture.pcapng --profile voip-sip.yaml
```

## Minimal Working Example

Start here, then add only what you need:

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

# Optional: machine-readable hints for deterministic profile recommendation
selector_metadata:
  family: lte
  domain: eps
  interface: s11
  triggers:
    protocols: [gtpv2, udp]
  strong_indicators: [gtpv2]
  weak_indicators: [dns]
  use_when: [session management, bearer control]
  avoid_when: [pure sip, pure ss7]
  cost_hint: medium
  output_focus: control_plane

# Informational hints included in the summary (free text)
summary_heuristics:
  - Flag retransmissions and transport analysis warnings.

# Max conversation rows in inspection output (default: 25)
max_conversations: 25
```

## Tips

### Finding TShark Field Names

```bash
# List all fields for a dissector
tshark -G fields | grep "^F" | grep sip | awk '{print $2}' | head -30

# Inspect the raw JSON for a specific protocol
tshark -r sample.pcap -T json | python3 -m json.tool | grep -A5 '"sip"'
```

### Verbatim Protocols

By default `pcap2llm` applies `_flatten` and filters fields. `verbatim_protocols`
is the escape hatch for protocols where you want near-raw dissector coverage
with minimal transformation:

```yaml
verbatim_protocols:
  - gtpv2
  - pfcp
```

`full_detail_fields` for the same protocol is ignored.

Important nuance:

- `verbatim` does not magically create fields that TShark did not dissect.
- For some protocols, especially Diameter, `pcap2llm` may still surface nested fields into flat `diameter.*` keys for usability.
- Raw decoder dump structures such as `diameter.avp`, `diameter.avp_tree`, and related `*_tree` blocks can be suppressed with `keep_raw_avps: false` to reduce LLM noise.

Use this when:

- You are unsure which fields you need and want everything
- TShark uses nested dicts that `_flatten` would modify
- You are building a custom downstream analysis on the raw output

### Runtime CLI Override

You can adjust `verbatim_protocols` for a single run without editing the
profile YAML:

```bash
# Add one protocol to verbatim for this run
pcap2llm analyze trace.pcap --profile lte-s11 --verbatim-protocol gtpv2

# Temporarily disable a profile default
pcap2llm analyze trace.pcap --profile lte-s6a --no-verbatim-protocol diameter

# Combine add/remove overlays; removal wins if both mention the same protocol
pcap2llm analyze trace.pcap --profile lte-s6a \
  --verbatim-protocol gtpv2 \
  --no-verbatim-protocol diameter
```

Effective behavior:

1. Load `verbatim_protocols` from the profile
2. Add every `--verbatim-protocol`
3. Remove every `--no-verbatim-protocol`
4. Use the resulting set only for that run

Important:

- This does not mutate the profile YAML.
- This does not create fields that TShark did not dissect.
- This does not replace `--two-pass`, which affects reassembly and dissection quality.
- This does not replace decoder overrides such as `--tshark-arg "-d" --tshark-arg "tcp.port==8443,http2"`.

### Selector Metadata

`selector_metadata` is optional, but recommended for profiles that should be
easy to discover from `pcap2llm recommend-profiles`.

Use it to describe when the profile is a good fit in a deterministic,
machine-readable way:

```yaml
selector_metadata:
  family: 5g
  domain: 5g-sa-core
  interface: n11
  triggers:
    protocols: [http2, json]
  strong_indicators: [pfcp]
  weak_indicators: [dns]
  use_when:
    - session management
    - smf troubleshooting
  avoid_when:
    - pure ngap
    - pure sip
  cost_hint: medium
  output_focus: control_plane
```

Current behavior:

- if `selector_metadata` is present, recommendation uses it directly
- if it is missing, `pcap2llm` falls back to deterministic inference from the profile name, relevant protocols, and top-priority protocols
- recommendation remains rule-based and explainable; there is no hidden AI scoring

### Two-Pass Mode

Enable for captures with IP fragmentation or TCP reassembly:

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
nodes:
  - cidr: 192.168.10.0/24
    alias: SBC_CLUSTER
    role: sbc
```

```bash
pcap2llm analyze capture.pcapng --profile voip-sip --mapping-file mapping.yaml
```
