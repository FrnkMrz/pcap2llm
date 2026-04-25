# Transport Decode Profile Plan

This plan is for analysis profiles, not privacy profiles. The goal is to make
TCP, UDP, and SCTP troubleshooting useful even when the higher-layer protocol is
unknown, malformed, encrypted, or intentionally ignored.

## Goals

- Add profile-level views for transport-layer diagnostics.
- Preserve packet-level transport evidence with minimal interpretation loss.
- Make SCTP troubleshooting first-class, including stream IDs, chunks, PPIDs,
  associations, retransmission signals, heartbeats, SACK behavior, and ABORT /
  SHUTDOWN paths.
- Keep the existing telecom profiles focused on service protocols, while adding
  explicit transport decode profiles for lower-layer investigations.

## Available Profiles

| Profile | Focus |
|---|---|
| `transport-core` | TCP, UDP, SCTP, IP, ICMP overview for mixed captures |
| `transport-sctp` | SCTP association and chunk-level analysis |
| `transport-tcp` | TCP streams, retransmissions, resets, handshakes, TLS adjacency |
| `transport-udp` | UDP conversations, DNS/NTP/RTP-adjacent traffic, fragmentation hints |

## Profile Shape

Each profile should use `verbatim_protocols` for the transport protocol under
inspection so TShark fields survive reduction with minimal flattening:

```yaml
name: transport-sctp
description: SCTP transport decode profile for association, stream, chunk, and retransmission analysis.
relevant_protocols:
  - sctp
  - ip
top_protocol_priority:
  - sctp
  - ip
protocol_aliases:
  sctp: [sctp]
  ip: [ip, ipv6]
verbatim_protocols:
  - sctp
reduced_transport_fields:
  - proto
  - src_port
  - dst_port
  - stream
  - sctp_stream
  - anomaly
  - notes
summary_heuristics:
  - Highlight SCTP retransmissions, duplicate TSNs, gaps, SACK-only bursts, ABORT, and SHUTDOWN.
```

## Implementation Steps

1. Add the four profile YAML files under `src/pcap2llm/profiles/`. Done.
2. Extend profile tests so each transport profile loads and has expected
   protocol aliases, priorities, and verbatim settings.
3. Extend index inspection to surface transport-specific counters:
   retransmissions, resets, SCTP chunk types, SACK/ABORT/SHUTDOWN counts, and
   stream IDs where available.
4. Add summary heuristics so `summary.json` calls out transport symptoms before
   the user has to inspect `detail.json`.
5. Add flow-model support for transport-only diagrams:
   TCP handshake/reset markers, SCTP INIT/COOKIE/SACK/ABORT/SHUTDOWN, and UDP
   request/response pair hints where ports or DNS transaction IDs allow it.
6. Document usage in `docs/PROFILES.md`, `docs/REFERENCE.md`, and the German
   guide.

## Open Design Choice

SCTP should probably be the first implementation target. It has the clearest
telecom value and benefits most from verbatim decode because upper layers such
as S1AP, NGAP, M3UA, or Diameter-over-SCTP can hide transport failure signals
when the user starts from an application profile.
