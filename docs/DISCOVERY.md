# Discovery Mode

`pcap2llm discover` is the broad, cheap first run for unknown captures.

It exists for staged troubleshooting and external orchestration:

- get a first protocol and transport picture
- detect likely network domains
- propose follow-up profiles
- keep the result deterministic and machine-readable

This command does not try to replace focused profile analysis. It answers:

> Which profile family or interface profile should I run next?

## Basic Usage

```bash
pcap2llm discover trace.pcapng
```

Outputs land in `artifacts/` by default — the same directory used by `analyze`.

Optional narrowing:

```bash
pcap2llm discover trace.pcapng \
  -Y "ngap || nas-5gs || http2"
```

Custom output directory:

```bash
pcap2llm discover trace.pcapng --out ./my-artifacts
```

Preview only:

```bash
pcap2llm discover trace.pcapng --dry-run
```

## Output Files

Discovery writes two files directly into the output directory — no subdirectory:

```text
artifacts/
  20260410_173000_discovery.json
  20260410_173000_discovery.md
```

The timestamp prefix comes from the first packet in the capture, using the same
logic as `analyze` artifacts. This keeps all run outputs in one flat, browsable
place.

| File | Purpose |
|---|---|
| `YYYYMMDD_HHMMSS_discovery.json` | Machine-readable scout result for agents and scripts |
| `YYYYMMDD_HHMMSS_discovery.md` | Short human summary |

## Discovery JSON Shape

The exact payload can evolve, but the core blocks are:

```json
{
  "status": "ok",
  "mode": "discovery",
  "capture": {
    "path": "...",
    "sha256": "...",
    "packet_count": 1234,
    "first_seen": "...",
    "last_seen": "..."
  },
  "transport_summary": {
    "tcp": 20,
    "udp": 50,
    "sctp": 200
  },
  "capture_context": {
    "link_or_envelope_protocols": ["eth", "vlan", "ethertype"],
    "transport_support_protocols": ["sctp"]
  },
  "protocol_summary": {
    "dominant_signaling_protocols": [
      {"name": "ngap", "count": 120, "strength": "strong"},
      {"name": "nas-5gs", "strength": "strong"},
      {"name": "sctp", "count": 200, "strength": "supporting"}
    ],
    "top_protocols": [
      {"name": "ngap", "count": 120},
      {"name": "nas-5gs", "count": 90}
    ],
    "relevant_protocols": ["ngap", "nas-5gs"],
    "raw_protocols": ["eth", "ip", "sctp", "ngap", "nas-5gs"]
  },
  "suspected_domains": [
    {
      "domain": "5g-sa-core",
      "score": 0.85,
      "reason": ["ngap present", "nas-5gs present"]
    }
  ],
  "candidate_profiles": [
    {
      "profile": "5g-n1-n2",
      "score": 9.5,
      "reason": ["ngap detected", "strong indicator ngap"]
    }
  ]
}
```

## What Discovery Looks At

- capture path, packet count, first/last timestamps, SHA-256 when readable
- transport mix such as TCP, UDP, SCTP
- low-level capture context such as Ethernet, VLAN, PPP, or similar envelopes
- dominant signaling protocols derived from decoded counts plus strong raw-protocol hints
- a curated `relevant_protocols` view for discovery, plus the raw top-protocol inventory
- a small conversation and anomaly slice
- rule-based domain hints
- deterministic profile recommendations

## What Discovery Does Not Do

- no hidden AI reasoning
- no automatic multi-run branching
- no deep specialized protocol extraction
- no final troubleshooting conclusion

Use a focused `analyze --profile ...` run after discovery confirms the likely
interface.

## How Scoring Works

Discovery uses two complementary scoring mechanisms.

### Combo-based domain detection

`suspected_domains` is produced by matching protocol co-occurrence patterns against
a ranked set of combo rules. For example:

- `ngap + nas-5gs + sctp` → `5g-sa-core` with high confidence
- `s1ap + nas-eps + sctp` → `lte-eps` with high confidence
- `diameter + sctp`       → `lte-eps` (Diameter over SCTP)
- `sip + sdp`             → `ims-voice` (active call flow)
- `map + tcap + sccp`     → `legacy-2g3g` (SS7/MAP core)

More specific combos win over less specific ones for the same domain.

Discovery does not rely on `top_protocols` alone. When the decoded top protocol
view is too flat, strong domain hints can still be recovered from
`raw_protocols`, especially for combinations such as `ngap + nas-5gs + sctp`
or `s1ap + nas-eps + sctp`.

The discovery payload also exposes `dominant_signaling_protocols` so humans and
agents can immediately see the primary signaling stack without confusing it with
generic carrier protocols such as `ip`. If a protocol is only recovered from
raw presence and there is no trustworthy decoded packet count, discovery omits
the `count` field instead of emitting misleading `count: 0`.

Low-level link, envelope, and early Layer-3 protocols such as `eth`,
`ethertype`, `vlan`, `ipcp`, or `pap` are intentionally kept out of
`dominant_signaling_protocols`. They remain available under `capture_context`
as trace context, but they do not drive domain scoring or profile ranking.

`top_protocols` remains the raw count-oriented view. Use it as a technical
packet summary, not as the primary fachliche interpretation. The curated
`relevant_protocols` and `dominant_signaling_protocols` blocks are the better
starting points for orchestration.

### Frequency weighting

A protocol that appears in very few packets contributes much less to the score.
The dampening tiers are:

| Relative frequency | Score multiplier |
|---|---|
| ≥ 5% of packets  | 1.0 (full weight) |
| 1% – 5%          | 0.7               |
| 0.5% – 1%        | 0.4               |
| < 0.5%           | 0.2               |

This prevents 3 stray DTAP frames in a 5G trace from triggering a `legacy-2g3g`
domain result.

Legacy signals also need partner protocols. A tiny `dtap` residue on its own is
treated as a side signal; discovery only promotes 2G/3G domains when partner
combinations such as `bssap + dtap + sccp`, `map + tcap + sccp`, or
`gtpv1 + udp` are present.

### Transport protocols alone do not drive recommendations

`ip`, `ipv6`, `tcp`, `udp`, `sctp`, `eth`, `frame`, and `data` are treated as
transport carriers. They never independently generate domain or profile scores.
They may add a small bonus only when at least one domain-specific signal is
already present in the same profile's relevant protocol list.

### Profile ranking

Candidate profiles are scored by summing frequency-dampened weights for their
strong indicators, trigger protocols, and weak indicators — all excluding
transport protocols. The profile with the highest domain-specific signal
score ranks first, then receives an extra bonus when it aligns with the top
`suspected_domains` hypothesis.

Hybrid voice profiles such as VoNR candidates are intentionally downranked when
no SIP-, SDP-, DNS-, or other IMS-specific indicators are present. LTE / EPS
profiles also stay visible as side signals in a 5G-dominant trace, but are
ranked below the primary 5G candidates unless they have their own LTE anchor
protocols such as `s1ap`, `diameter`, or `gtpv2`.

Generic Diameter-over-SCTP traces now stay biased toward LTE/EPS candidates
such as `lte-s6a` unless additional IMS-specific peer or signaling hints are
visible. DNS-only traces likewise keep DNS-focused profiles prominent instead
of promoting SIP, SBC, or register-specific candidates too early.

Host-resolution data is used only as a supporting signal. Resolved peer names
and roles may tighten interface guesses such as S5/S8 vs S11 or add context to
Diameter and SBI ranking, but they never replace decoded protocol evidence.

## Recommended Flow

```bash
# Step 1: discover what is in the capture
pcap2llm discover trace.pcapng

# Step 2: run focused analysis based on discovery result
pcap2llm analyze trace.pcapng --profile 5g-n2 --out ./artifacts
```

The discovery JSON is also accepted directly by `recommend-profiles`:

```bash
pcap2llm recommend-profiles artifacts/20260410_173000_discovery.json
```

For structured multi-run execution, continue with
[`docs/SESSIONS.md`](SESSIONS.md).
