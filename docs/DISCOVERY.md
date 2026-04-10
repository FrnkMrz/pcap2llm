# Discovery Mode

`pcap2llm discover` is the broad, cheap scout pass for unknown captures.

It exists for staged troubleshooting and external orchestration:

- get a first protocol and transport picture
- detect likely network domains
- propose follow-up profiles
- keep the result deterministic and machine-readable

This command does not try to replace focused profile analysis. It answers:

> Which profile family or interface profile should I run next?

## Basic Usage

```bash
pcap2llm discover trace.pcapng --out ./discovery
```

Optional narrowing:

```bash
pcap2llm discover trace.pcapng \
  -Y "ngap || nas-5gs || http2" \
  --out ./discovery
```

Preview only:

```bash
pcap2llm discover trace.pcapng --dry-run
```

## Output Files

Discovery writes two files:

| File | Purpose |
|---|---|
| `discovery.json` | Machine-readable scout result for agents and scripts |
| `discovery.md` | Short human summary |

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
  "protocol_summary": {
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
- top protocols and raw protocol inventory
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

### Transport protocols alone do not drive recommendations

`ip`, `ipv6`, `tcp`, `udp`, `sctp`, `eth`, `frame`, and `data` are treated as
transport carriers. They never independently generate domain or profile scores.
They may add a small bonus only when at least one domain-specific signal is
already present in the same profile's relevant protocol list.

### Profile ranking

Candidate profiles are scored by summing frequency-dampened weights for their
strong indicators, trigger protocols, and weak indicators — all excluding
transport protocols. The profile with the highest domain-specific signal
score ranks first.

## Recommended Flow

```bash
pcap2llm discover trace.pcapng --out ./session/discovery
pcap2llm recommend-profiles ./session/discovery/discovery.json
pcap2llm analyze trace.pcapng --profile 5g-n11 --out ./artifacts
```

For structured multi-run execution, continue with
[`docs/SESSIONS.md`](SESSIONS.md).
