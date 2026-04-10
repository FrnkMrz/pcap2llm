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

## Recommended Flow

```bash
pcap2llm discover trace.pcapng --out ./session/discovery
pcap2llm recommend-profiles ./session/discovery/discovery.json
pcap2llm analyze trace.pcapng --profile 5g-n11 --out ./artifacts
```

For structured multi-run execution, continue with
[`docs/SESSIONS.md`](SESSIONS.md).
