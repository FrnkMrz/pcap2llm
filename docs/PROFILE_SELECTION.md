# Profile Selection

`pcap2llm recommend-profiles` turns discovery evidence into deterministic,
explainable profile suggestions.

It is meant for:

- external agents
- scripts
- staged operator workflows
- UI layers that want a shortlist instead of one hidden decision

It is not an embedded AI feature.

## Basic Usage

From a prior discovery run:

```bash
pcap2llm recommend-profiles ./discovery/discovery.json
```

Directly from a capture:

```bash
pcap2llm recommend-profiles trace.pcapng
```

If you pass a capture, `pcap2llm` first performs an internal discovery pass and
then emits the recommendation result.

## Output Shape

```json
{
  "status": "ok",
  "recommended_profiles": [
    {
      "profile": "lte-s11",
      "score": 8.5,
      "reason": ["gtpv2 detected", "strong indicator gtpv2"],
      "selector_metadata": {
        "family": "lte",
        "domain": "eps",
        "interface": "s11"
      }
    }
  ],
  "suppressed_profiles": [
    {
      "profile": "volte-sip",
      "score": 0.0,
      "reason": ["no matching protocol evidence"]
    }
  ],
  "suspected_domains": [
    {
      "domain": "lte-eps",
      "score": 0.85,
      "reason": ["diameter present", "gtpv2 present"]
    }
  ]
}
```

## How Scoring Works

The current logic is rule-based and testable. It uses:

- observed protocol counts
- transport counts
- profile `relevant_protocols`
- profile `top_protocol_priority`
- optional `selector_metadata`

Typical positive signals:

- trigger protocol present
- strong indicator present
- transport family matches the profile
- domain-specific hints, such as SIP for VoLTE or NGAP plus NAS-5GS for 5GC

The result is intended as a shortlist, not as a forced final answer.

## Selector Metadata

Profiles can expose structured recommendation hints:

```yaml
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
```

Current fallback behavior:

- if `selector_metadata` exists, it is used directly
- if it is missing, `pcap2llm` infers a basic selector view from the profile name and protocol lists

This keeps old profiles recommendable while allowing newer profiles to become
more explicit over time.

## Practical Use

Good pattern:

1. Run `discover`
2. Call `recommend-profiles`
3. Pick one or more focused profile runs
4. Record that choice in a session manifest when you need full traceability

For multi-run orchestration and manifest layout, see
[`docs/SESSIONS.md`](SESSIONS.md).
