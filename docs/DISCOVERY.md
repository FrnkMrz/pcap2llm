# Discovery Mode

`pcap2llm discover` is the broad, cheap first run for unknown captures.

It exists for staged troubleshooting and external orchestration:

- get a first protocol and transport picture
- detect likely network domains
- propose follow-up profiles
- keep the result deterministic and machine-readable

This command does not try to replace focused profile analysis. It answers:

> Which profile family or interface profile should I run next?

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROFILE_SELECTION.md`](PROFILE_SELECTION.md)
- [`SESSIONS.md`](SESSIONS.md)
- [`WORKFLOWS.md`](WORKFLOWS.md)

## When To Use Discovery

Run `discover` when at least one of these is true:

- the capture is still unfamiliar
- the profile family is not obvious yet
- multiple domains appear mixed together
- you want a reproducible machine-readable scout artifact
- an agent, UI, or script should decide the next focused run

## `discover` vs `inspect` vs `analyze`

| Command | Best used for | Writes artifacts? | Typical next step |
|---|---|---|---|
| `inspect` | quick human overview when you already have a likely profile family | optional | tighten the filter or run `analyze` |
| `discover` | broad scout run for unknown captures and staged workflows | yes | `recommend-profiles`, then `analyze` |
| `analyze` | focused extraction for the interface you actually want to troubleshoot | yes | local review, LLM handoff, or another focused run |

In plain language:

- `inspect` helps a human orient quickly
- `discover` helps decide what focused run should happen next
- `analyze` produces the real troubleshooting artifact set

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

Recommended follow-up:

```bash
pcap2llm recommend-profiles artifacts/discover_trace_start_1_V_01.json
pcap2llm analyze trace.pcapng --profile <chosen-profile> --out ./artifacts
```

## Output Files

Discovery writes two files directly into the output directory — no subdirectory:

```text
artifacts/
  discover_trace_start_1_V_01.json
  discover_trace_start_1_V_01.md
```

The filename prefix uses the same semantic ordering as `analyze`: action,
capture name, start packet, and artifact version. This keeps all run outputs in
one flat, browsable place.

| File | Purpose |
|---|---|
| `discover_<capture>_start_<n>_V_01.json` | Machine-readable scout result for agents and scripts |
| `discover_<capture>_start_<n>_V_01.md` | Short human summary |

Both discovery outputs now begin with the same ordered metadata for easier comparison across reruns:

1. `run.action`
2. `capture.filename`
3. `capture.first_packet_number`
4. `artifact.version`

## Discovery JSON Shape

The exact payload can evolve, but the core blocks are:

```json
{
  "run": {
    "action": "discover"
  },
  "capture": {
    "filename": "trace.pcapng",
    "path": "...",
    "first_packet_number": 1,
    "first_seen": "...",
    "last_seen": "...",
    "sha256": "...",
    "packet_count": 1234
  },
  "artifact": {
    "version": "V_01"
  },
  "status": "ok",
  "mode": "discovery",
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
      {"name": "nas-5gs", "strength": "supporting"},
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
      "role": "primary",
      "reason": ["ngap present", "nas-5gs present"]
    }
  ],
  "candidate_profiles": [
    {
      "profile": "5g-n1-n2",
      "score": 9.5,
      "confidence": "high",
      "evidence_class": "protocol_strong",
      "reason": ["ngap detected", "strong indicator ngap"]
    }
  ],
  "classification_notes": [
    "family assignment remains ambiguous — DNS-only without domain-specific service markers"
  ],
  "classification_state": "ambiguous_support"
}
```

The Markdown header follows the same order:

- `Action`
- `Capture file`
- `Start packet`
- `Artifact version`

## What Discovery Looks At

- capture path, capture filename, first packet timestamp, packet count, first/last timestamps, SHA-256 when readable
- transport mix such as TCP, UDP, SCTP
- low-level capture context such as Ethernet, VLAN, PPP, or similar envelopes
- dominant signaling protocols derived from decoded counts plus strong raw-protocol hints
- a curated `relevant_protocols` view for discovery, plus the raw top-protocol inventory
- a small conversation and anomaly slice
- rule-based domain hints
- deterministic profile recommendations, including confidence / evidence-class hints for weaker host-assisted specializations

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
generic carrier protocols such as `ip`.

**Strength labels** in `dominant_signaling_protocols`:

| Label | Meaning |
|---|---|
| `strong` | Protocol appears in decoded packet counts — directly measured |
| `supporting` | Protocol inferred from raw protocol headers only — no decoded count available |

When a protocol is only recovered from raw presence (`strength: supporting`),
the `count` field is omitted entirely rather than emitting `count: 0`.
In the Markdown report, raw-signal-only entries appear with the label `[raw signal]`
to make the distinction visually clear.

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
`gtp + udp` (GTPv1 packet-core) are present.

> **Note on TShark GTPv1 naming:** TShark reports GTPv1 packets using the
> protocol name `gtp`, not `gtpv1`. Discovery recognises both spellings
> internally. When `gtp` appears without `gtpv2`, the trace is treated as
> a GTPv1-only packet-core (Gn/Gp ambiguous) and `legacy-2g3g-gprs` is
> promoted as the primary domain candidate. When `gtpv2` is also present,
> `gtp` is interpreted as LTE GTP-U (user-plane) rather than legacy Gn —
> legacy `2g3g-gn` profiles are suppressed in that case.

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
no SIP-, SDP-, or other IMS-specific indicators are present. DNS alone is not
treated as a voice indicator — it is infrastructure traffic, not signaling.
LTE / EPS profiles also stay visible as side signals in a 5G-dominant trace,
but are ranked below the primary 5G candidates unless they have their own LTE
anchor protocols such as `s1ap`, `diameter`, or `gtpv2`. In a strongly 5G SA
dominated trace with no LTE anchor signal at all, LTE profiles are further
suppressed rather than shown as near-peers of the 5G candidates.

Generic Diameter-over-SCTP traces stay biased toward LTE/EPS candidates such
as `lte-s6a` unless additional IMS-specific peer or signaling hints are
visible. DNS-only traces keep DNS-focused profiles prominent instead of
promoting SIP, SBC, or register-specific candidates too early.

### core-name-resolution: cross-generation telecom core naming

`core-name-resolution` is an evidence-driven support/infrastructure profile for
DNS-based lookup behavior that appears across all generations: 2G/3G core,
LTE/EPC, 5G core, and IMS/voice naming contexts.

It covers DNS traffic used to resolve APNs, Diameter realms, IMS domains, NF
service endpoints, and 3GPP-standard operator FQDNs. It is **not** a generic
DNS profile — it rises to the top only when actual telecom naming evidence is
detected in sampled `dns.qry.name` values and resolved peer names.

#### Strong evidence (each match = one strong hit)

| Pattern | Reason emitted |
|---|---|
| `3gppnetwork.org` | `3gppnetwork.org naming detected` |
| `.gprs` | `.gprs operator domain detected` |
| `epc.mnc` | `APN/EPC MCC/MNC naming pattern detected` |
| `ims.mnc` | `IMS MCC/MNC naming pattern detected` |
| `5gc.mnc` | `5GC MCC/MNC naming pattern detected` |
| `apn.epc` | `APN resolution naming detected` |
| `topon.` | `TOPON DNS routing prefix detected (3GPP node resolution)` |
| `mnc\d+.mcc\d+` (regex) | `MCC/MNC operator naming pattern detected` |

`topon.` is the 3GPP TS 29.303 DNS-based node-resolution prefix used for GTPv1/v2
routing in operator networks. Its presence in DNS queries is a strong indicator of
EPC or packet-core infrastructure traffic.

Two or more strong hits → full score boost and `confidence: high`.
One strong hit → medium boost and `confidence: medium`.

#### Supporting evidence (summarized, not per-hit)

IMS CSCF names (`pcscf`, `scscf`, `icscf`), MMTel, 5G NF hostnames
(`nrf.`, `amf.`, `smf.`, `udm.`, `ausf.`, `nssf.`), EPC/LTE node names
(`pgw.`, `sgw.`, `mme.`, `hss.`), base-station names (`enb.`, `gnb.`),
and generic `3gpp` context. Two or more supporting hits add a smaller bonus and emit a
summary reason when no strong hits are present.

#### Generic DNS does not strongly trigger this profile

A DNS trace with only `www.example.com` or similar generic names scores at
baseline (2.5) and does not dominate the candidate list. The score is meaningful
only when real telecom naming evidence is present.

#### Interpretive summary in reason text

When strong telecom naming evidence is detected, the first reason entry explains
the operational meaning rather than just listing pattern matches:

> `DNS trace matches telecom core naming — APN/realm/core service resolution support traffic`

Specific pattern reasons follow (e.g. `3gppnetwork.org naming detected`,
`MCC/MNC operator naming pattern detected`).

#### DNS family fan-out suppression

When `core-name-resolution` scores ≥ 4.0 and no signaling anchor is present,
family-specific `*-dns` profiles (e.g. `lte-dns`, `5g-dns`, `2g3g-dns`) are
further downranked. This reduces candidate list noise when the support-profile
explanation is already clearly the best one.

**Exception:** `volte-dns` and `vonr-dns` with a genuine IMS peer hint (resolved
P-CSCF/CSCF hostname) are NOT suppressed — the peer hint is independent evidence
that justifies their presence alongside `core-name-resolution`.

Use this profile when the DNS trace is about telecom core naming and no single
generation is clearly dominant. It is not a replacement for specific interface
profiles (`lte-s6a`, `5g-n2`, `volte-sip`, etc.) — it sits alongside them as
the natural home for naming-heavy, generation-ambiguous DNS traffic.

### DNS-only is intentionally family-ambiguous

Pure DNS traffic without accompanying control-plane signaling (no `ngap`,
`s1ap`, `diameter`, `sip`, `map`, etc.) is infrastructure or support traffic
that cannot be reliably assigned to a single network generation.

Discovery models this explicitly:
- `classification_state` is set to `"ambiguous_support"` — a structured signal for orchestrators
- All family-specific DNS profiles (`lte-dns`, `5g-dns`, `volte-dns`, `vonr-dns`, `2g3g-dns`) are gated unless a domain-specific anchor is present; `lte-dns` requires LTE evidence (`s1ap`, `diameter`, `gtpv2`), `5g-dns` requires 5G evidence (`ngap`, `nas-5gs`)
- A `classification_notes` entry reads: `"family assignment remains ambiguous — DNS-only without domain-specific service markers"`
- When telecom naming patterns are detected, `core-name-resolution` rises to the top

A family-specific DNS profile is only promoted when co-occurring evidence
warrants it: IMS peer hints allow `volte-dns`; 5G NF hostnames allow `5g-dns`.

### Host hints: supporting evidence, not proof

Resolved peer names and roles (from `--hosts-file` or `--mapping-file`) can
tighten interface guesses — for example, identifying S5/S8 vs S11 when only
generic GTP is visible — but they never replace decoded protocol evidence.

When a candidate's score depends primarily on host hints rather than protocol
counts, its `evidence_class` will read `protocol_partial_with_host_hints` or
`host_hints_only`, and a `classification_notes` entry explains why:

> `low-confidence specialization due to host hints; treat interface naming as plausible rather than fully proven`

This is an intermediate state between "no idea" and "fully decoded". The
candidate is still useful — it just needs to be read as plausible, not proven.

### Mixed-domain traces

When multiple domains score above threshold, `trace_shape` is `mixed_domain`
and `suspected_domains` carries a `role` field on each entry:

| Role | Meaning |
|---|---|
| `primary` | Dominant domain — score ≥ 0.7, OR the only domain present |
| `secondary` | Additional domain with meaningful signal — score ≥ 0.4 |
| `supporting` | Weak or side signal — score < 0.4 |

Role is only emitted when there is at least one domain entry. A single domain
always receives `primary` regardless of its score — labeling the only domain
`secondary` would be semantically broken.

When two domains both score ≥ 0.7 (co-dominant, e.g. a trace mixing MAP/TCAP/SCCP
with ngap), both receive `primary`. Run `discover` for the full candidate list.

### Legacy / SS7 profile calibration

Legacy profiles are gated against specific evidence:

- `2g3g-isup` requires explicit `isup` protocol evidence — without it the profile
  is fully suppressed regardless of MAP/TCAP/SCCP presence
- `2g3g-bssap`, `2g3g-geran`, `2g3g-gs`, and `2g3g-ss7-geran` require real
  `bssap`, `bssmap`, `dtap`, or `gsm_a` evidence — without it they are fully
  suppressed and do not appear in results at all
- `map + tcap + sccp` combinations keep `2g3g-map-core`, `2g3g-gr`, and
  `2g3g-sccp-mtp` as the primary SS7 core candidates without promoting
  BSSAP/GERAN/Gs side profiles

- `2g3g-gn` and `2g3g-gp` both require GTPv1 (`gtp` or `gtpv1`) to be present
  and are suppressed when `gtpv2` is the active control plane (that combination
  means GTP-U / LTE bearer traffic, not legacy Gn/Gp)

### Voice / IMS subprofile calibration

Within mixed IMS voice traces, Discovery separates the broad family from the
specialized subprofiles more aggressively:

- `volte-ims-core` requires `diameter` or IMS peer hints — SIP alone is insufficient
  to confirm core infrastructure role
- `volte-sip-call` rises on SDP or media-style call markers
- `volte-sip-register` rises on registrar/auth-style IMS context; without it the
  profile is strongly downranked
- `volte-sbc` rises only when peer naming or topology hints indicate an SBC boundary
- VoNR profiles (`vonr-*`) require 5G SA context (`ngap` or `nas-5gs`) beyond just
  IMS/SIP presence — in a pure SIP/SDP trace without 5G signals they stay clearly
  below their VoLTE equivalents

This keeps `sip + sdp` from flattening the entire VoLTE/VoNR profile cluster into
nearly equal candidates and prevents VoNR from falsely rising in LTE IMS traces.

### GTPv2 / EPS candidate fan-out

In a clear EPS/GTPv2 trace the candidate list is intentionally narrowed:

- `2g3g-gn` and `2g3g-gp` are fully suppressed when `gtpv2` is present
- `5g-n26` is heavily suppressed (score × 0.1) in pure EPS traces without any
  5GC indicators (`ngap`, `nas-5gs`, `http+json`) or N26-specific peer hints —
  N26 requires explicit EPC↔5GC interworking context
- EPS interface candidates (`lte-s5`, `lte-s8`, `lte-s11`, `lte-s10`) remain
  visible but stay honest about the ambiguity between them

### Transport-only SCTP / ICMP traces

When Discovery sees SCTP transport plus some ICMP but no decoded upper-layer
signaling, it now prefers notes/anomalies over a misleading legacy profile
guess. `icmp` alone is not enough to raise `2g3g-gn`; real `gtpv1` / `gtp`
evidence is still required for that direction.

### classification_state

`classification_state` is a structured top-level field designed for orchestration decisions.

| Value | Meaning |
|---|---|
| `"confident"` | Strong single-domain evidence (top domain score ≥ 0.7) |
| `"ambiguous_support"` | DNS-only or generic support traffic without family context |
| `"partial"` | Some protocol evidence but weak, gated, or host-hint-driven |
| `"mixed"` | Multiple competing domains |
| `"unknown"` | Transport-only or insufficient evidence |

An orchestrator can branch on `classification_state` before deciding whether to
call `analyze` directly, run `discover` first, or flag for human review.

### Classification notes vs. anomalies

The output separates two kinds of diagnostic messages:

- **`anomalies`** — actual network events worth investigating: transport-only
  traces, sparse Diameter, SCTP without upper-layer decode, legacy protocols
  alongside modern signaling
- **`classification_notes`** — methodological discovery limits: coarse decoded
  protocols, DNS-only ambiguity, host-hint-driven confidence, family uncertainty

An orchestrator should act on anomalies; classification notes explain the
discovery method's confidence level and are informational.

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
