# pcap2llm

`pcap2llm` converts `.pcap` and `.pcapng` network captures into structured,
privacy-controlled JSON artifacts for telecom troubleshooting.

It does **not** perform AI analysis itself. It prepares a deterministic,
LLM-ready handoff artifact from packet captures.

**Sweet spot:** focused signaling traces, filtered call flows, Diameter or GTP
problems, NGAP/NAS investigations, IMS procedures, and similar captures with a
few dozen to a few hundred relevant packets.

**Not designed for:** multi-hour rolling dumps used as-is. First narrow the
capture with `inspect`, `discover`, or a tighter `-Y` filter.

## Quick Start

Requirements:

- Python 3.11+
- `tshark` in PATH (Wireshark package)

```bash
# 1. Install
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

# 2. Get a first view without writing artifacts
pcap2llm inspect sample.pcapng --profile lte-core

# 3. If the trace is still unclear, scout it broadly
pcap2llm discover sample.pcapng

# 4. Run the focused analysis that writes artifacts
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

## Start With `inspect` Or `discover`?

Use `inspect` when you already know the likely profile family and want a fast
human overview.

Use `discover` when the capture is still unclear and you want:

- a broad protocol/domain scout pass
- deterministic candidate profiles
- machine-readable artifacts for agents, scripts, or staged workflows

Typical staged path for unknown captures:

```bash
pcap2llm discover trace.pcapng
pcap2llm recommend-profiles artifacts/discover_trace_start_1_V_01.json
pcap2llm analyze trace.pcapng --profile <chosen-profile> --out ./artifacts
```

`discover` is not the final analysis. It answers:

> What kind of capture is this, and which focused profile should I run next?

## What `analyze` Produces

Every `analyze` run writes a semantically ordered, versioned file set:

| File | Purpose |
|---|---|
| `analyze_<capture>_start_<n>_V_01_detail.json` | Primary LLM input: normalized packets, filtered fields, privacy applied |
| `analyze_<capture>_start_<n>_V_01_summary.json` | Sidecar with protocol mix, anomalies, timing, and coverage |
| `analyze_<capture>_start_<n>_V_01_summary.md` | Human-readable summary |
| `analyze_<capture>_start_<n>_V_01_flow.json` | Optional signaling flow model with lanes, events, phases, correlations, and collapse metadata (`--render-flow-svg`) |
| `analyze_<capture>_start_<n>_V_01_flow.svg` | Optional signaling sequence diagram with event hover tooltips and status coloring (`--render-flow-svg`) |
| `analyze_<capture>_start_<n>_V_01_pseudonym_mapping.json` | Only when pseudonymization is active |
| `analyze_<capture>_start_<n>_V_01_vault.json` | Only when encryption is active |

Shared metadata is surfaced consistently across `inspect`, `discover`, and
`analyze` outputs:

1. action
2. capture file
3. start packet
4. artifact version

## Picking A Profile

Start with the family that matches the traffic:

- `lte-*` for LTE / EPC
- `5g-*` for 5G SA core
- `volte-*` and `vonr-*` for voice over IMS
- `2g3g-*` for legacy 2G/3G / GERAN / SS7

If the exact interface is unknown, begin with the broader overview profile of
that family, for example `lte-core`, `5g-core`, `volte-ims-core`,
`vonr-ims-core`, or `2g3g-ss7-geran`.

Detailed profile catalogs live outside the README:

- Overview: [`docs/PROFILES.md`](docs/PROFILES.md)
- LTE / EPC: [`docs/PROFILES_LTE.md`](docs/PROFILES_LTE.md)
- 5G SA Core: [`docs/PROFILES_5G.md`](docs/PROFILES_5G.md)
- Voice / IMS: [`docs/PROFILES_VOICE.md`](docs/PROFILES_VOICE.md)
- 2G/3G / GERAN: [`docs/PROFILES_2G3G.md`](docs/PROFILES_2G3G.md)

## Privacy

Privacy is controlled separately from the analysis profile.

Common starting points:

- `internal` for local-only work
- `share` for internal sharing with subscriber pseudonymization
- `prod-safe` for stronger masking before external sharing
- `llm-telecom-safe` for external LLM handoff

Example:

```bash
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  --privacy-profile share \
  --out ./artifacts
```

Full privacy guidance: [`docs/PRIVACY_SHARING.md`](docs/PRIVACY_SHARING.md)

## Important Limits

By default `detail.json` contains the first **1,000 packets**. You can raise
the limit with `--max-packets N` or remove it with `--all-packets`.

That limit is a safety guard, not a scaling strategy:

- pass 1 still scans the entire filtered capture
- summary statistics still reflect the full filtered export
- a better `-Y` filter is usually more useful than a bigger packet limit

Practical rule:

1. run `inspect` or `discover`
2. narrow with `-Y` until the packet set is meaningful
3. then run `analyze`

Flow artifacts can be rendered during analyze and re-rendered later without
running tshark again:

```bash
pcap2llm analyze trace.pcapng --profile lte-core --render-flow-svg --out ./artifacts
pcap2llm visualize ./artifacts/analyze_trace_start_1_V_01_flow.json --width 1800
```

The flow renderer is intended for quick human orientation in focused signaling
traces. It uses resolved endpoint aliases/roles for lanes, groups adjacent
identical events when repeat collapse is enabled, and labels common telecom
messages with protocol-specific detail: Diameter result codes, GTPv2 message
names and causes, NGAP procedures, NAS-EPS/NAS-5GS message types, HTTP/2
method/path or status, and DNS query/response names, rcodes, and answer counts.
The left event gutter now shows packet number plus packet clock time
(`HH:mm:ss`), and the flow header includes the date of the first packet.
Hover text is intentionally different from the arrow label: it focuses on
packet/range, direction, protocol, timing, and correlation context instead of
repeating the visible message label. Error-ish outcomes such as Diameter result
codes >= 3000, HTTP status >= 400, GTPv2 causes >= 64, and DNS rcode failures
are highlighted in the SVG.

## Documentation Map

This README is intentionally the **entrypoint**, not the complete manual.

| Document | Role |
|---|---|
| **README.md** | First contact: what the tool is, how to start, where to go next |
| [`docs/DOCUMENTATION_MAP.md`](docs/DOCUMENTATION_MAP.md) | Complete inventory of all documentation pages and reading paths |
| [`docs/REFERENCE.md`](docs/REFERENCE.md) | Complete English command and option reference |
| [`docs/QUICKSTART_DE.md`](docs/QUICKSTART_DE.md) | German 5-minute quick start |
| [`docs/ANLEITUNG_DE.md`](docs/ANLEITUNG_DE.md) | German practical guide for day-to-day usage |
| [`docs/DISCOVERY.md`](docs/DISCOVERY.md) | Deep dive on `discover`, scoring, and scout artifacts |
| [`docs/PROFILE_SELECTION.md`](docs/PROFILE_SELECTION.md) | How `recommend-profiles` ranks candidates |
| [`docs/SESSIONS.md`](docs/SESSIONS.md) | Multi-run orchestration and session manifests |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | Protocol-specific workflows and local batch-run patterns |
| [`docs/NETWORK_ELEMENT_DETECTION.md`](docs/NETWORK_ELEMENT_DETECTION.md) | Deterministic network-element detection, mapping CSV format, and override behavior |
| [`docs/WEB_GUI.md`](docs/WEB_GUI.md) | Local Web GUI usage, profile management, dashboard, and bulk operations |
| [`docs/LLM_TROUBLESHOOTING_WORKFLOW.md`](docs/LLM_TROUBLESHOOTING_WORKFLOW.md) | PCAP -> `pcap2llm` -> external LLM workflow, including direct provider handoff |
| [`docs/LLM_MODE.md`](docs/LLM_MODE.md) | Machine-readable JSON mode for automation |
| [`docs/schema/`](docs/schema/) | Output schema reference |

## Development

```bash
pytest
ruff check .
```

## License

Apache License 2.0 - Copyright (c) 2026 Frank März
