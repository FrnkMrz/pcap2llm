# pcap2llm - Complete Reference

This is the authoritative English reference for `pcap2llm` commands, options,
artifacts, privacy controls, automation features, and advanced workflows.

Use this file when you need exact syntax, option names, or the technical shape
of outputs.

Related docs:

- [`../README.md`](../README.md) for the entrypoint and document map
- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md) for the full inventory of all documentation pages
- [`QUICKSTART_DE.md`](QUICKSTART_DE.md) for a short German quick start
- [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md) for a German practical guide

## What Is This Tool?

`pcap2llm` reads `.pcap` and `.pcapng` files, normalizes packets, protects sensitive data, and writes structured JSON artifacts. The primary output artifact (`detail.json`) is designed to be handed directly to an LLM as input — you can paste it into a prompt or load it via API.

The tool does **no AI analysis itself**. It formats and prepares. The LLM step is yours.

**Sweet spot:** A failed attach, a Diameter error, a GTPv2 session problem, a call flow with a few dozen to a few hundred signaling messages. Captures of seconds to a few minutes, filtered to relevant traffic.

**Not designed for:** Multi-hour rolling captures with tens of thousands of packets. The resulting `detail.json` would be too large for any LLM context window. When in doubt, use `pcap2llm inspect` first to understand the capture, then narrow with `-Y` before running `analyze`.

---

## Requirements and Installation

**Requirements:**
- Python 3.11 or newer
- `tshark` in PATH (Wireshark package)

```bash
# Verify
python3 --version
tshark -v
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

**Windows (PowerShell):**
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

**Behind a corporate proxy:**
```powershell
$env:HTTP_PROXY="http://proxy.example.com:8080"
$env:HTTPS_PROXY="http://proxy.example.com:8080"
python -m pip install --proxy http://proxy.example.com:8080 -e .[dev]
```

If `pip` fails with messages such as `getaddrinfo failed` or `Could not find a version that satisfies the requirement setuptools>=69`, the usual cause is missing proxy configuration rather than a missing `setuptools` release.

**With encryption support:**
```bash
pip install -e .[dev,encrypt]
```

---

## Command Overview

`pcap2llm` has four practical layers of surface area:

- everyday one-shot commands: `init-config`, `inspect`, `analyze`, `visualize`
- staged selection/orchestration helpers: `discover`, `recommend-profiles`
- structured multi-run helpers: `session start`, `session run-discovery`, `session run-profile`, `session finalize`
- direct external LLM handoff commands: `ask-chatgpt`, `ask-claude`, `ask-gemini`

For staged automation guidance, see [`docs/DISCOVERY.md`](DISCOVERY.md),
[`docs/PROFILE_SELECTION.md`](PROFILE_SELECTION.md), and
[`docs/SESSIONS.md`](SESSIONS.md).

For the documented PCAP -> `pcap2llm` -> external LLM sharing flow, see [`docs/LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md).

## Core Commands

### `init-config` — Create a configuration file

```bash
pcap2llm init-config
```

Writes `pcap2llm.config.yaml` to the current directory. Use this to persist defaults (profile, privacy, mapping, display filter) so you do not have to repeat them on the command line every time.

```bash
pcap2llm init-config my-project.yaml   # custom filename
pcap2llm init-config --force           # overwrite existing file
```

### `inspect` — Overview without writing artifacts

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Shows: packet count, detected protocols, transport distribution, conversations, anomalies. Writes no output files (unless `--out` is given). Use this as a first step to assess an unknown capture before committing to a full `analyze` run.

When you request JSON or Markdown output, inspect now includes explicit ordered metadata:

- `run.action`
- `capture.filename`
- `capture.first_packet_number`
- `artifact.version`

The Markdown header shows them in exactly that order. Inspect uses `V_01` as the explicit standalone report version.

In inspect JSON, `run`, `capture`, and `artifact` are the canonical top-level metadata blocks. `capture` carries the capture path, packet count, first packet number, and first/last seen timestamps. `metadata` is reserved for inspect-specific context such as display filters, protocol collections, DNS query samples, and hosts/mapping resolution flags.

Candidate `confidence` is intended as match confidence, not just raw protocol presence. Inspect may therefore mark downranked fallback candidates with `confidence: low` and `evidence_class: downranked_protocol_match` when strong generic protocol overlap exists but profile-specific context is missing.

```bash
# With display filter
pcap2llm inspect sample.pcapng --profile lte-core -Y "diameter || gtpv2"

# Write result to file
pcap2llm inspect sample.pcapng --profile lte-core --out inspect.json

# Print planned tshark command only
pcap2llm inspect sample.pcapng --profile lte-core --dry-run
```

**All options:**
```
--profile             Protocol profile (default: lte-core)
-Y / --display-filter TShark display filter
--config              YAML config file
--out                 Write JSON result to file instead of stdout
--format              Output format: json | markdown
--dry-run             Print planned tshark command, do not run it
--two-pass            Override two-pass dissection mode
--tshark-path         Path to tshark executable
--tshark-arg          Extra tshark argument (repeatable)
```

### `analyze` — Full pipeline, write artifacts

```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

Runs the complete pipeline and writes the output file set.

`summary.json`, `detail.json`, and `summary.md` now all expose the same ordered run metadata for fast comparison across reruns:

- `run.action`
- `capture.filename`
- `capture.first_packet_number`
- `artifact.version`

For bounded analyze runs, the JSON artifacts also include `selection.start_packet_number` and `selection.end_packet_number` so the detail window is explicit.

**All options:**
```
Profile & filtering:
  --profile               Protocol profile (default: lte-core)
  --privacy-profile       Privacy profile: internal | share | lab | prod-safe | llm-telecom-safe | <path>
  -Y / --display-filter   TShark display filter
  --config                YAML config file

Output control:
  --out                   Output directory (default: artifacts)
  --max-packets           Max packets in detail.json (default: 1000)
  --all-packets           Include all packets, overrides --max-packets
  --fail-on-truncation    Exit with error if detail.json would be truncated
  --max-capture-size-mb   Reject captures larger than N MiB (default: 250, 0=off)
  --oversize-factor       Reject if exported packets exceed max-packets by this factor (default: 10, 0=off)
  --dry-run               Print plan only, do not run tshark
  --llm-mode              Output strict JSON for agent/automation use
  --verbatim-protocol     Add a protocol to verbatim preservation for this run
  --no-verbatim-protocol  Remove a protocol from verbatim preservation for this run
  --render-flow-svg       Write additional flow.json and flow.svg artifacts
  --flow-title            Optional title for generated flow artifacts
  --flow-max-events       Limit rendered flow events (default: 120, 0=unlimited)
  --flow-svg-width        SVG width for flow rendering (default: 1600)
  --collapse-repeats / --no-collapse-repeats
                          Collapse adjacent identical flow events into xN markers

Endpoint resolution:
  --hosts-file            Wireshark-style hosts file
  --mapping-file          YAML/JSON alias mapping (supports CIDR)

Per-class privacy overrides:
  --ip-mode               IP addresses
  --hostname-mode         Hostnames
  --subscriber-id-mode    Generic subscriber IDs
  --msisdn-mode           MSISDN
  --imsi-mode             IMSI
  --imei-mode             IMEI
  --email-mode            Email addresses
  --dn-mode               Distinguished names
  --token-mode            Tokens / credentials
  --uri-mode              URIs
  --apn-dnn-mode          APN / DNN
  --diameter-identity-mode  Diameter identities
  --payload-text-mode     Payload text
                          Values: keep | mask | pseudonymize | encrypt | remove

TShark:
  --two-pass              Override two-pass dissection mode
  --tshark-path           Path to tshark executable
  --tshark-arg            Extra tshark argument (repeatable)
```

#### Optional flow artifacts

`--render-flow-svg` adds two sidecars to the normal `analyze` output set:

- `..._flow.json`: machine-readable flow model with endpoint lanes, events,
  protocol labels, phase blocks, request/response correlation, rendered/truncated
  event counts, and warnings.
- `..._flow.svg`: human-readable sequence diagram generated from that model.

The renderer uses endpoint aliases, IPs, hostnames, and roles to build lanes,
then orders common telecom roles by profile family (for example UE -> eNB/MME
for LTE, UE -> gNB/AMF/SMF for 5G, and CSCF-oriented ordering for IMS).
Adjacent identical events are collapsed by default and keep
`repeat_count`, `first_packet_no`, `last_packet_no`, and relative-time metadata.

Labels are protocol-aware when the extracted fields are available:

- Diameter command names plus `Result-Code` on answers
- GTPv2 message names plus response cause values; causes >= 64 are errors
- NGAP procedure names and NAS-EPS/NAS-5GS message names
- HTTP/2 request method/path or response status
- DNS query type/name, response rcode, answer count, and `dns.id` correlation

The SVG includes browser hover tooltips on event rows, with a wider transparent
hit target around each arrow plus an in-SVG tooltip fallback. Error events are
marked in red.
If a profile did not extract a rich app-layer message name, the renderer falls
back to `frame_protocols` for labels such as SIP, NGAP, NAS-5GS, S1AP, PFCP,
GTPv1/GTPv2, Diameter, RADIUS, SCCP, MAP, or ISUP.

### `visualize` - Re-render flow SVG from an existing flow JSON

```bash
pcap2llm visualize ./artifacts/analyze_trace_start_1_V_01_flow.json
pcap2llm visualize ./artifacts/analyze_trace_start_1_V_01_flow.json --out ./artifacts/flow_custom.svg --width 1800
```

Reads a previously generated `flow.json` and writes a fresh SVG without rerunning tshark or the analysis pipeline.
Use this after changing only presentation width or output path, or when you want
to keep the packet-processing artifacts fixed and regenerate the diagram.

**Options:**
```
--out                   Output SVG path (default: same stem as input, .svg extension)
--width                 SVG canvas width in pixels (default: 1600)
```

### `discover` — Broad scout run for orchestrators

```bash
pcap2llm discover sample.pcapng --out ./discovery
```

Runs a low-cost broad inspection profile and writes:

- `discovery.json` for machine-readable orchestration
- `discovery.md` for a short human summary

Use this when the interface is still unclear and you want a deterministic scout
artifact before choosing a focused analysis profile.

`discover` is broader than `inspect` and lighter than a focused `analyze` run.
It is the right first step for unknown captures, mixed-domain traces, and
agent-driven staged workflows.

Discovery JSON and Markdown now expose the same ordered metadata block as the other artifact-producing commands:

- `run.action`
- `capture.filename`
- `capture.first_packet_number`
- `artifact.version`

**Options:**
```
--out                   Output directory for discovery artifacts
-Y / --display-filter   Optional TShark display filter
--config                Optional YAML config file
--mapping-file          Optional YAML/JSON alias mapping
--hosts-file            Optional Wireshark hosts-style mapping file
--dry-run               Show planned TShark command only
--two-pass              Override two-pass mode for discovery
--tshark-path           Path to tshark executable
--tshark-arg            Extra tshark argument (repeatable)
```

### `recommend-profiles` — Deterministic profile recommendation

```bash
pcap2llm recommend-profiles ./discovery/discovery.json
pcap2llm recommend-profiles sample.pcapng
```

Returns machine-readable candidate profiles, suppressed profiles, and suspected
domains. The logic is rule-based and explainable; it does not run an embedded
LLM.

If the input is a discovery JSON file, the existing recommendation block is
returned directly. If the input is a capture, `pcap2llm` runs an internal
discovery pass first.

**Options:**
```
-Y / --display-filter   Optional TShark display filter when source is a capture
--tshark-path           Path to tshark executable
--tshark-arg            Extra tshark argument (repeatable)
```

## Direct LLM Handoff Commands

The provider handoff commands run the documented staged workflow internally:

1. `discover`
2. choose the recommended profile unless `--profile` is forced
3. `analyze` with the chosen privacy profile
4. build a bounded prompt from the resulting artifacts
5. send the request to the external provider API
6. write prompt and response artifacts next to the normal outputs

These commands are convenience wrappers around the documented workflow in
[`docs/LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md).

### `ask-chatgpt`

```bash
pcap2llm ask-chatgpt trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

**Provider-specific options:**
```
--model                OpenAI model name (default: gpt-4.1-mini)
--timeout-seconds      HTTP timeout for the OpenAI request
--api-key-env          Environment variable for the API key (default: OPENAI_API_KEY)
--max-messages         Maximum normalized detail messages included in the prompt
```

### `ask-claude`

```bash
pcap2llm ask-claude trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

**Provider-specific options:**
```
--model                Anthropic model name (default: claude-3-5-sonnet-latest)
--timeout-seconds      HTTP timeout for the Anthropic request
--api-key-env          Environment variable for the API key (default: ANTHROPIC_API_KEY)
--max-messages         Maximum normalized detail messages included in the prompt
--max-tokens           Maximum Claude response tokens
```

### `ask-gemini`

```bash
pcap2llm ask-gemini trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

**Provider-specific options:**
```
--model                Gemini model name (default: gemini-2.0-flash)
--timeout-seconds      HTTP timeout for the Gemini request
--api-key-env          Environment variable for the API key (default: GEMINI_API_KEY)
--max-messages         Maximum normalized detail messages included in the prompt
```

**Shared workflow options:**
```
--question             Question sent together with the generated artifacts
--profile              Optional forced profile; otherwise discovery chooses the best candidate
--privacy-profile      Privacy profile for the generated handoff artifacts
--display-filter       Optional TShark display filter
--config               Optional YAML config file
--mapping-file         Optional YAML/JSON alias mapping
--hosts-file           Optional Wireshark hosts-style mapping file
--out                  Artifact output directory
--dry-run              Show the planned workflow without executing it
--two-pass             Override TShark two-pass mode for the focused analyze run
--tshark-path          TShark executable path
--tshark-arg           Extra argument passed to tshark
--max-packets          Maximum packets written to detail.json before handoff
--all-packets          Include every exported packet in detail.json
--max-capture-size-mb  Fail fast for oversized captures before tshark export
--oversize-factor      Fail if exported packet count exceeds max-packets by this factor
```

## Session Commands

### `session start` — Initialize a structured session directory

```bash
pcap2llm session start sample.pcapng --out ./artifacts
```

Creates a timestamped session directory with `session_manifest.json` and stores
capture metadata such as the input path and SHA-256 hash.

### `session run-discovery` — Register a discovery run inside a session

```bash
pcap2llm session run-discovery --session ./artifacts/20260410_173000_session
```

Creates a `00_discovery`-style run directory, writes `discovery.json` and
`discovery.md`, and appends the run state to `session_manifest.json`.

### `session run-profile` — Run one profile as part of a session

```bash
pcap2llm session run-profile \
  --session ./artifacts/20260410_173000_session \
  --profile lte-s11 \
  --triggered-by 00_discovery \
  --reason "gtpv2 detected"
```

Useful orchestration fields:

- `--triggered-by` links the run to a previous run id
- `--reason` records explicit reasons for the follow-up
- `--tag` and `--notes` let an external orchestrator keep lightweight context
- `--verbatim-protocol` and `--no-verbatim-protocol` work here as one-run overrides too

### `session finalize` — Close the session and write a report

```bash
pcap2llm session finalize --session ./artifacts/20260410_173000_session
```

Marks the manifest with the chosen final status and writes
`session_report.md`.

---

## Output Files

Every `analyze` run writes a semantically ordered file set:

| File | Contents |
|---|---|
| `analyze_<capture>_start_<n>_V_01_detail.json` | **Primary LLM input** — normalized packets, reduced fields, privacy applied |
| `analyze_<capture>_start_<n>_V_01_summary.json` | Sidecar — protocol mix, conversations, anomalies, coverage, timing |
| `analyze_<capture>_start_<n>_V_01_summary.md` | Human-readable version of the summary |
| `analyze_<capture>_start_<n>_V_01_flow.json` | Optional signaling flow model, written when `--render-flow-svg` is used |
| `analyze_<capture>_start_<n>_V_01_flow.svg` | Optional signaling sequence diagram, written when `--render-flow-svg` is used |
| `analyze_<capture>_start_<n>_V_01_pseudonym_mapping.json` | Only when pseudonymization is active |
| `analyze_<capture>_start_<n>_V_01_vault.json` | Only when encryption is active |

- Filenames lead with semantic context: action, capture filename, start packet, artifact version.
- `_V_01` is always present; auto-increments to `_V_02`, `_V_03` if files already exist in the output directory
- `summary.json` and `detail.json` include `schema_version`, `generated_at` (ISO 8601 UTC), and `capture_sha256`
- `summary.json` includes a `coverage` block showing how many packets were exported and how many were written to `detail.json`
- `flow.json` is generated from the protected detail packets and can be passed to `pcap2llm visualize` for later SVG rendering

---

## Profiles

Profiles control which protocols are extracted, which fields are kept, and how TShark is configured.

**Built-in profiles:**

Profile families are documented separately so the command reference does not
turn into a second profile catalog.

Use the family that matches the traffic:

- `lte-*` for LTE / EPC
- `5g-*` for 5G SA Core
- `volte-*` and `vonr-*` for Voice-over-IMS
- `2g3g-*` for legacy 2G/3G / GERAN

Detailed profile reference:

- Overview: [`docs/PROFILES.md`](PROFILES.md)
- LTE / EPC: [`docs/PROFILES_LTE.md`](PROFILES_LTE.md)
- 5G SA Core: [`docs/PROFILES_5G.md`](PROFILES_5G.md)
- Voice / IMS: [`docs/PROFILES_VOICE.md`](PROFILES_VOICE.md)
- 2G/3G / GERAN: [`docs/PROFILES_2G3G.md`](PROFILES_2G3G.md)

```bash
pcap2llm analyze trace-5g.pcapng --profile 5g-core --out ./artifacts
```

### Verbatim protocol passthrough

By default pcap2llm filters protocol fields and applies `_flatten` to TShark values. `verbatim_protocols` keeps minimally transformed protocol detail when you need broader dissector coverage:

```yaml
verbatim_protocols:
  - gtpv2
```

Top-level protocol fields are retained, repeated nested protocol fields can be surfaced into flat protocol-prefixed keys, and `_ws.*` keys are stripped. `full_detail_fields` for the same protocol is ignored.

For protocols such as Diameter, raw decoder-dump structures like `diameter.avp`, `diameter.avp_tree`, and related `*_tree` blocks can be suppressed with `keep_raw_avps: false` to reduce LLM noise.

Runtime override for one run:

```bash
pcap2llm analyze trace.pcap --profile lte-s11 --verbatim-protocol gtpv2
pcap2llm analyze trace.pcap --profile lte-s6a --no-verbatim-protocol diameter
```

Semantics:

- start with the profile default
- add `--verbatim-protocol`
- remove `--no-verbatim-protocol`
- if both mention the same protocol, removal wins

`--verbatim-protocol` changes how already-dissected fields are preserved. It is
not a substitute for `--two-pass` or for decoder overrides via `--tshark-arg`.

For custom profile creation: [`docs/PROFILES.md`](PROFILES.md)

---

## Controlling Output Size

By default the first **1 000 packets** are written to `detail.json`. Inspection and all summary statistics always run on the full exported capture regardless of this setting.

```bash
# Default: first 1 000 packets
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts

# Custom limit
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 300

# No limit (caution: large files for long captures)
pcap2llm analyze sample.pcapng --profile lte-core --all-packets

# Error if limit would be exceeded
pcap2llm analyze sample.pcapng --profile lte-core --fail-on-truncation

# Reject very large captures before running tshark (default: 250 MiB, 0=off)
pcap2llm analyze sample.pcapng --profile lte-core --max-capture-size-mb 100

# Reject if exported count is more than 5× the detail limit (default factor: 10, 0=off)
pcap2llm analyze sample.pcapng --profile lte-core --oversize-factor 5
```

When truncated, `summary.json` contains a `detail_truncated` entry:

```json
"detail_truncated": {
  "included": 1000,
  "total_exported": 47312,
  "note": "detail.json contains only the first 1,000 of 47,312 packets."
}
```

### What `--max-packets` does not do

This is the most common source of confusion about how the tool scales:

- **Does not make TShark export streaming.** TShark always exports the full capture to JSON first. The packet limit is applied afterwards, during normalization. A 50 000-packet capture still causes a full 50 000-packet TShark export, regardless of `--max-packets 500`.
- **Does not make memory use proportional to the final detail artifact.** Memory during processing reflects the full export, not the limited output slice.
- **Does not make a large rolling capture a good LLM input.** Truncating to 500 packets from a 50 000-packet trace gives you 500 packets that may have no coherent call flow. The remedy is a better display filter before `analyze`, not a tighter packet limit.
- **Summary statistics always reflect the full export.** `summary.json` counts, timing, anomalies, and protocol distributions are computed over all exported packets — not just the packets that end up in `detail.json`.

**Practical implication:** use `inspect` first on unknown or large captures. Narrow with `-Y` until the packet count is in a useful range. Only then run `analyze`. Packet limits are a safety guard, not a replacement for focused captures.

---

## Display Filters

TShark display filters narrow what is analyzed. They are applied before normalization.

```bash
# Diameter only
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter"

# Diameter or GTPv2
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2"

# 5G NGAP view
pcap2llm analyze sample-5g.pcapng --profile 5g-n2 -Y "ngap"

# 5G SBI view
pcap2llm analyze sample-5g.pcapng --profile 5g-sbi -Y "http2"

# SS7
pcap2llm analyze sample-ss7.pcapng --profile 2g3g-ss7-geran -Y "gsm_map || cap || isup"
```

---

## Endpoint Mapping

Resolve raw IPs to readable names. Two mechanisms, combinable:

### A. Wireshark hosts file

The simplest setup: place your file at the default local path and the tool finds it automatically.

```text
.local/hosts
```

No CLI argument needed — the tool checks that path on every run and loads it if present.
If the file is absent, the tool continues without hosts mapping.

File format (standard Wireshark hosts syntax):

```text
10.10.1.11 mme-fra-a
10.20.8.44 hss-core-1
```

To override the default path for a single run:

```bash
pcap2llm analyze sample.pcapng --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample
```

See [Local-only sensitive files](#local-only-sensitive-files) for the `.local/` directory policy.

### B. Custom mapping file (with CIDR support)

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: Frankfurt
  - ip: 10.20.8.44
    alias: HSS_CORE_1
    role: hss
  - cidr: 10.30.0.0/16
    alias: eNB_CLUSTER
    role: enb
    site: Berlin
```

```bash
pcap2llm analyze sample.pcapng --profile lte-core \
  --mapping-file ./examples/mapping.sample.yaml
```

### C. Local subnet fallback file

For large roaming-partner or infrastructure ranges, place a local fallback file at:

```text
.local/Subnets
```

Format: one CIDR and one alias per line, separated by whitespace.

```text
10.10.0.0/16 EPC_CORE
198.51.100.0/24 ROAMING_PARTNER_A
```

You can also override the path explicitly:

```bash
pcap2llm analyze sample.pcapng --profile lte-core \
  --subnets-file ./Subnets
```

**Precedence:** exact matches win first. Exact IP/hostname matches from the mapping file or hosts file are used before any CIDR fallback is considered. The local subnet file is only consulted when no exact match exists. If still nothing matches, the resolver infers a role from the port number (port 3868 → `diameter`, port 2123 → `gtpc`, port 8805 → `pfcp`).

### D. Local SS7 point-code file

For SS7 and MTP3 traces, place a local point-code alias file at:

```text
.local/ss7pcs
```

Format: one point code and one alias per line, separated by whitespace.

```text
0-5093 VZB
INAT0-6316 Verizon_WestOrange_INAT0
```

You can also override the path explicitly:

```bash
pcap2llm analyze sample.pcapng --profile 2g3g-sccp-mtp \
  --ss7pcs-file ./ss7pcs
```

This file is used for MTP3 point-code fallback based on `mtp3.opc` and `mtp3.dpc`. Exact IP, hostname, and CIDR matches still take precedence.

### E. Automatic network element mapping CSV

If a file named `network_element_mapping.csv` is present in the current working directory,
the resolver auto-loads deterministic network-element mapping rules.

Strict CSV header:

```csv
type,value,network_element_type
ip,10.10.10.21,HSS
subnet,10.20.30.0/24,DRA
```

Detection order:

1. exact IP mapping (`ip_mapping`, confidence 100)
2. subnet mapping (`subnet_mapping`, confidence 90)
3. hostname pattern (`hostname_pattern`, confidence 80)
4. protocol/port heuristic (`protocol`, confidence 50)
5. fallback unknown (`unknown`, confidence 0)

When active, detection metadata is attached to endpoint labels and resolved peers:

- `network_element_type`
- `network_element_confidence`
- `network_element_source`
- optional `network_element_warning`
- optional `network_element_override`

Manual override is available through resolver API usage (`network_element_override`) and wins over all automatic signals.

For full details and supported types, see [`NETWORK_ELEMENT_DETECTION.md`](NETWORK_ELEMENT_DETECTION.md).

---

## Privacy

### Privacy profiles (recommended)

| Profile | What it does |
|---|---|
| `internal` | Keep everything as-is |
| `share` | Pseudonymize subscriber IDs (IMSI, MSISDN), remove tokens |
| `lab` | Pseudonymize all subscriber data, mask IPs |
| `prod-safe` | Maximum protection — mask IPs, pseudonymize all PII, remove tokens/email/URI/payload |
| `llm-telecom-safe` | External LLM-safe default — pseudonymize endpoints and subscriber IDs, remove secrets/payload, keep telecom structure |

```bash
pcap2llm analyze sample.pcapng --profile lte-core --privacy-profile share
```

### Per-class overrides

Combine a base privacy profile with individual class overrides:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --privacy-profile share \
  --imei-mode remove \
  --ip-mode keep \
  --out ./artifacts
```

**Available modes:**
- `keep` (alias: `off`) — leave unchanged
- `mask` (alias: `redact`) — replace with `[redacted]`
- `pseudonymize` — stable hash-based alias, e.g. `IMSI_a3f2b1c4`
- `encrypt` — Fernet encryption (requires `cryptography` extra)
- `remove` — delete the field entirely

**Pseudonyms are stable across runs** — the same input value always produces the same alias (BLAKE2s hash). This allows correlation between separate analyses of related captures.

### Encryption workflow

```bash
# Install encryption extra
pip install -e .[dev,encrypt]

# Generate a Fernet key
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set the key as an environment variable
export PCAP2LLM_VAULT_KEY=<your-key>

# Run analysis with encryption
pcap2llm analyze sample.pcapng --imsi-mode encrypt --profile lte-core --out ./artifacts
```

If `PCAP2LLM_VAULT_KEY` is not set, artifact generation fails fast. `vault.json`
stores metadata only and is not a recovery package.

For full privacy guidance: [`docs/PRIVACY_SHARING.md`](PRIVACY_SHARING.md)

---

## Anomaly Detection

The tool automatically detects and flags:

**Transport layer:**
- TCP retransmissions
- Out-of-order segments
- SCTP analysis warnings

**Diameter:**
- Unanswered requests (no answer within the capture)
- Error result codes (≥ 3000)
- Duplicate hop-by-hop IDs

**GTPv2-C:**
- Unanswered Create Session Requests
- Rejected sessions (cause ≠ 16)
- Error Indications

All anomalies appear in `summary.json` under `anomalies` and `anomaly_counts_by_layer`.

---

## Timing Analysis

`summary.json` includes `timing_stats`:

- Total capture duration
- min / max / mean / p95 of inter-packet intervals
- Detected burst periods (`burst_periods`) — time windows with unusually dense traffic

Useful for spotting cascading failures (timeout at packet N → retransmissions immediately after) and traffic spikes.

---

## TShark Options

```bash
# tshark not in PATH
pcap2llm analyze sample.pcapng --tshark-path /usr/local/bin/tshark --profile lte-core

# Two-pass mode for better reassembly (HTTP/2, fragmented packets)
pcap2llm analyze sample.pcapng --profile lte-core --two-pass

# Force a port to be decoded as a specific protocol
pcap2llm analyze sample.pcapng --profile 5g-core \
  --tshark-arg "-d" --tshark-arg "tcp.port==8443,http2"
```

Two-pass can also be set in the profile YAML:
```yaml
tshark:
  two_pass: true
```

---

## Automation and LLM Mode

With `--llm-mode` the CLI outputs machine-readable JSON instead of human-readable text. Suitable for scripts and agents:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --llm-mode --out ./artifacts
```

The JSON output includes `status`, `coverage`, `artifact_prefix`, `artifact_version`, and on failure an `error_code`.

For full documentation: [`docs/LLM_MODE.md`](LLM_MODE.md)

---

## Output Schema

Each packet object in `detail.json`:

```json
{
  "packet_no": 4711,
  "time_rel_ms": 12345.67,
  "top_protocol": "diameter",
  "src": { "ip": "10.10.1.11", "alias": "MME_FRA_A", "role": "mme" },
  "dst": { "ip": "10.20.8.44", "alias": "HSS_CORE_1", "role": "hss" },
  "transport": { "proto": "sctp", "stream": 3, "anomaly": false },
  "privacy": { "modes": { "ip": "keep", "imsi": "pseudonymize" } },
  "anomalies": [],
  "message": { "protocol": "diameter", "fields": { "diameter.cmd.code": "316" } }
}
```

Full schema reference: [`docs/schema/`](schema/)

---

## Troubleshooting

**`tshark was not found in PATH`**
```bash
which tshark
tshark -v
# macOS:   brew install wireshark
# Ubuntu:  sudo apt install tshark
# Custom:  --tshark-path /usr/local/bin/tshark
```

**`tshark output is not valid JSON`**
Usually caused by a TShark version older than 3.6 or a corrupt capture file. Upgrade TShark or re-capture.

**`PCAP2LLM_VAULT_KEY is not a valid Fernet key`**
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**`detail.json` has fewer packets than expected**
Default limit is 1 000. Check `summary.json` for a `detail_truncated` entry showing the total exported count. Use `--all-packets` or `--max-packets N`.

**Empty `detail.json` / no packets at all**
Check your display filter — it may be filtering out everything. Run without `-Y` first to verify. Also check that the profile matches the traffic type.

**Encryption does not work**
```bash
pip install -e .[dev,encrypt]
```

---

## Typical Workflows

```bash
# Assess an unknown capture
pcap2llm inspect trace.pcapng --profile lte-core

# Filtered analysis with endpoint names and privacy
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  -Y "diameter" \
  --privacy-profile share \
  --mapping-file ./mapping.yaml \
  --out ./artifacts

# 5G Core
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-core \
  -Y "pfcp || ngap || http2" \
  --two-pass \
  --out ./artifacts

# SS7
pcap2llm analyze trace-ss7.pcapng \
  --profile 2g3g-ss7-geran \
  -Y "gsm_map || cap || isup || bssap" \
  --out ./artifacts
```

For protocol-specific step-by-step workflows: [`docs/WORKFLOWS.md`](WORKFLOWS.md)

---

---

## Local-only sensitive files

The repository contains a reserved local-only directory at `.local/`.

This directory holds local, sensitive, or developer-specific artifacts that must **not** be committed to version control.

### Default hosts file path

```text
.local/hosts
```

If this file exists, the tool loads it automatically on every `analyze` run.
No `--hosts-file` argument is required in the normal case.

If the file is absent, the tool logs a debug message and continues without hosts mapping. It does not fail.

### Creating the file

After cloning, create the directory and place your hosts file:

```bash
# place your Wireshark hosts file at:
cp /path/to/your/hosts .local/hosts
```

### What belongs in .local/

- `.local/hosts` — Wireshark hosts mapping
- `.local/PCAPs/...` — local-only captures for one-shot batch runs
- `.local/runs/...` — output from `scripts/run_all_local_pcaps.sh`, including flow artifacts and `RESULTS.md`
- `.local/results/...` — output from curated local batch definitions
- local mapping tables
- anonymization dictionaries
- raw trace files for local testing
- temporary analysis outputs not meant for Git

### Git protection

`.gitignore` ignores all real files under `.local/` except:
- `.local/.gitkeep` — keeps the directory present in fresh clones
- `.local/README.md` — documents the directory purpose

A normal `git add .` will **not** stage the hosts file.

### Pre-commit hook

Install the project's pre-commit hook to block accidental force-adds:

```bash
bash scripts/install-git-hooks.sh
```

The hook rejects any staged file under `.local/` that is not one of the two allowed placeholders.

### CI protection

The CI pipeline runs a `local-files-guard` job on every push and pull request.
It fails if any disallowed file under `.local/` is tracked in the repository —
even if someone bypassed the local hook with `git add -f`.

### Safety note

This design strongly reduces accidental publication risk, but it is not an absolute guarantee against intentional bypass. A file stored inside the repository tree is not as isolated as a file stored fully outside of it.

---

## Documentation Map

| Document | Contents |
|---|---|
| [`../README.md`](../README.md) | Overview, quick start, CLI reference summary |
| [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md) | Full inventory of all documentation pages and reading paths |
| **[`REFERENCE.md`](REFERENCE.md)** (this file) | Complete English reference |
| [`QUICKSTART_DE.md`](QUICKSTART_DE.md) | German 5-minute start |
| [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md) | German practical guide |
| [`WORKFLOWS.md`](WORKFLOWS.md) | Step-by-step workflows for LTE, 5G, SS7 |
| [`PROFILES.md`](PROFILES.md) | Creating custom analysis profiles |
| [`LLM_MODE.md`](LLM_MODE.md) | Machine-readable JSON mode for automation |
| [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md) | Privacy model and data sharing guidance |
| [`schema/`](schema/) | JSON schema reference for both output files |
| [`security/`](security/) | Threat model, encryption model |
| [`architecture/`](architecture/) | Pipeline internals for contributors |
