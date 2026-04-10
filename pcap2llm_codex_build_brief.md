# PCAP-to-LLM Analyzer: Codex Build Brief

## Role

You are a senior software engineer and network tooling specialist.

Your job is to create a production-ready **CLI-first Python project** that converts PCAP/PCAPNG files into **LLM-friendly structured analysis artifacts** for telecom troubleshooting, with an initial focus on **4G core network protocols** and a later extension path for **5G core**.

This project must be runnable from:
- a normal shell
- OpenCode
- Claude Code
- Codex-style coding agents

Use clear commits, clean structure, readable code, and practical defaults.

---

## Primary goal

Build a tool that takes a PCAP or PCAPNG file, runs it through **TShark/Wireshark dissectors**, and produces:

1. a **summary artifact** for quick AI analysis
2. a **detail artifact** with selected packet/message content
3. optional **mapping / vault artifacts** for pseudonymization or reversible protection
4. a clean **CLI** for analysts

The tool must **not** simply dump Wireshark output. It must normalize and reduce the data so that an LLM can analyze it efficiently.

---

## Key functional requirements

### 1. Input
Support:
- `.pcap`
- `.pcapng`

CLI must accept:
- one input file
- optional display filter
- optional protocol profile
- optional mapping file
- optional Wireshark hosts file
- optional output directory

Example:
```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./out
```

---

### 2. Core processing pipeline
Implement this pipeline:

1. **Inspect**
   - detect relevant protocols
   - collect basic capture metadata
   - gather simple conversation / stream information where useful

2. **Export via TShark**
   - use structured export, preferably JSON
   - optionally use two-pass analysis mode
   - support profile-driven TShark options

3. **Normalize**
   - transform raw TShark output into a stable internal schema
   - identify the highest relevant application/signaling layer per packet/message

4. **Reduce**
   - keep the highest relevant protocol in full detail
   - keep lower layers only in reduced / curated form
   - hide L2 completely by default

5. **Resolve**
   - support Wireshark hosts file input
   - support custom alias / translation file
   - resolve IPs and hostnames into analyst-friendly aliases when configured

6. **Protect**
   - support field-level masking, pseudonymization, or encryption
   - protection must be switchable per data class

7. **Summarize**
   - produce summary and detail artifacts for LLM use
   - optionally produce markdown summary for human reading

---

## Protocol scope

### Phase 1: LTE / EPC / 4G core focus
Prioritize support for:
- Diameter
- GTPv2-C
- S1AP
- NAS-EPS
- DNS
- SCTP
- TCP / UDP as reduced context
- TLS / HTTP only as needed for operational interfaces

### Phase 2: 5G extension path
Design the architecture so later profiles can support:
- HTTP/2
- JSON REST payloads
- NGAP
- NAS-5GS
- NRF / AMF / SMF / UDM / UDR / AUSF / PCF / NSSF style traffic
- TLS
- SBI-style flows

Do not fully implement 5G parsing now unless it comes almost for free. The design must allow it.

---

## Privacy and data handling model

This is a central requirement.

The tool must **not** force a single anonymization model. It must support configurable protection modes.

### Protection modes
Implement support for:

- `off`
  - keep original values

- `mask`
  - redact values irreversibly

- `pseudonymize`
  - replace values with stable aliases within one case

- `encrypt`
  - encrypt selected fields with a local key for secure archival
  - encryption is optional and must not be required for normal use

### Data classes
Protection must be configurable by class, not only by regex.

Support at least these classes:

- `ip`
- `hostname`
- `subscriber_id`
- `msisdn`
- `imsi`
- `imei`
- `email`
- `distinguished_name`
- `token`
- `uri`
- `apn_dnn`
- `diameter_identity`
- `payload_text`

### Important behavior
- IP addresses must be retainable because they are needed for technical analysis.
- IP addresses must also support anonymization/pseudonymization.
- Hostnames must be optionally resolved, masked, aliased, or kept.
- Sensitive identities such as IMSI, MSISDN, e-mail addresses, DNs, Diameter host identities, tokens, and similar values must be switchable per class.

---

## Layer retention rules

### Default behavior
- **L2 / Ethernet / MAC**: hide completely by default
- **L3 / IP**: keep by default, because analysis needs it
- **L4 / TCP / UDP / SCTP**: retain only reduced context
- **Top relevant protocol**: keep in full detail

### Reduced transport context should include things like:
- transport protocol name
- stream / conversation identifier if available
- flags for retransmission / reordering / anomaly if detectable
- selected SCTP stream information if useful

Do not expose raw binary dumps unless explicitly requested.

---

## Name resolution and translation support

Support two optional inputs:

### A. Wireshark hosts file
Standard hosts-style mapping, for example:
```text
10.10.1.11 mme-fra-a
10.10.1.12 mme-fra-b
10.20.8.44 hss-core-1
```

### B. Custom mapping file
Support YAML or JSON mapping with richer metadata, for example:
```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: fra
  - ip: 10.20.8.44
    alias: HSS_CORE_1
    role: hss
    site: dc1
```

The tool should merge and apply these sources in a predictable order.

Suggested precedence:
1. explicit custom mapping
2. Wireshark hosts file
3. original value

---

## CLI requirements

Provide a user-friendly CLI with subcommands.

### Required subcommands
- `analyze`
- `inspect`
- `init-config`

### Example usage
```bash
pcap2llm inspect sample.pcapng

pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --ip-mode keep \
  --hostname-mode alias \
  --subscriber-id-mode pseudonymize \
  --email-mode mask \
  --dn-mode pseudonymize \
  --token-mode remove \
  --hosts-file ./wireshark_hosts \
  --mapping-file ./mapping.yaml \
  --out ./artifacts
```

### CLI design goals
- sensible defaults
- clear help text
- readable error messages
- dry-run option
- verbose and debug modes

---

## Output artifacts

For a normal `analyze` run, produce at least:

### 1. `summary.json`
Compact, LLM-friendly overview:
- capture metadata
- relevant protocols
- conversations / flows
- packet/message counts
- anomalies
- profile used
- privacy modes used

### 2. `detail.json`
Normalized detail view:
- selected packets/messages
- source and destination context
- top protocol
- reduced transport context
- protected or original fields according to configuration

### 3. `summary.md`
Human-readable report with:
- capture overview
- protocol mix
- probable notable findings
- explanation of privacy mode
- file references

### 4. optional mapping / vault outputs
Only if protection modes require it:
- pseudonymization mapping
- encrypted vault file
- key handling notes

---

## Internal normalized schema

Define and document an internal schema. It does not have to be perfect, but it must be stable and explicit.

A packet/message object should look roughly like this:

```json
{
  "packet_no": 4711,
  "time_rel_ms": 12345.67,
  "top_protocol": "diameter",
  "src": {
    "ip": "10.10.1.11",
    "alias": "MME_FRA_A",
    "role": "mme"
  },
  "dst": {
    "ip": "10.20.8.44",
    "alias": "HSS_CORE_1",
    "role": "hss"
  },
  "transport": {
    "proto": "sctp",
    "stream": 3,
    "anomaly": false
  },
  "privacy": {
    "ip_mode": "keep",
    "subscriber_id_mode": "pseudonymize",
    "hostname_mode": "alias"
  },
  "message": {
    "protocol": "diameter",
    "command_code": 316,
    "application_id": 16777251
  }
}
```

The exact schema may improve during implementation, but it must stay coherent and documented.

---

## Profiles

Implement a profile system using YAML.

### Required initial profile
- `lte-core`

### Profile responsibilities
A profile should define:
- relevant protocols
- preferred top-layer detection order
- fields to retain in full
- lower-layer fields to retain in reduced form
- field classes to protect by default
- optional TShark settings
- optional summary heuristics

Example profile ideas:
- `lte-core`
- `epc-ops`
- later: `5gc-sbi`

---

## TShark integration

Use `tshark` as the backend dissector engine.

### Requirements
- detect if `tshark` is installed
- fail with a useful message if not
- isolate TShark invocation in a dedicated module
- support configurable extra arguments
- support two-pass mode where useful
- prefer structured export
- do not depend on Wireshark GUI

### Important
The implementation must be robust if TShark output varies slightly between versions.

---

## Project structure

Create a clean repository structure similar to this:

```text
pcap2llm/
  README.md
  pyproject.toml
  .gitignore
  .env.example
  src/
    pcap2llm/
      __init__.py
      cli.py
      config.py
      models.py
      tshark_runner.py
      inspector.py
      normalizer.py
      reducer.py
      resolver.py
      protector.py
      summarizer.py
      profiles/
        __init__.py
      utils/
        __init__.py
  tests/
    test_cli.py
    test_profiles.py
    test_resolver.py
    test_protector.py
    test_normalizer.py
  examples/
    mapping.sample.yaml
    wireshark_hosts.sample
    config.sample.yaml
```

You may improve the structure, but keep it clean and conventional.

---

## Developer experience requirements

The repository must be pleasant to use.

### Include:
- `README.md`
- installation instructions
- quick start
- CLI examples
- privacy model explanation
- profile explanation
- contribution notes

### Tooling
Use:
- Python 3.11+
- `typer` or `argparse` for CLI
- `pydantic` or dataclasses for internal models
- `pytest`
- type hints
- logging
- Ruff or similar linting if practical

Keep dependencies modest.

---

## GitHub repository creation

If GitHub credentials are available in the current environment, create a new repository named:

```text
pcap2llm
```

If that name is taken in the target account, use:
- `pcap2llm-tool`
- `pcap-ai-export`
- `pcap2ai`

### Repository requirements
- initialize Git
- create a first clean commit
- create a useful README
- push to GitHub if authentication is available
- if GitHub auth is not available, still initialize the local repo and print exact next steps

Do not block the rest of the work on GitHub creation.

---

## Execution environment requirements

The build workflow must work from:
- terminal shell
- OpenCode
- Claude Code
- Codex-like coding agents

### Therefore
- use plain shell commands where possible
- avoid IDE-only steps
- avoid hidden manual assumptions
- document every required external dependency

---

## Security requirements

- never send raw PCAP contents to remote services automatically
- all protection / mapping must run locally
- encryption keys must remain local
- document clearly what is reversible and what is not
- do not hardcode secrets
- do not require cloud access

---

## Acceptance criteria

The build is complete when all of the following are true:

1. I can install the tool locally.
2. I can run `pcap2llm inspect file.pcapng`.
3. I can run `pcap2llm analyze file.pcapng --profile lte-core`.
4. The tool produces `summary.json`, `detail.json`, and `summary.md`.
5. IP retention is configurable.
6. Hostname resolution via hosts file is supported.
7. Custom translation / alias mapping is supported.
8. Sensitive classes such as IMSI, MSISDN, e-mail, DN, tokens, and host identities are independently switchable.
9. L2 is hidden by default.
10. L3 is preserved by default.
11. L4 is reduced by default.
12. The top relevant protocol is preserved in fuller detail.
13. The project has tests.
14. The repository is initialized and ready for GitHub push.
15. The README explains setup and usage clearly.

---

## Nice-to-have features

Implement these only if they fit naturally and do not derail the core build:

- markdown prompt export for LLM handoff
- `--preset llm-safe`
- `--preset local-debug`
- `--preset strict-share`
- optional encryption vault
- protocol-specific summarization hints
- sample output files in `examples/`

---

## What not to do

- Do not build a GUI.
- Do not depend on Wireshark GUI.
- Do not overengineer plugin frameworks.
- Do not attempt full telecom protocol perfection in v1.
- Do not dump raw packet hex unless explicitly requested.
- Do not remove IPs by force.
- Do not hide everything so aggressively that the output becomes useless.

---

## Delivery instructions

Please complete the work in this order:

1. create the repository structure
2. initialize Git
3. implement the CLI skeleton
4. implement TShark detection and basic export
5. implement normalization and reduction
6. implement resolution and privacy controls
7. add the `lte-core` profile
8. add tests
9. write README
10. create the first commit
11. push to GitHub if authentication is available

At the end, provide:
- a short architecture summary
- a list of created files
- exact run commands
- any limitations or open points

---

## Suggested implementation notes

These are suggestions, not hard mandates:

- Use `typer` for a friendly CLI.
- Keep profile loading simple with YAML.
- Separate `resolver` from `protector`.
- Make pseudonymization deterministic within one run and optionally stable via saved mapping.
- Treat Wireshark hosts file as one input signal, not the only truth source.
- Prefer clean JSON artifacts over trying to preserve the full Wireshark tree.
- Make transport reduction explicit and traceable.

---

## Final instruction

Build a practical, readable, CLI-first repository for analysts. The project should be useful quickly, not academically perfect.

Prioritize:
- correctness
- clarity
- privacy controls
- maintainability
- real operator usability
