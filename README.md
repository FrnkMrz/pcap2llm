# pcap2llm

`pcap2llm` converts `.pcap` and `.pcapng` captures into compact, LLM-friendly artifacts for telecom troubleshooting. It ships with profile-driven workflows for LTE / EPC, 5G core, and legacy 2G/3G SS7 plus GERAN analysis without reworking the CLI or data model.

## Deutsch

Kurzer Einstieg auf Deutsch:

- [`docs/QUICKSTART_DE.md`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/docs/QUICKSTART_DE.md)
- [`docs/ANLEITUNG_DE.md`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/docs/ANLEITUNG_DE.md)

Kurzfassung:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pcap2llm inspect sample.pcapng --profile lte-core
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

## What It Produces

For a normal `analyze` run the tool writes:

- `summary.json`: compact case overview for AI analysis
- `detail.json`: normalized packet/message detail with reduced lower layers
- `summary.md`: human-readable report
- `pseudonym_mapping.json`: only when pseudonymization is used
- `vault.json`: only when encryption is used

## Design Goals

- CLI-first and automation-friendly
- `tshark` as the local dissector backend
- L2 hidden by default
- L3 preserved by default
- L4 reduced to analyst-useful context
- top relevant protocol retained in fuller detail
- privacy controls selectable per data class

## Installation

Requirements:

- Python 3.11+
- `tshark` available in `PATH`

Create a virtual environment and install the package:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

If you need encryption mode:

```bash
pip install -e .[dev,encrypt]
```

## Quick Start

Inspect a capture:

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Analyze a capture and write artifacts:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample \
  --mapping-file ./examples/mapping.sample.yaml \
  --out ./artifacts
```

Preview the plan without invoking `tshark`:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --dry-run
```

Write a starter config file:

```bash
pcap2llm init-config
```

## Privacy Model

Privacy is controlled per data class. Supported classes:

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

Supported modes:

- `keep`
- `mask`
- `pseudonymize`
- `encrypt`
- `remove`

Notes:

- `keep` is the default spelling for the "off" behavior in the build brief.
- pseudonyms stay stable within one case and are exported to `pseudonym_mapping.json`.
- encryption is local-only and uses `PCAP2LLM_VAULT_KEY` when provided.
- if encryption is requested without `PCAP2LLM_VAULT_KEY`, a temporary local key is generated for the process and described in `vault.json`.

## Profiles

Profiles are YAML-driven and define:

- relevant protocols
- top-layer detection priority
- full-detail fields for each top protocol
- reduced transport fields
- default privacy modes
- `tshark` execution hints

The repository ships with:

- `lte-core`
- `5g-core`
- `2g3g-ss7-geran`

Recommended profile selection:

- `lte-core`: LTE / EPC with Diameter, GTPv2-C, S1AP, and NAS-EPS
- `5g-core`: 5G core with PFCP, NGAP, NAS-5GS, and HTTP/2 SBI
- `2g3g-ss7-geran`: legacy 2G/3G signaling with SS7, MAP, CAP, ISUP, BSSAP, and GERAN, without UTRAN

Profile references live in both:

- [`profiles/lte-core.yaml`](/Users/frank/Library/Mobile Documents/com~apple~CloudDocs/GitHub/pcap4llm/profiles/lte-core.yaml)
- [`profiles/5g-core.yaml`](/Users/frank/Library/Mobile Documents/com~apple~CloudDocs/GitHub/pcap4llm/profiles/5g-core.yaml)
- [`profiles/2g3g-ss7-geran.yaml`](/Users/frank/Library/Mobile Documents/com~apple~CloudDocs/GitHub/pcap4llm/profiles/2g3g-ss7-geran.yaml)
- [`src/pcap2llm/profiles/lte-core.yaml`](/Users/frank/Library/Mobile Documents/com~apple~CloudDocs/GitHub/pcap4llm/src/pcap2llm/profiles/lte-core.yaml)
- [`src/pcap2llm/profiles/5g-core.yaml`](/Users/frank/Library/Mobile Documents/com~apple~CloudDocs/GitHub/pcap4llm/src/pcap2llm/profiles/5g-core.yaml)
- [`src/pcap2llm/profiles/2g3g-ss7-geran.yaml`](/Users/frank/Library/Mobile Documents/com~apple~CloudDocs/GitHub/pcap4llm/src/pcap2llm/profiles/2g3g-ss7-geran.yaml)

## Normalized Schema

`detail.json` contains packet/message objects shaped like:

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
    "modes": {
      "ip": "keep",
      "subscriber_id": "pseudonymize",
      "hostname": "keep"
    }
  },
  "message": {
    "protocol": "diameter",
    "fields": {
      "diameter.cmd.code": "316"
    }
  }
}
```

## Repository Layout

```text
pcap2llm/
  README.md
  pyproject.toml
  src/pcap2llm/
  profiles/
  examples/
  tests/
```

## Development

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check .
```

## Contribution Notes

- Keep parsing logic resilient to small `tshark` JSON differences.
- Prefer extending profiles before adding protocol-specific branching.
- Do not send raw PCAP contents to remote services automatically.
- Keep secrets and encryption keys local.

## GitHub Next Steps

The repo is initialized locally by this build. If you want to publish it manually:

```bash
git remote add origin git@github.com:<your-account>/pcap2llm.git
git push -u origin main
```
