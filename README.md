# pcap2llm

`pcap2llm` converts `.pcap` and `.pcapng` captures into compact, LLM-friendly artifacts for telecom troubleshooting. It ships with profile-driven workflows for LTE/EPC, 5G core, and legacy 2G/3G SS7 plus GERAN analysis.

## Deutsch

Kurzer Einstieg auf Deutsch:

- [`docs/QUICKSTART_DE.md`](docs/QUICKSTART_DE.md)
- [`docs/ANLEITUNG_DE.md`](docs/ANLEITUNG_DE.md)

## What It Produces

For a normal `analyze` run the tool writes:

- filenames always start with the timestamp of the first packet, e.g. `20240406_075320_...`
- every run always gets a version suffix: `_V_01`, `_V_02`, etc. (auto-incremented when the file already exists)

| File | Contents |
|---|---|
| `YYYYMMDD_HHMMSS_summary_V_01.json` | Compact case overview: protocols, conversations, anomalies, timing stats |
| `YYYYMMDD_HHMMSS_detail_V_01.json` | Normalized packet/message detail with reduced lower layers |
| `YYYYMMDD_HHMMSS_summary_V_01.md` | Human-readable report |
| `YYYYMMDD_HHMMSS_pseudonym_mapping_V_01.json` | Only when pseudonymization is used |
| `YYYYMMDD_HHMMSS_vault_V_01.json` | Only when encryption is used |

The CLI JSON output also includes `artifact_prefix` and `artifact_version` so automation can reliably identify the generated file set.

Both JSON files include `schema_version`, `generated_at` (ISO 8601 UTC), and `capture_sha256` for reproducibility and audit.

By default the generated `*_detail.json` contains only the first **1 000 packets**. Use `--all-packets` to remove the limit or `--max-packets N` to set a custom value. Inspection and all summary statistics always run on the full capture regardless of this setting. When the output is truncated, the generated `*_summary.json` contains a `detail_truncated` key explaining how many packets were exported vs. included.

## When This Tool Works Well — and When It Does Not

pcap2llm is designed for **targeted, focused captures**: a failed attach procedure, a Diameter exchange with an unexpected error, a single GTPv2-C session setup, a call flow with a few dozen to a few hundred signaling messages. That is the sweet spot.

**Works well:**
- A filtered capture of one signaling flow or a handful of related transactions
- Investigating a specific error: one failed call, one rejected session, one timeout
- Captures of seconds to a few minutes, filtered down to relevant protocol traffic
- A `detail.json` of a few hundred packets feeds comfortably into any LLM context window

**Does not work well:**
- Throwing a multi-megabyte rolling capture at it and expecting the LLM to find the needle
- Full-node traffic dumps with tens of thousands of packets — the `detail.json` will be too large for any LLM to reason over
- Long captures that mix many unrelated flows — the LLM sees everything but understands nothing

**Practical rule of thumb:** if your filtered capture has more than ~2 000 signaling messages, consider splitting it by flow or SCTP/TCP stream before analyzing. Use `pcap2llm inspect` first to understand what is inside, then narrow down with `-Y` before running `analyze`.

The `--max-packets` default of 1 000 is a safety rail, not a target. A tight filter and a focused capture window produce far better LLM output than a big capture trimmed by the packet limit.

## Design Goals

- CLI-first and automation-friendly
- `tshark` as the local dissector backend — no cloud dependency
- L2 hidden by default; L3 preserved; L4 reduced to analyst-useful context
- Top relevant protocol retained in fuller detail
- Privacy controls selectable per data class

## Installation

Requirements:

- Python 3.11+
- `tshark` available in `PATH` (Wireshark package)

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

For encryption support:

```bash
pip install -e .[dev,encrypt]
```

On Windows inside the active `.venv`, the prompt typically shows `(.venv)` and all `python`, `pip`, `pytest`, and `pcap2llm` commands use that virtual environment.

## Quick Start

```bash
# Inspect metadata only
pcap2llm inspect sample.pcapng --profile lte-core

# Full analysis (default: first 1 000 packets in the generated detail artifact)
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample \
  --mapping-file ./examples/mapping.sample.yaml \
  --out ./artifacts

# Example JSON response fields after analyze:
# "artifact_prefix": "20240406_075320"
# "artifact_version": null

# Include all packets in the generated detail artifact (large captures → large file)
pcap2llm analyze sample.pcapng --profile lte-core --all-packets

# Custom packet limit
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 500

# Preview the plan without invoking tshark
pcap2llm analyze sample.pcapng --profile lte-core --dry-run

# Generate a starter config file
pcap2llm init-config
```

## Endpoint Mapping

Two mapping sources are supported and can be combined:

- **`--hosts-file`**: Wireshark-style hosts file (`<IP>  <hostname>`)
- **`--mapping-file`**: YAML/JSON with aliases, roles, sites, CIDR ranges

**Precedence**: `--mapping-file` overrides `--hosts-file` for the same IP.

Example mapping file with CIDR support:

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: Frankfurt
  - cidr: 10.20.0.0/16
    alias: HSS_CLUSTER
    role: hss
    site: Munich
```

If no mapping entry is found for an IP, the resolver falls back to port-based role inference (e.g. port 3868 → `diameter`, port 8805 → `pfcp`).

## Privacy Model

Privacy is controlled per data class via `--<class>-mode`:

| Data class | Default (lte-core) |
|---|---|
| `ip` | `keep` |
| `hostname` | `keep` |
| `subscriber_id` | `pseudonymize` |
| `msisdn` | `pseudonymize` |
| `imsi` | `pseudonymize` |
| `imei` | `mask` |
| `email` | `mask` |
| `distinguished_name` | `pseudonymize` |
| `token` | `remove` |
| `uri` | `mask` |
| `apn_dnn` | `keep` |
| `diameter_identity` | `pseudonymize` |
| `payload_text` | `mask` |

Supported modes (aliases in parentheses):

- `keep` (alias: `off`) — no change
- `mask` (alias: `redact`) — replace with `[redacted]`
- `pseudonymize` — replace with a stable hash-based alias, e.g. `IMSI_a3f2b1c4`
- `encrypt` — Fernet encryption (requires `cryptography` extra)
- `remove` — delete the field entirely

Pseudonyms are **stable across runs**: the same original value always produces the same alias (BLAKE2s hash).

### Encryption Workflow

1. Install the `encrypt` extra: `pip install -e .[dev,encrypt]`
2. Generate a Fernet key: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
3. Export the key: `export PCAP2LLM_VAULT_KEY=<key>`
4. Run the analysis: `pcap2llm analyze sample.pcapng --imsi-mode encrypt`
5. The key source is documented in the generated `*_vault.json`. Without the key the encrypted values cannot be recovered.

If `PCAP2LLM_VAULT_KEY` is not set, a temporary key is generated for the process and stored in the generated `*_vault.json`.

## Profiles

Profiles are YAML-driven and define protocol priorities, field extraction, and privacy defaults.

Built-in profiles:

| Profile | Use case |
|---|---|
| `lte-core` | LTE/EPC: Diameter, GTPv2-C, S1AP, NAS-EPS |
| `5g-core` | 5G: PFCP, NGAP, NAS-5GS, HTTP/2 SBI |
| `2g3g-ss7-geran` | Legacy 2G/3G: SS7, MAP, CAP, ISUP, BSSAP, GERAN (no UTRAN) |

To create a custom profile, see [`docs/PROFILES.md`](docs/PROFILES.md).

## Anomaly Detection

The tool detects both transport-layer and application-layer anomalies:

**Transport**: TCP retransmissions, out-of-order segments, SCTP analysis warnings.

**Diameter**: unanswered requests, error result codes (≥ 3000), duplicate hop-by-hop IDs.

**GTPv2-C**: unanswered Create Session Requests, rejected sessions, Error Indications.

Anomalies appear in the generated `*_summary.json` under `anomalies` and are classified by layer in `anomaly_counts_by_layer`.

## Normalized Schema

Generated `*_detail.json` packet objects:

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

## Troubleshooting

**`tshark was not found in PATH`**
Install Wireshark/TShark and ensure it is on `PATH`. On macOS: `brew install wireshark`. On Ubuntu: `sudo apt install tshark`. Use `--tshark-path /path/to/tshark` if it is not in `PATH`.

**`tshark output is not valid JSON`**
Usually caused by a very old TShark version or a corrupt capture. Try upgrading TShark (≥ 3.6 recommended) or re-capturing.

**`PCAP2LLM_VAULT_KEY is not a valid Fernet key`**
The key must be a URL-safe base64-encoded 32-byte value. Generate one with:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**`Expected an object at the root of <file>`**
Your YAML config or mapping file has an invalid root type. The top-level element must be a mapping (`key: value`), not a list or scalar.

**Generated `*_detail.json` contains fewer packets than expected**
By default only the first 1 000 packets are written to the generated `*_detail.json`. Use `--all-packets` to include everything, or increase the limit with `--max-packets N`. Check the generated `*_summary.json` for a `detail_truncated` entry that shows the total exported count.

**Empty `*_detail.json` / no packets at all**
Check the display filter (`-Y`) — it may be filtering out all packets. Run without a filter first. Also verify the profile matches the traffic (e.g. use `5g-core` for 5G captures).

## Development

```bash
pytest          # run tests
ruff check .    # lint
```

Run a single test file:
```bash
pytest tests/test_pipeline.py -v
```

## Contribution Notes

- Keep parsing logic resilient to small `tshark` JSON differences across versions.
- Prefer extending profiles before adding protocol-specific branching in code.
- Do not send raw PCAP contents to remote services.
- Keep secrets and encryption keys local.

## License

This project is licensed under the Apache License 2.0.

Copyright (c) 2026 Frank März
