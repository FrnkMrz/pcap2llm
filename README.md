# pcap2llm

`pcap2llm` converts `.pcap` and `.pcapng` network captures into structured, privacy-controlled JSON artifacts for telecom troubleshooting. You give it a capture file — it gives you a clean, LLM-ready handoff artifact.

The tool does **no AI analysis**. It prepares and formats the data. The LLM step is separate and up to you.

> **Sweet spot:** A failed attach, a Diameter error, a specific call flow — captures of seconds to a few minutes with a few hundred signaling packets. Not designed for multi-megabyte rolling dumps.

---

## Quick Start

```bash
# 1. Install
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# 2. Inspect a capture (no artifacts written)
pcap2llm inspect sample.pcapng --profile lte-core

# 3. Analyze and write artifacts
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts

# 4. Preview without running tshark
pcap2llm analyze sample.pcapng --profile lte-core --dry-run
```

Requirements: Python 3.11+, `tshark` in PATH (Wireshark package).

---

## What It Produces

Every `analyze` run writes a timestamped, versioned file set:

| File | Purpose |
|---|---|
| `YYYYMMDD_HHMMSS_detail_V_01.json` | **Primary LLM input** — normalized packets, reduced fields, privacy-applied |
| `YYYYMMDD_HHMMSS_summary_V_01.json` | Sidecar — protocol mix, conversations, anomalies, coverage, timing |
| `YYYYMMDD_HHMMSS_summary_V_01.md` | Human-readable version of the summary |
| `YYYYMMDD_HHMMSS_pseudonym_mapping_V_01.json` | Only when pseudonymization is active |
| `YYYYMMDD_HHMMSS_vault_V_01.json` | Only when encryption is active |

- Timestamp comes from the first packet in the capture
- `_V_01` is always present; auto-increments to `_V_02`, `_V_03` if files already exist
- Both JSON files include `schema_version`, `generated_at` (ISO 8601 UTC), and `capture_sha256`

By default `detail.json` contains the first **1 000 packets**. Use `--all-packets` to remove the limit or `--max-packets N` to set a custom value. Inspection and all summary statistics always run on the full capture regardless of this setting.

---

## Profiles

Choose the profile that matches your capture:

| Profile | Use case |
|---|---|
| `lte-core` | LTE / EPC — Diameter, GTPv2-C, S1AP, NAS-EPS, DNS |
| `5g-core` | 5G Core — PFCP, NGAP, NAS-5GS, HTTP/2 SBI |
| `2g3g-ss7-geran` | Legacy 2G/3G — SS7, MAP, CAP, ISUP, BSSAP, GERAN |

```bash
pcap2llm analyze trace.pcapng --profile 5g-core --out ./artifacts
```

To create a custom profile: [`docs/PROFILES.md`](docs/PROFILES.md)

---

## Privacy

Privacy is controlled per data class. The built-in privacy profiles cover the most common cases:

| Privacy profile | What it does |
|---|---|
| `internal` | Keep everything as-is |
| `share` | Pseudonymize subscriber IDs (IMSI, MSISDN), remove tokens |
| `lab` | Pseudonymize all subscriber data, mask IPs |
| `prod-safe` | Maximum protection — mask IPs, pseudonymize all PII, remove tokens/email/URI |

```bash
pcap2llm analyze trace.pcapng --profile lte-core --privacy-profile share --out ./artifacts
```

Available modes per class: `keep` · `mask` · `pseudonymize` · `encrypt` · `remove`

Override individual classes on the command line:

```bash
pcap2llm analyze trace.pcapng --profile lte-core \
  --privacy-profile share \
  --imei-mode remove \
  --ip-mode mask
```

Pseudonyms are **stable across runs** — same input value always produces the same alias (BLAKE2s hash), e.g. `IMSI_a3f2b1c4`. Full privacy reference: [`docs/PRIVACY_SHARING.md`](docs/PRIVACY_SHARING.md)

---

## Endpoint Mapping

Resolve raw IPs to readable names using a hosts file or a custom mapping:

```bash
pcap2llm analyze trace.pcapng --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample \
  --mapping-file ./examples/mapping.sample.yaml
```

The mapping file supports individual IPs, hostnames, and CIDR ranges:

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: Frankfurt
  - cidr: 10.20.0.0/16
    alias: HSS_CLUSTER
    role: hss
```

If no mapping entry exists for an IP, the resolver infers a role from the port (e.g. port 3868 → `diameter`, port 8805 → `pfcp`).

---

## Anomaly Detection

The tool automatically flags:

- **Transport**: TCP retransmissions, out-of-order segments, SCTP warnings
- **Diameter**: unanswered requests, error result codes (≥ 3000), duplicate hop-by-hop IDs
- **GTPv2-C**: unanswered Create Session Requests, rejected sessions, Error Indications

Anomalies appear in `summary.json` under `anomalies` and `anomaly_counts_by_layer`.

---

## Full CLI Reference

### `pcap2llm inspect`

Inspect a capture without writing analysis artifacts.

```
pcap2llm inspect <capture> [options]

  --profile             Protocol profile (default: lte-core)
  -Y / --display-filter TShark display filter
  --config              YAML config file
  --out                 Write JSON result to file instead of stdout
  --dry-run             Print planned tshark command only
  --two-pass            Override two-pass dissection mode
  --tshark-path         Path to tshark executable
  --tshark-arg          Extra tshark argument (repeatable)
```

### `pcap2llm analyze`

Run the full pipeline and write artifacts.

```
pcap2llm analyze <capture> [options]

Profile & filtering:
  --profile             Protocol profile (default: lte-core)
  --privacy-profile     Privacy profile (internal | share | lab | prod-safe | <path>)
  -Y / --display-filter TShark display filter
  --config              YAML config file

Output:
  --out                 Output directory (default: artifacts)
  --max-packets         Max packets in detail.json (default: 1000)
  --all-packets         Include all packets, overrides --max-packets
  --fail-on-truncation  Error if detail would be truncated
  --max-capture-size-mb Reject captures larger than N MiB (default: 250, 0=off)
  --dry-run             Print plan only, no tshark execution
  --llm-mode            Output strict JSON for agent/automation use

Endpoint resolution:
  --hosts-file          Wireshark-style hosts file
  --mapping-file        YAML/JSON alias mapping (supports CIDR)

Privacy overrides (per class):
  --ip-mode / --hostname-mode / --subscriber-id-mode / --msisdn-mode
  --imsi-mode / --imei-mode / --email-mode / --dn-mode / --token-mode
  --uri-mode / --apn-dnn-mode / --diameter-identity-mode / --payload-text-mode
                        keep | mask | pseudonymize | encrypt | remove

TShark:
  --two-pass            Override two-pass dissection mode
  --tshark-path         Path to tshark executable
  --tshark-arg          Extra tshark argument (repeatable)
```

### `pcap2llm init-config`

Write a starter configuration file.

```
pcap2llm init-config [path]   (default: pcap2llm.config.yaml)
  --force               Overwrite existing file
```

---

## Output Schema (detail.json)

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

Full schema reference: [`docs/schema/`](docs/schema/)

---

## Troubleshooting

**`tshark was not found in PATH`**
Install Wireshark/TShark and ensure it is on PATH.
- macOS: `brew install wireshark`
- Ubuntu: `sudo apt install tshark`
- Custom path: `pcap2llm analyze sample.pcapng --tshark-path /usr/local/bin/tshark`

**`tshark output is not valid JSON`**
Usually an old TShark version (< 3.6) or a corrupt capture. Upgrade TShark or re-capture.

**`PCAP2LLM_VAULT_KEY is not a valid Fernet key`**
Generate a valid key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**`detail.json` has fewer packets than expected**
Default limit is 1 000 packets. Check `summary.json` for a `detail_truncated` entry.
Use `--all-packets` or `--max-packets N` to adjust.

**Empty `detail.json`**
Check your display filter — it may be filtering out everything. Try without `-Y` first.
Also verify the profile matches the traffic (e.g. use `5g-core` for 5G captures).

---

## Documentation

| Document | What it covers |
|---|---|
| **README.md** (this file) | Overview, quick start, full CLI reference |
| [`docs/QUICKSTART_DE.md`](docs/QUICKSTART_DE.md) | German 5-minute start |
| [`docs/ANLEITUNG_DE.md`](docs/ANLEITUNG_DE.md) | Vollständige deutsche Referenz |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | Step-by-step workflows for LTE, 5G, SS7 |
| [`docs/PROFILES.md`](docs/PROFILES.md) | Creating custom analysis profiles |
| [`docs/LLM_MODE.md`](docs/LLM_MODE.md) | Machine-readable JSON mode for automation |
| [`docs/PRIVACY_SHARING.md`](docs/PRIVACY_SHARING.md) | Privacy model and data sharing guidance |
| [`docs/schema/`](docs/schema/) | JSON schema reference for both output files |
| [`docs/security/`](docs/security/) | Threat model, encryption model |
| [`docs/architecture/`](docs/architecture/) | Pipeline internals |

---

## Installation

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

### With encryption support

```bash
pip install -e .[dev,encrypt]
export PCAP2LLM_VAULT_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
```

---

## Development

```bash
pytest           # run all tests
pytest tests/test_pipeline.py -v   # single file
ruff check .     # lint
```

18 test modules. Key test files: `test_pipeline.py`, `test_normalizer.py`, `test_privacy_profiles.py`, `test_cli.py`.

---

## License

Apache License 2.0 — Copyright (c) 2026 Frank März
