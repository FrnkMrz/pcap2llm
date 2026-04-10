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

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

Behind a corporate proxy:

```powershell
$env:HTTP_PROXY="http://proxy.example.com:8080"
$env:HTTPS_PROXY="http://proxy.example.com:8080"
python -m pip install --proxy http://proxy.example.com:8080 -e .[dev]
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

By default `detail.json` contains the first **1 000 packets**. Use `--all-packets` to remove the limit or `--max-packets N` to set a custom value. The pipeline uses **two passes**: pass 1 exports lightweight field data for all packets (inspection and summary stats always cover the full capture); pass 2 exports full JSON only for the selected N packets. **Pass 1 still scans the entire capture.** A large rolling trace with a 500-packet limit still requires a full pass-1 scan and produces a random slice as output. The remedy is a tighter `-Y` filter, not a bigger limit.

---

## Profiles

Choose the profile that matches your capture:

| Profile | Use case |
|---|---|
| `lte-core` | LTE / EPC — Diameter, GTPv2-C, S1AP, NAS-EPS, DNS |
| `lte-s1` | S1-MME — eNodeB ↔ MME, S1AP-focused control plane |
| `lte-s1-nas` | NAS on S1 — Attach, TAU, authentication, ESM flows |
| `lte-s6a` | S6a — MME ↔ HSS, Diameter over SCTP |
| `lte-s11` | S11 — MME ↔ SGW, GTPv2-C bearer control |
| `lte-s10` | S10 — inter-MME relocation and context transfer |
| `lte-sgs` | SGs — MME ↔ MSC/VLR, CSFB and paging interworking |
| `lte-s5` | S5 — SGW ↔ PGW, EPC control plane with bounded GTP-UP context |
| `lte-s8` | S8 — roaming-oriented SGW ↔ PGW / inter-PLMN GTP context |
| `lte-dns` | LTE/EPC/IMS-adjacent DNS troubleshooting |
| `lte-sbc-cbc` | SBc — MME ↔ CBC for Cell Broadcast / ETWS / CMAS |
| `5g-core` | 5G Core — PFCP, NGAP, NAS-5GS, HTTP/2 SBI |
| `5g-n1-n2` | Broad 5G registration/service view across NGAP and NAS-5GS |
| `5g-n2` | N2-only NGAP signaling between gNB and AMF |
| `5g-nas-5gs` | NAS-5GS-centric registration, mobility, and SM signaling |
| `5g-sbi` | Generic HTTP/2 SBI troubleshooting across 5GC network functions |
| `5g-sbi-auth` | Authorization-heavy SBI capture with token/header focus |
| `5g-n8` | UDM-facing SBI on N8 |
| `5g-n10` | UDM ↔ AUSF authentication exchanges on N10 |
| `5g-n11` | SMF-facing SBI control on N11 |
| `5g-n12` | AUSF ↔ UDM identity/auth data on N12 |
| `5g-n13` | UDM ↔ UDR subscriber data access on N13 |
| `5g-n14` | AMF ↔ AMF mobility and context coordination on N14 |
| `5g-n15` | PCF-facing SBI policy control on N15 |
| `5g-n16` | SMF ↔ PCF policy and session influence on N16 |
| `5g-n22` | 5GC ↔ NSSF / roaming-oriented SBI selection context on N22 |
| `5g-n26` | Hybrid 4G/5G interworking around EPC handover and mobility context |
| `5g-n40` | SMF ↔ CHF charging-related SBI exchanges on N40 |
| `5g-dns` | 5GC-adjacent DNS troubleshooting |
| `5g-cbc-cbs` | Cell Broadcast Center / CBS signaling in a 5G context |
| `2g3g-ss7-geran` | Legacy 2G/3G — SS7, MAP, CAP, ISUP, BSSAP, GERAN |
| `2g3g-gn` | Gn — SGSN ↔ GGSN, intra-PLMN GTPv1 control plane |
| `2g3g-gp` | Gp — roaming/inter-PLMN GTPv1 control plane |
| `2g3g-gr` | Gr — SGSN ↔ HLR over MAP/TCAP/SCCP |
| `2g3g-gs` | Gs — SGSN ↔ MSC/VLR paging and combined CS/PS procedures |
| `2g3g-geran` | GERAN/A-interface-adjacent core-side BSSAP and DTAP view |
| `2g3g-dns` | Legacy/core DNS troubleshooting |
| `2g3g-map-core` | Generic MAP-core troubleshooting beyond one interface |
| `2g3g-cap` | CAP / CAMEL service-control signaling |
| `2g3g-bssap` | Focused BSSAP/BSSMAP/DTAP technical view |
| `2g3g-isup` | Legacy voice/circuit ISUP signaling |
| `2g3g-sccp-mtp` | Lower-layer SCCP / MTP routing and transport issues |

```bash
pcap2llm analyze trace.pcapng --profile 5g-core --out ./artifacts
```

For interface selection guidance across the LTE family: [`docs/PROFILES.md`](docs/PROFILES.md)

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

## CLI Reference

Three commands: `inspect` (no files written), `analyze` (full pipeline + artifacts), `init-config` (create config file).

Full option reference: [`docs/REFERENCE.md`](docs/REFERENCE.md)

---

## LTE Interface Family

The LTE family is now split into focused interface profiles instead of forcing
everything through one generic EPC view:

- `lte-s1` for broad S1-MME procedure troubleshooting
- `lte-s1-nas` when NAS-EPS sequencing is the real subject
- `lte-s6a` for Diameter on S6a, with surfaced AVPs and raw AVP dumps removed by default
- `lte-s11` for MME ↔ SGW control-plane GTPv2-C
- `lte-s10` for inter-MME relocation and context transfer
- `lte-sgs` for CSFB and SGs interworking
- `lte-s5` and `lte-s8` for SGW ↔ PGW contexts, with `lte-s8` framed for roaming
- `lte-dns` for resolver and name-resolution faults
- `lte-sbc-cbc` for Cell Broadcast SBc signaling, not Session Border Controllers

Use `lte-core` when you need a quick mixed-EPC overview. Use the interface
profiles when you want cleaner protocol prioritization, better heuristics, and
more focused `detail.json` output.

## 5G SA Core Family

The 5G family now also includes focused SA core interface profiles instead of
forcing every capture through one mixed `5g-core` lens:

- `5g-n1-n2` for a broad AMF-facing registration and control-plane picture
- `5g-n2` when NGAP itself is the subject
- `5g-nas-5gs` when NAS-5GS sequencing and causes matter more than the radio-side wrapper
- `5g-sbi` for generic HTTP/2 SBI troubleshooting
- `5g-sbi-auth` for token-, identity-, and authorization-heavy SBI exchanges
- `5g-n8`, `5g-n10`, `5g-n12`, `5g-n13` for UDM/AUSF/UDR-centered SBI paths
- `5g-n11`, `5g-n15`, `5g-n16`, `5g-n40` for SMF/PCF/CHF-related control interfaces
- `5g-n14` for inter-AMF mobility coordination
- `5g-n22` for NSSF or roaming-oriented SBI selection context
- `5g-n26` for hybrid EPC/5GC interworking
- `5g-dns` for 5GC-adjacent name-resolution faults
- `5g-cbc-cbs` for public-warning / cell-broadcast signaling in a 5G context

Use `5g-core` when you want a quick mixed overview across NGAP, NAS-5GS, PFCP,
and SBI. Use the focused profiles when you want cleaner protocol ranking,
better heuristics, and smaller interface-specific artifacts.

## 2G/3G Core Family

The legacy family is also split into focused core-side profiles instead of one
large SS7 bucket:

- `2g3g-gn` for intra-PLMN GTPv1 control plane
- `2g3g-gp` for roaming/inter-PLMN GTPv1 context
- `2g3g-gr` for SGSN ↔ HLR MAP signaling
- `2g3g-gs` for SGSN ↔ MSC/VLR paging and combined CS/PS procedures
- `2g3g-geran` for broader GERAN/A-interface-adjacent core visibility
- `2g3g-dns` for legacy/core DNS faults
- `2g3g-map-core` for broader MAP-core analysis
- `2g3g-cap` for CAP/CAMEL service logic
- `2g3g-bssap` for a tighter BSSAP/BSSMAP/DTAP view
- `2g3g-isup` for circuit-signaling call flows
- `2g3g-sccp-mtp` for lower-layer SS7 routing and transport

Use `2g3g-ss7-geran` only when you need the older broad bundle. Use the
focused 2G/3G profiles when you want cleaner interface-specific heuristics and
less cross-protocol noise.

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
| **README.md** (this file) | Overview, quick start, CLI reference summary |
| [`docs/REFERENCE.md`](docs/REFERENCE.md) | **Complete English reference** |
| [`docs/QUICKSTART_DE.md`](docs/QUICKSTART_DE.md) | German 5-minute start |
| [`docs/ANLEITUNG_DE.md`](docs/ANLEITUNG_DE.md) | Vollständige deutsche Referenz |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | Step-by-step workflows for LTE, 5G, SS7 |
| [`docs/PROFILES.md`](docs/PROFILES.md) | Creating custom analysis profiles |
| [`docs/LLM_MODE.md`](docs/LLM_MODE.md) | Machine-readable JSON mode for automation |
| [`docs/PRIVACY_SHARING.md`](docs/PRIVACY_SHARING.md) | Privacy model and data sharing guidance |
| [`docs/schema/`](docs/schema/) | JSON schema reference for both output files |
| [`docs/security/`](docs/security/) | Threat model, encryption model |
| [`docs/architecture/`](docs/architecture/) | Pipeline internals for contributors |

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

18 test modules. Key test files: `test_pipeline.py`, `test_normalizer.py`, `test_privacy_profiles.py`, `test_cli.py`, `test_cli_llm_mode.py` (machine-facing `--llm-mode` contract).

---

## License

Apache License 2.0 — Copyright (c) 2026 Frank März
