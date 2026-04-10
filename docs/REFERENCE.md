# pcap2llm — Complete Reference

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

## The Three Commands

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

**All options:**
```
Profile & filtering:
  --profile               Protocol profile (default: lte-core)
  --privacy-profile       Privacy profile: internal | share | lab | prod-safe | <path>
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

---

## Output Files

Every `analyze` run writes a file set named with the timestamp of the first packet and a version number:

| File | Contents |
|---|---|
| `YYYYMMDD_HHMMSS_detail_V_01.json` | **Primary LLM input** — normalized packets, reduced fields, privacy applied |
| `YYYYMMDD_HHMMSS_summary_V_01.json` | Sidecar — protocol mix, conversations, anomalies, coverage, timing |
| `YYYYMMDD_HHMMSS_summary_V_01.md` | Human-readable version of the summary |
| `YYYYMMDD_HHMMSS_pseudonym_mapping_V_01.json` | Only when pseudonymization is active |
| `YYYYMMDD_HHMMSS_vault_V_01.json` | Only when encryption is active |

- `_V_01` is always present; auto-increments to `_V_02`, `_V_03` if files already exist in the output directory
- Both JSON files include `schema_version`, `generated_at` (ISO 8601 UTC), and `capture_sha256`
- `summary.json` includes a `coverage` block showing how many packets were exported and how many were written to `detail.json`

---

## Profiles

Profiles control which protocols are extracted, which fields are kept, and how TShark is configured.

**Built-in profiles:**

| Profile | Use case |
|---|---|
| `lte-core` | LTE / EPC — Diameter, GTPv2-C, S1AP, NAS-EPS, DNS, TLS |
| `lte-s1` | S1-MME — eNodeB ↔ MME, S1AP-focused control plane |
| `lte-s1-nas` | NAS on S1 — Attach, TAU, authentication, and ESM flows |
| `lte-s6a` | S6a — MME ↔ HSS, Diameter over SCTP |
| `lte-s11` | S11 — MME ↔ SGW, GTPv2-C bearer control |
| `lte-s10` | S10 — inter-MME relocation and context transfer |
| `lte-sgs` | SGs — MME ↔ MSC/VLR CSFB and paging interworking |
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
| `volte-sip` | Broad VoLTE / IMS SIP troubleshooting on LTE / EPS |
| `volte-sip-register` | VoLTE IMS registration and challenge-flow analysis |
| `volte-sip-call` | VoLTE call setup and teardown troubleshooting |
| `volte-diameter-cx` | VoLTE Cx / Dx subscriber and registration context |
| `volte-diameter-rx` | VoLTE Rx policy and authorization signaling |
| `volte-diameter-sh` | VoLTE Sh subscriber-profile and service-data access |
| `volte-dns` | DNS for IMS discovery in LTE / EPS voice environments |
| `volte-rtp-signaling` | RTP/RTCP as supporting evidence for VoLTE signaling |
| `volte-sbc` | VoLTE Session Border Controller edge troubleshooting |
| `volte-ims-core` | Broad SIP + Diameter + DNS IMS-core view for VoLTE |
| `vonr-sip` | Broad VoNR / IMS SIP troubleshooting on 5GS |
| `vonr-sip-register` | VoNR IMS registration and readiness analysis |
| `vonr-sip-call` | VoNR call setup and teardown troubleshooting |
| `vonr-ims-core` | Broad SIP + SBI + DNS + N1/N2 voice-core view for VoNR |
| `vonr-policy` | Voice-relevant policy and QoS control on 5GS |
| `vonr-dns` | DNS for IMS discovery in 5GS voice environments |
| `vonr-n1-n2-voice` | Voice-relevant NGAP and NAS-5GS state on N1/N2 |
| `vonr-sbi-auth` | Auth-related SBI flows that affect VoNR readiness |
| `vonr-sbi-pdu` | Voice-relevant PDU and session-control SBI flows |
| `vonr-sbc` | VoNR Session Border Controller edge troubleshooting |
| `2g3g-ss7-geran` | Broad legacy 2G/3G bundle across SS7, MAP, CAP, ISUP, and GERAN |
| `2g3g-gn` | Gn — SGSN ↔ GGSN, intra-PLMN GTPv1 control plane |
| `2g3g-gp` | Gp — roaming/inter-PLMN GTPv1 control plane |
| `2g3g-gr` | Gr — SGSN ↔ HLR MAP signaling |
| `2g3g-gs` | Gs — SGSN ↔ MSC/VLR paging and combined CS/PS procedures |
| `2g3g-geran` | GERAN/A-interface-adjacent core-side BSSAP and DTAP view |
| `2g3g-dns` | Legacy/core DNS troubleshooting |
| `2g3g-map-core` | Generic MAP-core analysis beyond one interface |
| `2g3g-cap` | CAP / CAMEL service-control signaling |
| `2g3g-bssap` | Focused BSSAP/BSSMAP/DTAP technical view |
| `2g3g-isup` | Legacy voice/circuit ISUP signaling |
| `2g3g-sccp-mtp` | Lower-layer SCCP / MTP routing and transport issues |

Use `5g-core` for a broad first-pass mixed 5GC view. Use the narrower 5G SA
profiles when the interface is known and you want smaller, cleaner artifacts.

```bash
pcap2llm analyze trace-5g.pcapng --profile 5g-n11 --out ./artifacts
```

### Verbatim protocol passthrough

By default pcap2llm filters protocol fields and applies `_flatten` to TShark values. `verbatim_protocols` keeps minimally transformed protocol detail when you need broader dissector coverage:

```yaml
verbatim_protocols:
  - gtpv2
```

Top-level protocol fields are retained, repeated nested protocol fields can be surfaced into flat protocol-prefixed keys, and `_ws.*` keys are stripped. `full_detail_fields` for the same protocol is ignored.

For protocols such as Diameter, raw decoder-dump structures like `diameter.avp`, `diameter.avp_tree`, and related `*_tree` blocks can be suppressed with `keep_raw_avps: false` to reduce LLM noise.

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

```text
10.10.1.11 mme-fra-a
10.20.8.44 hss-core-1
```

```bash
pcap2llm analyze sample.pcapng --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample
```

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

**Precedence:** mapping file overrides hosts file for the same IP. If no mapping is found, the resolver infers a role from the port number (port 3868 → `diameter`, port 2123 → `gtpc`, port 8805 → `pfcp`).

---

## Privacy

### Privacy profiles (recommended)

| Profile | What it does |
|---|---|
| `internal` | Keep everything as-is |
| `share` | Pseudonymize subscriber IDs (IMSI, MSISDN), remove tokens |
| `lab` | Pseudonymize all subscriber data, mask IPs |
| `prod-safe` | Maximum protection — mask IPs, pseudonymize all PII, remove tokens/email/URI/payload |

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

If `PCAP2LLM_VAULT_KEY` is not set, a temporary key is generated and stored in `vault.json`. Without the key, encrypted values cannot be recovered.

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

## Documentation Map

| Document | Contents |
|---|---|
| [`../README.md`](../README.md) | Overview, quick start, CLI reference summary |
| **[`REFERENCE.md`](REFERENCE.md)** (this file) | Complete English reference |
| [`QUICKSTART_DE.md`](QUICKSTART_DE.md) | German 5-minute start |
| [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md) | Complete German reference |
| [`WORKFLOWS.md`](WORKFLOWS.md) | Step-by-step workflows for LTE, 5G, SS7 |
| [`PROFILES.md`](PROFILES.md) | Creating custom analysis profiles |
| [`LLM_MODE.md`](LLM_MODE.md) | Machine-readable JSON mode for automation |
| [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md) | Privacy model and data sharing guidance |
| [`schema/`](schema/) | JSON schema reference for both output files |
| [`security/`](security/) | Threat model, encryption model |
| [`architecture/`](architecture/) | Pipeline internals for contributors |
