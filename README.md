# pcap2llm

`pcap2llm` converts `.pcap` and `.pcapng` network captures into structured,
privacy-controlled JSON artifacts for telecom troubleshooting. You give it a
capture file; it gives you a clean, LLM-ready handoff artifact.

The tool does **no AI analysis**. It prepares and formats the data. The LLM
step is separate and up to you.

> **Sweet spot:** A failed attach, a Diameter error, a specific call flow —
> captures of seconds to a few minutes with a few hundred signaling packets.
> Not designed for multi-megabyte rolling dumps.

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

Requirements: Python 3.11+, `tshark` in PATH (Wireshark package).

## What It Produces

Every `analyze` run writes a semantically ordered, versioned file set:

| File | Purpose |
|---|---|
| `analyze_<capture>_<YYYYMMDD_HHMMSS>_V_01_detail.json` | **Primary LLM input** — normalized packets, reduced fields, privacy-applied |
| `analyze_<capture>_<YYYYMMDD_HHMMSS>_V_01_summary.json` | Sidecar — protocol mix, conversations, anomalies, coverage, timing |
| `analyze_<capture>_<YYYYMMDD_HHMMSS>_V_01_summary.md` | Human-readable version of the summary |
| `analyze_<capture>_<YYYYMMDD_HHMMSS>_V_01_pseudonym_mapping.json` | Only when pseudonymization is active |
| `analyze_<capture>_<YYYYMMDD_HHMMSS>_V_01_vault.json` | Only when encryption is active |

- Filenames lead with semantic context: action, capture filename, first-packet timestamp, artifact version.
- `_V_01` is always present and auto-increments if files already exist.
- JSON and Markdown outputs now expose ordered run metadata for readability and automation:
  `run.action`, `capture.filename`, `capture.first_packet_number`, and `artifact.version`.
- `summary.json` and `detail.json` also include `schema_version`, `generated_at` (ISO 8601 UTC), and `capture_sha256`.

`inspect`, `discover`, and `analyze` all present that metadata in the same human-first order:

1. action
2. capture file
3. first-packet timestamp
4. artifact version

## Profiles

Choose the profile family that matches the capture:

- LTE / EPC for S1, S6a, S11, S10, SGs, S5/S8, EPC DNS, and Cell Broadcast SBc
- 5G SA Core for broad 5GC, N1/N2, SBI, policy, charging, DNS, and N26 interworking
- VoLTE / VoNR / IMS for voice-over-IMS signaling, Diameter policy/subscriber paths, Session Border Controllers, and voice-relevant 5GS context
- 2G/3G Core / GERAN for Gn/Gp, Gr, Gs, MAP, CAP, ISUP, GERAN, and lower-layer SS7

Examples:

```bash
pcap2llm analyze trace.pcapng --profile lte-core --out ./artifacts
pcap2llm analyze trace-5g.pcapng --profile 5g-n11 --out ./artifacts
pcap2llm analyze trace-ims.pcapng --profile volte-sip-call --out ./artifacts
```

Detailed profile reference:

- Overview: [`docs/PROFILES.md`](docs/PROFILES.md)
- LTE / EPC: [`docs/PROFILES_LTE.md`](docs/PROFILES_LTE.md)
- 5G SA Core: [`docs/PROFILES_5G.md`](docs/PROFILES_5G.md)
- Voice / IMS: [`docs/PROFILES_VOICE.md`](docs/PROFILES_VOICE.md)
- 2G/3G Core / GERAN: [`docs/PROFILES_2G3G.md`](docs/PROFILES_2G3G.md)

## Agent-Ready Orchestration

`pcap2llm` can now act as a deterministic building block for external agents or
automation layers without hiding decisions inside the tool itself.

Typical staged flow:

```bash
# 1. Broad scout run — artifacts land in artifacts/ like any other run
pcap2llm discover trace.pcapng

# 2. Deterministic profile recommendation from the discovery result
pcap2llm recommend-profiles artifacts/20260410_173000_discovery.json

# 3. Structured multi-run session
pcap2llm session start trace.pcapng --out ./artifacts
pcap2llm session run-discovery --session ./artifacts/20260410_173000_session
pcap2llm session run-profile --session ./artifacts/20260410_173000_session --profile lte-s11
pcap2llm session finalize --session ./artifacts/20260410_173000_session
```

More detail:

- [`docs/DISCOVERY.md`](docs/DISCOVERY.md) for scout runs and discovery artifacts
- [`docs/PROFILE_SELECTION.md`](docs/PROFILE_SELECTION.md) for recommendation logic and `selector_metadata`
- [`docs/SESSIONS.md`](docs/SESSIONS.md) for session manifests and multi-run orchestration
- [`docs/LLM_TROUBLESHOOTING_WORKFLOW.md`](docs/LLM_TROUBLESHOOTING_WORKFLOW.md) for the documented PCAP -> `pcap2llm` -> external LLM handoff workflow

## LLM Troubleshooting Workflow

When an external LLM should explain or troubleshoot a trace, use the documented workflow in [`docs/LLM_TROUBLESHOOTING_WORKFLOW.md`](docs/LLM_TROUBLESHOOTING_WORKFLOW.md).

In short:

1. run `discover`
2. choose the focused profile
3. run `analyze --privacy-profile llm-telecom-safe`
4. share only the minimum necessary artifact excerpt with the LLM
5. never share the raw PCAP, `pseudonym_mapping.json`, `vault.json`, or key material
6. validate the LLM answer against the local artifacts

Direct ChatGPT handoff is also available from the CLI when `OPENAI_API_KEY` is set:

```bash
pcap2llm ask-chatgpt trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

Direct Claude handoff is also available from the CLI when `ANTHROPIC_API_KEY` is set:

```bash
pcap2llm ask-claude trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

Direct Gemini handoff is also available from the CLI when `GEMINI_API_KEY` is set:

```bash
pcap2llm ask-gemini trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

## Repo-Owned Local Batch Runner

The repo now includes a committed local batch runner plus committed batch definitions, while private captures and generated artifacts stay local-only.

Quick path:

```bash
# 1. Put local captures under ignored storage such as .local/PCAPs/
# 2. Review or edit the committed batch definition
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --list

# 3. Run the whole batch
python3 scripts/run_local_batches.py --batch batches/local_examples.toml

# 4. Or run only one named case
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --case analyze_diameter_s6a_orange_pl
```

How it is intended to work:

1. Clone the repo and install `pcap2llm`.
2. Place private PCAPs, hosts files, and mapping files in ignored local storage such as `.local/`.
3. Keep the run catalog in versioned files such as [`batches/local_examples.toml`](batches/local_examples.toml).
4. Run the repo-owned runner from the repo root.
5. Review local outputs under `.local/results/` and do not commit them.

Notes:

- the runner script lives at [`scripts/run_local_batches.py`](scripts/run_local_batches.py)
- the batch format is TOML and stays human-editable
- local result directories default to `.local/results/...` and can be overridden with `--output-root`
- `--case` selects one or more named cases
- `--dry-run` shows the resolved commands without executing them
- `.gitignore` protects `.local/`, `artifacts/`, common output folders, and optional local batch override files such as `batches/*.local.toml`

If you want the old "just run everything under `.local/`" behavior, use the repo-owned helper:

```bash
bash scripts/run_all_local_pcaps.sh
```

Optional:

```bash
bash scripts/run_all_local_pcaps.sh --quick
bash scripts/run_all_local_pcaps.sh --force
```

## Important Limits

By default `detail.json` contains the first **1,000 packets**. Use
`--all-packets` to remove the limit or `--max-packets N` to set a custom value.

The pipeline uses **two passes**:

- pass 1 scans all packets as lightweight field data (low memory)
- pass 2 exports full JSON only for the selected packet window — memory is proportional to `--max-packets`, not the full capture

Important consequence: **pass 1 still scans the entire capture**. A large
rolling trace with a 500-packet limit still requires a full pass-1 scan and
produces only the first 500 packets as output. The remedy is a tighter `-Y`
filter, not a bigger limit.

Practical rule:

- Run `inspect` first on unknown captures.
- Narrow with `-Y` until the packet set is actually useful.
- Enable `--two-pass` when SIP/TCP or HTTP/2 reassembly matters.

## Privacy

Privacy is controlled per data class. The built-in privacy profiles cover the
most common cases:

| Privacy profile | What it does |
|---|---|
| `internal` | Keep everything as-is |
| `share` | Pseudonymize subscriber IDs (IMSI, MSISDN), remove tokens |
| `lab` | Pseudonymize all subscriber data, mask IPs |
| `prod-safe` | Maximum protection — mask IPs, pseudonymize all PII, remove tokens/email/URI |

```bash
pcap2llm analyze trace.pcapng --profile lte-core --privacy-profile share --out ./artifacts
```

Full privacy guidance: [`docs/PRIVACY_SHARING.md`](docs/PRIVACY_SHARING.md)

## Troubleshooting

**`tshark was not found in PATH`**

Install Wireshark/TShark and ensure it is on PATH.

- macOS: `brew install wireshark`
- Ubuntu: `sudo apt install tshark`
- Custom path: `pcap2llm analyze sample.pcapng --tshark-path /usr/local/bin/tshark`

**`tshark output is not valid JSON`**

Usually an old TShark version (< 3.6) or a corrupt capture. Upgrade TShark or
re-capture.

**`detail.json` has fewer packets than expected`**

Check `summary.json` for coverage or truncation and tighten the display filter
before increasing limits.

**Empty `detail.json`**

Try without `-Y` first and confirm that the chosen profile family matches the
traffic.

## Documentation

| Document | What it covers |
|---|---|
| **README.md** (this file) | Overview, quick start, limits, navigation |
| [`docs/REFERENCE.md`](docs/REFERENCE.md) | Complete English command and option reference |
| [`docs/PROFILES.md`](docs/PROFILES.md) | Profile navigation and custom profile authoring |
| [`docs/PROFILES_LTE.md`](docs/PROFILES_LTE.md) | LTE / EPC profile family reference |
| [`docs/PROFILES_5G.md`](docs/PROFILES_5G.md) | 5G SA core profile family reference |
| [`docs/PROFILES_VOICE.md`](docs/PROFILES_VOICE.md) | VoLTE / VoNR / IMS profile family reference |
| [`docs/PROFILES_2G3G.md`](docs/PROFILES_2G3G.md) | 2G/3G core / GERAN profile family reference |
| [`docs/QUICKSTART_DE.md`](docs/QUICKSTART_DE.md) | German quick start |
| [`docs/ANLEITUNG_DE.md`](docs/ANLEITUNG_DE.md) | German guide |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | Step-by-step workflows |
| [`docs/LLM_MODE.md`](docs/LLM_MODE.md) | Machine-readable JSON mode for automation |
| [`docs/DISCOVERY.md`](docs/DISCOVERY.md) | Discovery mode and scout artifacts |
| [`docs/PROFILE_SELECTION.md`](docs/PROFILE_SELECTION.md) | Deterministic profile recommendation and selector metadata |
| [`docs/SESSIONS.md`](docs/SESSIONS.md) | Multi-run session orchestration and manifests |
| [`docs/schema/`](docs/schema/) | JSON schema reference |

## Development

```bash
pytest
ruff check .
```

## License

Apache License 2.0 — Copyright (c) 2026 Frank März
