# Sessions

Sessions let external agents or scripts stitch multiple `pcap2llm` runs into
one structured analysis trail.

Use them when you want:

- a discovery run plus several focused follow-ups
- explicit run-to-run relationships
- machine-readable outputs per step
- a final manifest and a short session report

## Typical Session Flow

```bash
pcap2llm session start trace.pcapng --out ./artifacts
pcap2llm session run-discovery --session ./artifacts/20260410_173000_session
pcap2llm session run-profile \
  --session ./artifacts/20260410_173000_session \
  --profile lte-s11 \
  --triggered-by 00_discovery \
  --reason "gtpv2 detected"
pcap2llm session finalize --session ./artifacts/20260410_173000_session
```

## Directory Layout

Example:

```text
artifacts/
  20260410_173000_session/
    session_manifest.json
    session_report.md
    00_discovery/
      discovery.json
      discovery.md
    01_lte-s11/
      20260410_102458_summary_V_01.json
      20260410_102458_detail_V_01.json
      20260410_102458_summary_V_01.md
```

## Manifest Structure

The exact shape can evolve, but the current manifest keeps:

- `session_id`
- `status`
- `created_at`, `updated_at`, optional `finished_at`
- `input_capture.path`
- `input_capture.sha256`
- `runs[]`

Each run records, as applicable:

- `run_id`
- `mode`
- `profile`
- `status`
- `started_at`, `finished_at`
- `triggered_by`
- `reason`
- `tag`
- `notes`
- `overrides`
- `outputs`
- `warnings`
- `error`

## Discovery Runs

`session run-discovery` creates a numbered discovery step such as
`00_discovery` and stores the same artifacts as standalone discovery mode:

- `discovery.json`
- `discovery.md`

The run is appended to `session_manifest.json` with its current state.

## Profile Runs

`session run-profile` executes one focused analysis inside the session and
records why it happened.

Useful orchestration fields:

- `--triggered-by 00_discovery` to point back to the parent step
- `--reason ...` to store human or agent rationale
- `--tag ...` for a short orchestrator label
- `--notes ...` for free-text context
- `--verbatim-protocol` and `--no-verbatim-protocol` for one-run protocol detail tuning

Current scope:

- profile runs record structural overrides such as two-pass and verbatim changes
- the session helper currently runs with default privacy behavior unless you do a standalone `analyze` with more specific privacy or mapping options

## Finalization

`session finalize` updates the session status and writes `session_report.md`.

Typical statuses:

- `completed`
- `failed`

The report is meant as a light human recap. The manifest is the authoritative
machine-readable source.

## Design Principle

Sessions make `pcap2llm` orchestratable without turning it into a hidden agent.

The tool provides:

- deterministic primitives
- explicit run state
- traceable outputs

The external orchestrator still decides:

- which recommendation to trust
- which follow-up profile to run
- whether to branch, retry, or stop
