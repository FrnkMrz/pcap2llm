# LLM Preparation And LLM Mode

`pcap2llm` remains a local CLI tool. Its role is LLM preparation: turning a telecom trace into stable, privacy-aware artifacts that can be passed to a downstream LLM. `--llm-mode` makes that preparation flow easier for an external orchestrator or agent to call reliably without turning the tool into a service, SDK, or MCP integration.

## Where The LLM Preparation Happens

- `detail.json` is the primary LLM handoff artifact
- `summary.json` is the structured sidecar for coverage, counts, anomalies, and privacy metadata
- `summary.md` is the human-readable sidecar
- `--llm-mode` only changes the CLI return format; it does not change the artifact semantics

## Purpose

- strict JSON result on stdout
- deterministic artifact generation stays unchanged
- machine-readable warnings and errors
- no generative reasoning inside `pcap2llm`

## Success Shape

Typical success payload:

```json
{
  "status": "ok",
  "mode": "llm",
  "profile": "lte-core",
  "privacy_profile": "share",
  "capture": {
    "path": "sample.pcapng",
    "sha256": "..."
  },
  "artifact_prefix": "20240406_075320",
  "artifact_version": 1,
  "files": {
    "summary": "artifacts/...summary...",
    "detail": "artifacts/...detail...",
    "markdown": "artifacts/...summary.md",
    "mapping": null,
    "vault": null
  },
  "coverage": {
    "detail_packets_included": 312,
    "detail_packets_available": 312,
    "detail_truncated": false,
    "summary_packet_count": 312,
    "truncation_note": null
  },
  "warnings": [],
  "limits": {
    "max_packets": 1000,
    "all_packets": false,
    "max_capture_size_mb": 250,
    "fail_on_truncation": false
  }
}
```

## Error Shape

Typical failure payload:

```json
{
  "status": "error",
  "mode": "llm",
  "error": {
    "code": "capture_too_large",
    "message": "capture file is 412.7 MiB, which exceeds --max-capture-size-mb 250"
  }
}
```

## Warning Model

Warnings are structured objects such as:

- `detail_truncated`
- `capture_size_guard_disabled`
- `no_relevant_protocols_detected`
- `pseudonym_mapping_created`
- `encrypted_output_requires_key_handling`
- `full_load_ingestion_applies`

## Dry Run

`--llm-mode --dry-run` returns a machine-readable plan JSON and does not write artifacts.

## Limits

- still a local CLI tool
- not a Python API
- not an MCP/server integration
- still not streaming ingestion
- still best for focused captures
- reasoning remains the responsibility of the downstream LLM or orchestrator
