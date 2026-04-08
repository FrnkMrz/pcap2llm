# LLM Mode

`pcap2llm` remains a local CLI tool. `--llm-mode` makes it easier for an external orchestrator or agent to call the tool reliably without turning it into a service, SDK, or MCP integration.

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
