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
  "artifact_prefix": "analyze_sample_start_1",
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
    "fail_on_truncation": false,
    "oversize_factor": 10.0
  },
  "schema_versions": {
    "summary": "1.0",
    "detail": "1.0"
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

Warnings are structured objects in the `warnings` array. Each has a `code` and a `message`.

| Warning code | When it appears | Suggested next action |
|---|---|---|
| `full_load_ingestion_applies` | Always — every success run | Informational. Pass 1 scans all packets as lightweight field data; pass 2 exports full JSON only for selected packets. Use focused captures and `-Y` filters for large inputs. |
| `detail_truncated` | `total_exported > max_packets` | Re-filter with `-Y` to narrow to the relevant call flow. Do **not** just raise `--max-packets`. |
| `capture_size_guard_disabled` | `--max-capture-size-mb 0` was set | Verify the operator intended this. Flag for human review in automated pipelines. |
| `oversize_guard_disabled` | `--oversize-factor 0` was set | Same as above — guard bypass should be intentional. |
| `no_relevant_protocols_detected` | No profile-relevant protocols in the capture | Re-check `--profile` matches traffic type. Run `inspect` without `-Y` to see what TShark sees. |
| `pseudonym_mapping_created` | Pseudonymization produced a mapping sidecar | Keep `pseudonym_mapping.json` separate. Do **not** forward it with the artifact set. |
| `encrypted_output_requires_key_handling` | Encryption was active | `PCAP2LLM_VAULT_KEY` must be managed separately. Never pass it with the artifact. |

## Typical Automation Flow

### When to inspect first vs. direct analyze

| Situation | Approach |
|---|---|
| Unknown capture, source unclear | `inspect` first to check protocol mix and packet count |
| Large trace, unsure of filter | `inspect` with candidate `-Y` filter, then `analyze` |
| Known capture, focused call flow | Direct `analyze --llm-mode` is fine |

### Step-by-step pattern

```bash
# 1 — inspect if capture is unknown
pcap2llm inspect trace.pcapng --profile lte-core

# 2 — narrow filter if needed (check packet count from inspect)
# 3 — run analyze in LLM mode
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  --privacy-profile share \
  --llm-mode \
  --out ./artifacts
```

### Reading the result

```json
{
  "status": "ok",
  "mode": "llm",
  "profile": "lte-core",
  "privacy_profile": "share",
  "capture": { "path": "trace.pcapng", "sha256": "..." },
  "files": {
    "detail": "artifacts/analyze_trace_start_1_V_01_detail.json",
    "summary": "artifacts/analyze_trace_start_1_V_01_summary.json",
    "markdown": "artifacts/analyze_trace_start_1_V_01_summary.md"
  },
  "coverage": {
    "detail_packets_included": 312,
    "detail_packets_available": 312,
    "detail_truncated": false
  },
  "warnings": [
    { "code": "full_load_ingestion_applies", "message": "..." }
  ]
}
```

**What to check first:**

1. `status` — `"ok"` or `"error"`. On error, read `error.code` for a machine-actionable response.
2. `coverage.detail_truncated` — if `true`, the detail artifact is a slice. Consider refining the filter before passing to an LLM.
3. `warnings` — check for `no_relevant_protocols_detected` (wrong profile or filter too strict) or `pseudonym_mapping_created` (keep the mapping file separate).
4. `files.detail` — this is the primary artifact to pass to the downstream LLM.

`artifact_prefix` is now the semantic filename prefix, not a timestamp. It reflects action, capture name, and start packet.

### On error

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

Map `error.code` to an automated response:

| Code | Automated response |
|---|---|
| `capture_too_large` | Reject; ask operator to narrow the capture or raise `--max-capture-size-mb` deliberately |
| `capture_oversize` | Reject; export was far larger than the detail limit — re-filter with `-Y` before retrying |
| `tshark_missing` | Abort pipeline; alert on missing dependency |
| `missing_vault_key` | Abort; request `PCAP2LLM_VAULT_KEY` from secret store |
| `invalid_vault_key` | Abort; key format is wrong — generate a new Fernet key |
| `invalid_tshark_json` | Abort; TShark version may be too old (< 3.6) or capture is corrupt |
| `tshark_failed` | Abort; surface `error.message` — likely a bad display filter or corrupt file |
| `detail_truncated_and_disallowed` | Reject; `--fail-on-truncation` was set — tighten `-Y` filter and retry |
| `artifact_write_failed` | Abort; surface `error.message` — disk full or permissions issue |
| `runtime_error` | Unexpected; surface full `error.message` for human investigation |

---

## Orchestrator Next Action

Use this table to decide what to do after receiving any result.

| Condition | Next action |
|---|---|
| `status == "ok"`, no warnings | Pass `files.detail` to downstream LLM |
| `status == "ok"` + `detail_truncated` warning | Narrow with `-Y` and retry before forwarding — truncated detail is a slice of the call flow |
| `status == "ok"` + `no_relevant_protocols_detected` | Re-check `--profile`; run `inspect` without `-Y` to see what TShark sees |
| `status == "ok"` + `oversize_guard_disabled` | Verify the bypass was intentional; flag for human review in automated pipelines |
| `error.code == "capture_too_large"` | Reject; ask operator for smaller capture or stricter `-Y` filter |
| `error.code == "capture_oversize"` | Keep capture, re-filter with stricter `-Y`, retry |
| `error.code == "tshark_missing"` | Abort pipeline; alert on missing dependency — no retry will help |
| `error.code == "missing_vault_key"` or `"invalid_vault_key"` | Stop; request valid `PCAP2LLM_VAULT_KEY` from secret store |
| `error.code == "artifact_write_failed"` | Retry only after storage/permissions issue is resolved |
| `error.code == "detail_truncated_and_disallowed"` | Tighten `-Y` filter and retry — do **not** raise `--max-packets` |

### Safe automated behaviors

These actions are safe to perform without human review:

- **Retry** after `artifact_write_failed` once the storage or permissions issue is resolved
- **Re-filter and retry** after `detail_truncated` — tighten `-Y` before retrying
- **Stop immediately** on `tshark_missing` — no retry will help; alert on missing dependency
- **Abort and request key** on `missing_vault_key` or `invalid_vault_key` — do not retry with the same credentials
- **Pass** `files.detail` to downstream LLM on `status == "ok"` with no warnings

### Human review recommended

Pause and escalate to a human in these situations:

- **Guard bypasses active**: `capture_size_guard_disabled` or `oversize_guard_disabled` warnings are present — verify the bypass was intentional before forwarding artifacts
- **No relevant protocols**: `no_relevant_protocols_detected` — the profile or filter may be wrong; a human should confirm the capture content before proceeding
- **Privacy boundary unclear**: the capture is going outside the originating team, but the effective `privacy_modes` in `summary.json` have not been reviewed
- **Mapping sidecar present**: `pseudonym_mapping_created` warning — confirm the mapping file is NOT included in the artifact set before sharing

### When to run `inspect` before `analyze --llm-mode`

Prefer `inspect` first when:
- the capture source is unknown or unfamiliar
- the protocol mix is not confirmed
- the capture is large (more than a few hundred packets expected)
- no display filter has been validated yet
- it is the first run against a new capture source

`inspect` is cheap and avoids a full `analyze` run on a capture that will fail the oversize guard or produce no relevant output.

---

## Dry Run

`--llm-mode --dry-run` returns a machine-readable plan JSON and does not write artifacts.

```json
{
  "status": "ok",
  "mode": "llm",
  "dry_run": true,
  "capture": { "path": "trace.pcapng" },
  "profile": "lte-core",
  "privacy_profile": "share",
  "display_filter": "diameter",
  "limits": {
    "max_packets": 1000,
    "all_packets": false,
    "fail_on_truncation": false,
    "max_capture_size_mb": 250,
    "oversize_factor": 10.0
  },
  "privacy_modes": {},
  "files_would_be_written": true,
  "hosts_file": null,
  "mapping_file": null,
  "command": ["tshark", "-n", "-r", "trace.pcapng", "-T", "json", "-Y", "diameter"]
}
```

## Limits

- still a local CLI tool
- not a Python API
- not an MCP/server integration
- two-pass ingestion: pass 1 scans all packets as lightweight field data (low memory); pass 2 exports full JSON only for the selected packet window — memory is proportional to `--max-packets`, not the full capture
- pass 1 still scans the full capture: a large rolling trace still requires a full pass-1 scan; the remedy is a tighter `-Y` filter, not a bigger `--max-packets`
- still best for focused captures
- reasoning remains the responsibility of the downstream LLM or orchestrator
