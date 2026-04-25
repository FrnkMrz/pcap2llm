# Web GUI

`pcap2llm` includes an optional locally hosted Web GUI for upload-driven review,
reruns, and artifact inspection.

## Start

```bash
pcap2llm-web
```

Alternative:

```bash
python -m pcap2llm.web.app
```

Default URL:

```text
http://127.0.0.1:8765
```

## Local Sanity Check

For local Web GUI changes, this is the smallest useful verification flow:

```bash
python3 -m venv .venv
./.venv/bin/pip install -e '.[dev]'
./.venv/bin/ruff check .
./.venv/bin/python -m pytest tests/web/test_jobs.py tests/web/test_profiles.py tests/web/test_security_validation.py tests/web/test_pcap_runner.py tests/web/test_profiles_routes.py tests/web/test_web_upload.py
./.venv/bin/python -m pytest tests/test_resolver_extended.py
bash scripts/smoke_test_web_gui.sh
```

The smoke test starts the Web GUI locally, checks the main HTML routes, and
exercises a real upload through the job page.

## Typical Workflow

1. Upload a capture (`.pcap` or `.pcapng`).
2. Optionally run discovery.
3. Review the recommended profile or choose one manually.
4. Run analyze.
5. Inspect artifacts, flow preview, and logs.
6. Download only the files you need.

## Analyze UI Capabilities

Currently exposed in the Analyze form:

- `profile`
- `privacy-profile`
- `display-filter`
- `max-packets`
- `all-packets`
- `fail-on-truncation`
- `max-capture-size-mb`
- `oversize-factor`
- `render-flow-svg`
- `flow-title`
- `flow-max-events`
- `flow-svg-width`
- `collapse-repeats`
- `hosts-file`
- `mapping-file`
- `subnets-file`
- `ss7pcs-file`
- helper files as per-job uploads under `input/support/`
- `tshark-path`
- `two-pass`

## Analyze Option Notes

- `max-packets`: limits how many packets are written to `detail.json`.
- `Export all packets to detail.json`: removes that limit. Use only for small,
  already well-filtered captures.
- `Fail if the detail export would be cut off`: aborts the run if `detail.json`
  would otherwise contain only the first N packets.
- `Better TShark reassembly for fragmented traffic`: enables TShark two-pass
  dissection. This is especially useful for HTTP/2, SIP, Diameter, and other
  fragmented or reassembled traffic, but may cost extra runtime.
- `Render flow diagram`: adds `flow.json` and `flow.svg`.
- `Merge repeated messages`: collapses adjacent identical flow events into `xN`
  markers.

## Environment Variables

- `PCAP2LLM_WEB_HOST` (default `127.0.0.1`)
- `PCAP2LLM_WEB_PORT` (default `8765`)
- `PCAP2LLM_WEB_WORKDIR` (default `./web_runs`)
- `PCAP2LLM_WEB_MAX_UPLOAD_MB` (default `1`)
- `PCAP2LLM_WEB_COMMAND_TIMEOUT_SECONDS` (default `600`)
- `PCAP2LLM_WEB_TSHARK_PATH` (optional)
- `PCAP2LLM_WEB_DEFAULT_PRIVACY_PROFILE` (default `share`)
- `PCAP2LLM_WEB_CLEANUP_ENABLED` (default `true`) to enable automatic cleanup of
  old jobs
- `PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS` (default `7`) to delete jobs older than N
  days

## Local `.local` Defaults

When the Web GUI runs against a local workspace, it follows the same helper
file conventions as the CLI:

- `.local/hosts`
- `.local/Subnets`
- `.local/ss7pcs`
- optional `.local/mapping.yaml`, `.local/mapping.yml`, or `.local/mapping.json`

If you start the app with `PCAP2LLM_WEB_WORKDIR=.local/web_runs`, these paths
are prefilled automatically in the Analyze form and applied even without manual
entry.

Local privacy profiles are stored in `.local/profiles/` in that mode and are
loaded again on restart. Older profiles from the legacy path
`.local/web_runs/profiles/` are migrated automatically.

## Job Layout

```text
<workdir>/<job_id>/
  job.json
  input/
  discovery/
  artifacts/
  logs/
```

## Security

- Local bind by default (`127.0.0.1`)
- Accepts only `.pcap` and `.pcapng`
- Configurable upload size limit
- Sanitized filenames
- Downloads scoped to the current job directory
- No external API calls from the Web GUI itself
- security headers:
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `X-XSS-Protection`
  - `Referrer-Policy`
- input validation:
  - profile names: alphanumeric, `_`, `-`, spaces, `.`, length `1..255`
  - descriptions: max 1000 characters
  - protection modes limited to supported values such as `keep`, `mask`,
    `pseudonymize`, `encrypt`, `remove`

## Known Security Gaps

See [docs/SECURITY_AUDIT_WEB_GUI.md](SECURITY_AUDIT_WEB_GUI.md) for details.

- missing CSRF protection
- missing authentication and authorization
- missing rate limiting
- path traversal prevention is implemented
- file upload validation is implemented
- input validation and length limits are implemented
- security headers are implemented

This app is designed for local-only use by default. Remote or production-facing
deployment needs additional hardening.

## Logs

Discovery and analyze runs write separate log files:

- `logs/discovery_stdout.log`
- `logs/discovery_stderr.log`
- `logs/discovery_command.json`
- `logs/recommend_stdout.log`
- `logs/recommend_stderr.log`
- `logs/recommend_command.json`
- `logs/analyze_stdout.log`
- `logs/analyze_stderr.log`
- `logs/analyze_command.json`

On the job page, the logs panel is collapsed by default so it stays out of the
way until you intentionally open it for troubleshooting or auditability.

## Downloads

- consolidated file list on the job page with section (`artifacts`,
  `discovery`, `logs`) and size
- scoped download route: `/jobs/<job_id>/files/<section>/<filename>`
- Markdown artifacts (`*.md`) can be viewed inline in the browser
- ZIP bundle via `/jobs/<job_id>/files.zip` including `artifacts/`,
  `discovery/`, and `logs/`

## UX Details

- the Analyze form remembers the last values used for that job
- failures show both a human-readable message and a machine-readable error code
- `Delete job` removes the full job directory
- dashboard available at `/dashboard` with job and privacy-profile statistics
- jobs can be multi-selected and deleted from the start page
- Telekom-inspired magenta/neutral visual theme with active navigation states,
  consistent focus rings, and shared light/dark color tokens
- dark-mode toggle in the header persists via `localStorage`
- responsive layout for smaller screens
- the flow preview is rendered inline as interactive SVG, not as a static image
- hover works directly in the page preview and still works after downloading the
  SVG
- the flow preview uses a larger scrollable viewer so wide sequence diagrams are
  readable without cranking up browser zoom
- privacy-profile choices in the Analyze form are sized more compactly to their
  content

## Automatic Cleanup

Enabled by default. On app startup, jobs older than
`PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS` are deleted. The default is 7 days.

### Disable Cleanup

```bash
export PCAP2LLM_WEB_CLEANUP_ENABLED=false
pcap2llm-web
```

### Configure Cleanup Behavior

```bash
export PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS=14
export PCAP2LLM_WEB_CLEANUP_ENABLED=true
pcap2llm-web
```

### Trigger Cleanup Manually

```bash
curl -X POST http://127.0.0.1:8765/admin/cleanup
# response: {"status": "ok", "deleted_jobs": 2, "max_age_days": 7}
```

With an explicit override:

```bash
curl -X POST http://127.0.0.1:8765/admin/cleanup -H "Content-Type: application/json" -d '{"max_age_days": 1}'
# response: {"status": "ok", "deleted_jobs": 5, "max_age_days": 1}
```

If `PCAP2LLM_WEB_CLEANUP_ENABLED=false`, startup cleanup does not run, but the
admin API remains available.

## Privacy Profiles

The page `http://127.0.0.1:8765/profiles` manages privacy profiles for the Web
GUI.

### Supported Actions

- view built-in privacy profiles such as `internal`, `share`, `lab`,
  `prod-safe`, and `llm-telecom-safe`
- duplicate a built-in profile as a local editable profile
- create a new local profile
- edit a local profile
- save changes
- delete a local profile
- duplicate a local profile
- bulk-delete local profiles
- export local profiles as JSON or CSV
- search local profiles by name or description

### Editable Fields

General fields:

- unique profile name
- description

Per-data-class handling rules:

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

Supported protection modes depend on the data class. Common values include:

- `keep`
- `mask`
- `pseudonymize`
- `encrypt`
- `remove`

For IMEI, the UI also exposes the specialized mode:

- `keep_tac_mask_serial`

This IMEI-only mode keeps the TAC prefix visible and masks the serial suffix.
It is not an email-specific mode. Email addresses use only the standard modes:
`keep`, `mask`, `pseudonymize`, `encrypt`, or `remove`.

### API Endpoints

List all local profiles as JSON:

```bash
curl http://127.0.0.1:8765/api/profiles
```

Export profiles as JSON:

```bash
curl -L "http://127.0.0.1:8765/profiles/export?fmt=json" -o privacy_profiles.json
```

Export profiles as CSV:

```bash
curl -L "http://127.0.0.1:8765/profiles/export?fmt=csv" -o privacy_profiles.csv
```

## Current Limits

- no user management
- no database backend
- no direct external LLM integration from the Web GUI

## Further Reading

- network-element detection: [docs/NETWORK_ELEMENT_DETECTION.md](NETWORK_ELEMENT_DETECTION.md)
- English reference: [docs/REFERENCE.md](REFERENCE.md)
- Web GUI security audit: [docs/SECURITY_AUDIT_WEB_GUI.md](SECURITY_AUDIT_WEB_GUI.md)
