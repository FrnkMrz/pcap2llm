# Local-only files

This directory is reserved for local, sensitive, or developer-specific files.

**Do not commit real files stored here.**

This directory is ignored by Git except for this README and `.gitkeep`.

## Default hosts file

Place your Wireshark-style hosts file at:

```
.local/hosts
```

The tool loads it automatically if it exists. No CLI argument is required.

## Batch runner for all local traces

Use this script when you want one command that runs `discover`, `inspect`, and
`analyze` for every `.pcap` and `.pcapng` file anywhere under `.local/`:

```bash
bash .local/run_all_traces.sh
```

Useful variants:

```bash
bash .local/run_all_traces.sh --quick
bash .local/run_all_traces.sh --force
```

- `--quick` runs only `discover` + `inspect`
- `--force` re-runs traces even if a run folder already exists

Results are written to:

```text
.local/runs/
```

Each trace gets its own folder with discovery, inspect, and analyze outputs,
plus a combined overview in:

```text
.local/runs/RESULTS.md
```

Notes:

- the script auto-detects the best profile from discovery output
- `.local/hosts` is passed automatically when present
- `.local/runs/` is excluded from the scan, so generated outputs are never
  treated as input traces

## What belongs here

- `.local/hosts` — Wireshark hosts mapping
- local mapping tables (YAML/JSON)
- anonymization dictionaries
- raw trace files used for local testing
- temporary analysis outputs not meant for Git

## What does not belong here

Real files stored in `.local/` must never be staged or committed.
Git ignore rules, pre-commit hooks, and CI checks all enforce this.

## Safety note

`.gitignore`, pre-commit hooks, and CI together strongly reduce the risk of
accidental publication. This is not an absolute guarantee against intentional
bypass — a file stored inside the repository tree is not as isolated as a file
stored fully outside of it.
