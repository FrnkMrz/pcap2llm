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

## Default subnet fallback file

Place your whitespace-delimited subnet fallback file at:

```
.local/Subnets
```

The tool loads it automatically if it exists. It is used only when no exact
IP or hostname match was found from hosts or mapping files.

## Default SS7 point-code file

Place your whitespace-delimited SS7 point-code alias file at:

```
.local/ss7pcs
```

The tool loads it automatically if it exists. It is used as an SS7 fallback
for MTP3 OPC/DPC values when no higher-priority IP or hostname mapping exists.

## Repo-owned local batch runner

The committed runner now lives in the repo, not under `.local/`.

Use it like this from the repo root:

```bash
bash scripts/run_all_local_pcaps.sh
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --list
python3 scripts/run_local_batches.py --batch batches/local_examples.toml
```

The runner and batch definitions are versioned in the repo:

- `scripts/run_all_local_pcaps.sh`
- `scripts/run_local_batches.py`
- `batches/local_examples.toml`

But the real inputs and outputs stay local-only:

- captures such as `.local/PCAPs/...`
- helper files such as `.local/hosts`
- one-shot run output under `.local/runs/`
- curated batch output under `.local/results/...`

Useful variants:

```bash
bash scripts/run_all_local_pcaps.sh --quick
bash scripts/run_all_local_pcaps.sh --force
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --case inspect_volte_mixed_trace
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --dry-run
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --output-root .local/results/tmp
```

Use `run_all_local_pcaps.sh` when you want the old one-shot "scan everything in `.local/` and run it" flow.
It runs `discover`, `inspect`, and `analyze` for each `.pcap`/`.pcapng`,
auto-selects the top discovery profile, uses the local-only `internal` privacy
profile, and renders `flow.json` plus `flow.svg` for each analyzed capture.
The generated `.local/runs/RESULTS.md` includes a flow overview and short event
samples from each `flow.json`.

Use `run_local_batches.py` when you want a curated, versioned set of named cases.

## What belongs here

- `.local/hosts` — Wireshark hosts mapping
- `.local/Subnets` — CIDR fallback mappings for roaming partner or cluster IP ranges
- `.local/ss7pcs` — SS7 point-code aliases for OPC/DPC-based peer naming
- `.local/PCAPs/...` — local captures for one-shot batch runs
- `.local/runs/...` — local `run_all_local_pcaps.sh` output, including flow artifacts
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
