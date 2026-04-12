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

## Repo-owned local batch runner

The committed runner now lives in the repo, not under `.local/`.

Use it like this from the repo root:

```bash
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --list
python3 scripts/run_local_batches.py --batch batches/local_examples.toml
```

The runner and batch definitions are versioned in the repo:

- `scripts/run_local_batches.py`
- `batches/local_examples.toml`

But the real inputs and outputs stay local-only:

- captures such as `.local/PCAPs/...`
- helper files such as `.local/hosts`
- result directories such as `.local/results/...`

Useful variants:

```bash
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --case inspect_volte_mixed_trace
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --dry-run
python3 scripts/run_local_batches.py --batch batches/local_examples.toml --output-root .local/results/tmp
```

This keeps the run catalog reviewable in Git while preventing local PCAPs and generated artifacts from being tracked.

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
