# Golden Corpus

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`schema/detail.schema.md`](schema/detail.schema.md)
- [`schema/summary.schema.md`](schema/summary.schema.md)
- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)

The golden corpus under `tests/fixtures/golden/` is the reviewable regression surface for public artifact behavior.

## What Each Fixture Contains

Each fixture directory contains:

- `scenario.json`: profile, privacy settings, description, and sanitization note
- `raw_packets.json`: sanitized surrogate input representing the extracted packet stream
- `expected_summary.json`
- `expected_detail.json`

## Sanitization Rules

Before data may enter the corpus, remove or transform:

- subscriber identifiers
- sensitive IPs or hostnames
- credentials, tokens, and cookies
- customer content

Each fixture must record the sanitization approach in `scenario.json`.

## Refreshing Expected Outputs

Refresh all fixtures intentionally:

```bash
python scripts/update_golden.py --force
```

Refresh only one fixture:

```bash
python scripts/update_golden.py --force lte_attach_success
```

The script refuses silent overwrite unless `--force` is given.

## When To Update The Corpus

- serializer changes
- schema changes
- privacy policy behavior changes
- deterministic summary behavior changes

If a golden output changes, review the diff as a product change, not as incidental test noise.
