# Release Checklist

Use this checklist to verify that a release is consistent across packaging,
tests, schemas, corpus snapshots, and user-facing documentation.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROJECT_STATUS.md`](PROJECT_STATUS.md)
- [`golden_corpus.md`](golden_corpus.md)
- [`schema/detail.schema.md`](schema/detail.schema.md)
- [`schema/summary.schema.md`](schema/summary.schema.md)

Automated in CI:

- License and package metadata verified in built wheel and sdist
- CI green on supported Python versions
- Packaging build succeeds
- Package metadata validation passes
- Schema validation tests pass
- Golden regression tests pass
- Privacy and encryption tests pass

Manual release review:

- Golden corpus changes are intentionally reviewed when snapshots move
- Docs are updated for any behavior or contract change
- Known limitations still match actual behavior
- Release notes / changelog entries reflect user-visible changes
