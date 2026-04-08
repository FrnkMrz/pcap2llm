# Release Checklist

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
