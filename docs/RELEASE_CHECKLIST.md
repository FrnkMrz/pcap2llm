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

Restored feature regression review:

- Analyze profile selector still shows grouped transport, 2G/3G, 4G/EPC, 5G, Voice/IMS, and DNS views
- Transport profiles are still present and selectable: `transport-core`, `transport-tcp`, `transport-udp`, `transport-sctp`
- Privacy Profiles page still supports built-in editing flow with `Save Local Override` and `Reset to Built-in`
- Built-in privacy overrides are still applied during analyze runs, not only displayed in the UI
- IMSI partial privacy modes still work end-to-end: `keep_mcc_mnc_mask_msin`, `keep_mcc_mnc_pseudonymize_msin`, `keep_mcc_mnc_encrypt_msin`
- MSISDN partial privacy modes still work end-to-end: `keep_cc_ndc_mask_subscriber`, `keep_cc_ndc_pseudonymize_subscriber`, `keep_cc_ndc_encrypt_subscriber`
- Root-level runtime profile artifacts under `profiles/` are not tracked in git
- Cross-platform web runner path still works on Windows, macOS, and Linux via `python -m pcap2llm`
