# Privacy Modes And Safe Sharing

Use this page when you need to choose a privacy profile or decide which
artifacts can safely leave the trusted boundary.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`REFERENCE.md`](REFERENCE.md)
- [`privacy_coverage.md`](privacy_coverage.md)
- [`security/threat_model.md`](security/threat_model.md)
- [`security/encryption_model.md`](security/encryption_model.md)
- [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md)

## Choose A Profile For Your Scenario

| Scenario | Recommended profile | Notes |
|---|---|---|
| Internal team troubleshooting | `share` | Good default for most internal work |
| Vendor ticket | `prod-safe` | Remove tokens, reduce sensitive metadata |
| Lab replay / test environment | `lab` | Stronger anonymization, still useful context |
| Personal local analysis | `internal` | Only in fully trusted environments |
| LLM sharing outside trusted boundary | `llm-telecom-safe` | Keeps topology correlation through pseudonyms without exposing raw endpoints |

```bash
pcap2llm analyze trace.pcapng --profile lte-core --privacy-profile share --out ./artifacts
```

---

## What To Share And What Not To Share

| Artifact | Sensitivity | Guidance |
|---|---|---|
| `detail.json` | **Sensitive by default** | Contains packet-level data. Always check effective privacy modes before sharing. |
| `summary.json` | Lower, but check | Protocol counts, anomalies, timing — verify effective modes first. |
| `summary.md` | Easiest to share | Human-readable, but still check if subscriber IDs appear. |
| `flow.json` | Similar to protected detail slice | Optional. Derived from protected packets, but can expose endpoint labels, DNS names, APN/DNN context, and failure causes. Review before sharing. |
| `flow.svg` | Human-readable visual sidecar | Optional. Good for local review and tickets after privacy verification; inspect labels/tooltips before attaching. |
| `pseudonym_mapping.json` | **Never share with artifact** | Maps pseudonyms back to real values. Must stay separate from the artifact set. |
| `vault.json` | **Not a recovery package** | Contains encryption metadata only, not the key. Useless without `PCAP2LLM_VAULT_KEY`. |

**`PCAP2LLM_VAULT_KEY` must never travel with the artifacts.** Not in the same ticket, not in the same chat, not in the same archive.

---

## Safe-Sharing Workflow

1. **Choose a privacy profile** — use the table above to pick `share`, `prod-safe`, `llm-telecom-safe`, `lab`, or `internal`
2. **Run analyze** — check that the command includes `--privacy-profile <chosen>`
3. **Verify the effective output** — open `summary.json` and read the `privacy_modes` block; the profile name alone does not tell you what actually ran (see note below)
4. **Verify optional sidecars** — if `flow.json` / `flow.svg` were created, inspect their labels and tooltips; if `pseudonym_mapping.json` was created, keep it separate; if `vault.json` was created, confirm the key is stored outside the share path
5. **Share only what is needed** — for vendor tickets: `summary.json` + `summary.md` are often enough; attach `detail.json` only if the vendor needs packet-level data

> **Effective policy beats intended policy.** The profile name you pass is only the starting point. Config file overrides and CLI `--*-mode` flags can change individual class modes without changing the profile name. Always read `privacy_modes` in `summary.json` to confirm what actually applied before sharing.

---

## Encryption vs. Pseudonymization

**Pseudonymization** (`pseudonymize` mode) replaces sensitive values with stable, hash-based aliases like `IMSI_a3f2b1c4`. The real value is not stored anywhere in the artifact. Pseudonyms are consistent across runs. This is the right choice for most sharing scenarios.

**Encryption** (`encrypt` mode) transforms sensitive values with Fernet encryption using `PCAP2LLM_VAULT_KEY`. The encrypted artifact is unreadable without the key. Use encryption when you need to retain the real values for later decryption — for example, internal archival or audit retention.

**Encryption does not make casual sharing safe.** If you share an encrypted artifact and the key is shared separately later, the data is fully recoverable. Pseudonymization is the safer choice when you want irreversible protection for the shared artifact.

---

## Common Mistakes

- **Sharing `pseudonym_mapping.json` with the artifact set.** This file maps pseudonyms back to real subscriber IDs and IP addresses. Sharing it alongside `detail.json` undoes all pseudonymization.
- **Assuming `vault.json` is a recovery package.** It contains key metadata only — not the key itself. An encrypted artifact is unreadable without `PCAP2LLM_VAULT_KEY` stored separately.
- **Using `share` when `prod-safe` or `llm-telecom-safe` is more appropriate.** `share` is a sensible default for internal work. If the artifact is leaving your team — vendor ticket, external LLM, third-party review — use `prod-safe` for maximum suppression or `llm-telecom-safe` when the receiver needs correlated node relationships without raw endpoint exposure.
- **Sending `detail.json` when `summary.json` would be enough.** For most vendor tickets, `summary.json` + `summary.md` contain the protocol counts, anomalies, and timing needed to diagnose an issue. Attach `detail.json` only when the recipient needs packet-level fields.
- **Assuming `flow.svg` is automatically safe because it is visual.** Flow labels and hover tooltips can contain endpoint names, DNS queries, APN/DNN values, result codes, and failure causes. Treat it as a derived artifact that still needs privacy review.
- **Trusting the profile name instead of reading the output.** Profile, config overrides, and CLI flags all interact. Read `privacy_modes` in `summary.json` before sharing — not just the command line you ran.

---

## Concrete Examples

### Internal ticket — team-internal LTE investigation

```bash
pcap2llm analyze failed_attach.pcapng \
  --profile lte-core \
  --privacy-profile share \
  --out ./artifacts
```

Share: `detail.json`, `summary.json`, `summary.md`; optionally `flow.svg` after reviewing labels and tooltips
Keep back: `pseudonym_mapping.json` (if created)

---

### Vendor ticket — sending trace to equipment vendor

```bash
pcap2llm analyze diameter_error.pcapng \
  --profile lte-core \
  --privacy-profile prod-safe \
  --out ./artifacts
```

Share: `summary.json`, `summary.md` — attach `detail.json` or `flow.svg` only if the vendor explicitly needs packet-level data or a visual sequence.
Do not share: `pseudonym_mapping.json`, `vault.json`, any key material.

---

### LLM input — passing artifact to an AI assistant

```bash
pcap2llm analyze gtp_session.pcapng \
  --profile lte-core \
  --privacy-profile llm-telecom-safe \
  --llm-mode \
  --out ./artifacts
```

Pass `detail.json` to the LLM. Use `summary.json` to verify coverage and confirm `detail_truncated` is false (or acceptable). Keep `flow.svg` as a local review aid unless the prompt specifically needs a sequence abstraction; if you share `flow.json`, review it like a derived detail artifact. Check `warnings` in the `--llm-mode` JSON output for any privacy-relevant notices before uploading.
