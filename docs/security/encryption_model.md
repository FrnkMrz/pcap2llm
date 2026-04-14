# Encryption Model

Related docs:

- [`../DOCUMENTATION_MAP.md`](../DOCUMENTATION_MAP.md)
- [`../PRIVACY_SHARING.md`](../PRIVACY_SHARING.md)
- [`../REFERENCE.md`](../REFERENCE.md)
- [`threat_model.md`](threat_model.md)

`pcap2llm` supports inline encryption for selected data classes, but only under an explicit operator-supplied key model.

## Chosen Model

`pcap2llm` uses **externally supplied key only**.

- Encryption is allowed only when `PCAP2LLM_VAULT_KEY` is set explicitly.
- If the key is missing, artifact generation fails fast.
- `pcap2llm` does not generate temporary recovery keys.
- `vault.json` contains metadata only. It never contains the decryption secret.

## Current Behavior

- `validate_vault_key()` checks that `cryptography` is available when encrypt mode is active.
- `validate_vault_key()` fails if `PCAP2LLM_VAULT_KEY` is missing.
- `validate_vault_key()` fails if the supplied value is not a valid Fernet key.
- Encrypted values are stored inline in the generated artifact.
- `vault.json` records the key source and warnings, not the key.
- `summary.md` may reference the vault sidecar when encryption is used, but that sidecar is not enough to decrypt anything.

## Recoverability

- Decryption is possible only if the operator kept the original `PCAP2LLM_VAULT_KEY`.
- If the key is lost, encrypted values are unrecoverable.
- Sharing `vault.json` without the key is safe only in the narrow sense that it does not disclose the secret.

## What Users Must Not Assume

- `vault.json` is not a recovery package.
- Environment variables are not durable key management.
- Encryption does not make careless sharing acceptable.

## Operational Guidance

- Set `PCAP2LLM_VAULT_KEY` intentionally before running `pcap2llm analyze`.
- Store the key outside the artifact directory and outside the same ticket, chat thread, or share target.
- Prefer pseudonymization or removal for routinely shared outputs; use encryption only when a real recovery need exists.
