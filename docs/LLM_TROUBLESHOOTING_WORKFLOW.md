# LLM Troubleshooting Workflow

Use this workflow when a `.pcap` or `.pcapng` should be translated into a privacy-controlled artifact set and then explained or troubleshot by an external LLM.

The external LLM never receives the raw capture file directly.

## Goal

`pcap2llm` is the local deterministic translation layer between telecom packet captures and an external LLM that cannot open PCAP files itself.

The workflow is:

1. inspect the capture locally
2. choose a focused analysis profile
3. apply a repo-owned privacy profile
4. generate artifacts locally with `pcap2llm`
5. pass only the minimum necessary artifact content to the LLM
6. validate the LLM answer against the local artifacts

## Standard LLM-PCAP Workflow

Recommended default:

```bash
# 1. Broad first pass
pcap2llm discover trace.pcapng

# 2. Recommend focused profiles from the discovery result
pcap2llm recommend-profiles artifacts/discover_trace_start_1_V_01.json

# 3. Run focused analysis with the dedicated LLM-sharing privacy profile
pcap2llm analyze trace.pcapng \
  --profile <chosen-profile> \
  --privacy-profile llm-telecom-safe \
  --out ./artifacts
```

For HTTP/2-heavy 5G SBI traces, add `--two-pass`.

## Required Rules

1. Never send the raw PCAP to an external LLM.
2. Use privacy profiles from `src/pcap2llm/privacy_profiles/` to control disclosure.
3. For external LLM use, start with `llm-telecom-safe`.
4. Never share `pseudonym_mapping.json`, `vault.json`, or any vault key material.
5. Prefer `summary.json` and a targeted `detail.json` excerpt over the full artifact set.
6. Treat the LLM answer as advisory until it is checked against the local artifacts.

## Why `llm-telecom-safe`

`llm-telecom-safe` is intended for telecom troubleshooting with external LLMs.

It protects subscriber and secret-bearing fields while preserving enough technical structure for troubleshooting:

- `ip`: pseudonymized
- `hostname`: pseudonymized
- `subscriber_id`, `msisdn`, `imsi`, `imei`: pseudonymized
- `token`, `email`, `payload_text`: removed
- `diameter_identity`: pseudonymized
- `apn_dnn`: kept
- `uri`: masked

This keeps endpoint relationships and repeated node identities analyzable without exposing the raw values.

## What To Send To The LLM

Prefer the smallest useful input:

1. `summary.json` for protocol mix, anomalies, timing, and coverage
2. a focused excerpt from `detail.json` for the relevant call flow or failure window
3. a short operator question such as:
   - what procedure is shown here?
   - where does the failure occur?
   - what is the most likely root cause?
   - explain the signaling sequence step by step

Do not send whole artifacts blindly when a narrow excerpt is enough.

## Validation Step

After the LLM responds:

1. compare the explanation to `summary.json`
2. check protocol ordering and anomalies against `detail.json`
3. separate direct trace evidence from hypotheses

Recommended reporting style:

- trace-confirmed findings
- plausible hypotheses
- open questions / missing evidence

## Suggested Trigger Phrase For Agents

To invoke this workflow consistently in agent-assisted use, use a fixed phrase such as:

`Use the documented LLM-PCAP workflow for <capture>`

That means:

1. run `discover`
2. choose the focused profile
3. run `analyze --privacy-profile llm-telecom-safe`
4. prepare a minimal LLM-ready artifact excerpt
5. validate the LLM answer against the local artifacts

## Direct ChatGPT CLI Handoff

When `OPENAI_API_KEY` is available, the workflow can be executed directly from the CLI:

```bash
pcap2llm ask-chatgpt trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

What this command does:

1. runs `discover`
2. selects the best recommended profile unless `--profile` is forced
3. runs `analyze` with the selected profile and chosen privacy profile
4. builds a ChatGPT prompt from `summary.json` plus a bounded `detail.json` excerpt
5. sends the request to the OpenAI Responses API
6. writes prompt and response artifacts next to the normal `pcap2llm` outputs

Required environment variable:

```bash
export OPENAI_API_KEY=...
```

## Direct Claude CLI Handoff

When `ANTHROPIC_API_KEY` is available, the workflow can also be executed directly against Claude:

```bash
pcap2llm ask-claude trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

Required environment variable:

```bash
export ANTHROPIC_API_KEY=...
```

## Direct Gemini CLI Handoff

When `GEMINI_API_KEY` is available, the workflow can also be executed directly against Gemini:

```bash
pcap2llm ask-gemini trace.pcapng \
  --privacy-profile llm-telecom-safe \
  --question "Explain the trace and identify the likely failure point"
```

Required environment variable:

```bash
export GEMINI_API_KEY=...
```
