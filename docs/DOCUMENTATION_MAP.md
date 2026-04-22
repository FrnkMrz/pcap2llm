# Documentation Map

This page is the inventory and navigation guide for the `pcap2llm`
documentation set.

Use it when you want to know:

- which document exists for which purpose
- where to start for a specific task
- which pages are user-facing, operator-facing, or contributor-facing
- which related pages you should read next

## Recommended Reading Paths

### I am new to the project

1. [`../README.md`](../README.md)
2. [`QUICKSTART_DE.md`](QUICKSTART_DE.md) or [`REFERENCE.md`](REFERENCE.md)
3. [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md)

### I have an unknown capture

1. [`DISCOVERY.md`](DISCOVERY.md)
2. [`PROFILE_SELECTION.md`](PROFILE_SELECTION.md)
3. [`WORKFLOWS.md`](WORKFLOWS.md)
4. [`REFERENCE.md`](REFERENCE.md)

### I want to hand artifacts to an external LLM

1. [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md)
2. [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md)
3. [`LLM_MODE.md`](LLM_MODE.md)
4. [`REFERENCE.md`](REFERENCE.md)

### I want to understand or create profiles

1. [`PROFILES.md`](PROFILES.md)
2. one of the family guides:
   [`PROFILES_LTE.md`](PROFILES_LTE.md),
   [`PROFILES_5G.md`](PROFILES_5G.md),
   [`PROFILES_VOICE.md`](PROFILES_VOICE.md),
   [`PROFILES_2G3G.md`](PROFILES_2G3G.md)
3. [`WORKFLOWS.md`](WORKFLOWS.md)

### I am changing artifact contracts, privacy logic, or pipeline internals

1. [`PROJECT_STATUS.md`](PROJECT_STATUS.md)
2. [`schema/detail.schema.md`](schema/detail.schema.md)
3. [`schema/summary.schema.md`](schema/summary.schema.md)
4. [`privacy_coverage.md`](privacy_coverage.md)
5. [`security/threat_model.md`](security/threat_model.md)
6. [`architecture/current_pipeline.md`](architecture/current_pipeline.md)
7. [`architecture/scaling_plan.md`](architecture/scaling_plan.md)

## Entry Points

| Document | Audience | Purpose | Read next |
|---|---|---|---|
| [`../README.md`](../README.md) | everyone | first contact, quick explanation, main navigation | [`QUICKSTART_DE.md`](QUICKSTART_DE.md), [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md), [`REFERENCE.md`](REFERENCE.md) |
| [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md) | everyone | complete document inventory and navigation hub | whichever topic page matches your task |
| [`QUICKSTART_DE.md`](QUICKSTART_DE.md) | German-speaking users | shortest path from install to first meaningful run | [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md), [`DISCOVERY.md`](DISCOVERY.md), [`REFERENCE.md`](REFERENCE.md) |
| [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md) | German-speaking users | practical day-to-day usage guide | [`WORKFLOWS.md`](WORKFLOWS.md), [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md), [`REFERENCE.md`](REFERENCE.md) |
| [`REFERENCE.md`](REFERENCE.md) | operators, integrators, contributors | full English command, option, artifact, and visualization reference | topic-specific pages linked below |

## Capture Analysis And Orchestration

| Document | Audience | Purpose | Related docs |
|---|---|---|---|
| [`DISCOVERY.md`](DISCOVERY.md) | operators, integrators | explain `discover`, scoring, ambiguity handling, scout artifacts | [`PROFILE_SELECTION.md`](PROFILE_SELECTION.md), [`SESSIONS.md`](SESSIONS.md), [`WORKFLOWS.md`](WORKFLOWS.md) |
| [`PROFILE_SELECTION.md`](PROFILE_SELECTION.md) | operators, integrators | explain `recommend-profiles` and deterministic ranking | [`DISCOVERY.md`](DISCOVERY.md), [`PROFILES.md`](PROFILES.md), [`SESSIONS.md`](SESSIONS.md) |
| [`SESSIONS.md`](SESSIONS.md) | integrators, automation authors | structured multi-run manifests and session reports | [`DISCOVERY.md`](DISCOVERY.md), [`PROFILE_SELECTION.md`](PROFILE_SELECTION.md), [`REFERENCE.md`](REFERENCE.md) |
| [`WORKFLOWS.md`](WORKFLOWS.md) | operators | protocol-family troubleshooting flows and operator triage | [`PROFILES.md`](PROFILES.md), [`DISCOVERY.md`](DISCOVERY.md), [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md) |
| [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md) | operators, AI-assisted users | safe PCAP -> artifact -> external LLM workflow | [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md), [`LLM_MODE.md`](LLM_MODE.md), [`DISCOVERY.md`](DISCOVERY.md) |
| [`LLM_MODE.md`](LLM_MODE.md) | automation authors | strict machine-readable CLI contract for `analyze --llm-mode` | [`REFERENCE.md`](REFERENCE.md), [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md), [`PROJECT_STATUS.md`](PROJECT_STATUS.md) |

## Privacy, Security, And Sharing

| Document | Audience | Purpose | Related docs |
|---|---|---|---|
| [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md) | operators | choose privacy profiles and share artifacts safely | [`REFERENCE.md`](REFERENCE.md), [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md), [`privacy_coverage.md`](privacy_coverage.md) |
| [`privacy_coverage.md`](privacy_coverage.md) | contributors, reviewers | map CLI privacy classes to canonical/internal coverage | [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md), [`security/threat_model.md`](security/threat_model.md), [`REFERENCE.md`](REFERENCE.md) |
| [`security/threat_model.md`](security/threat_model.md) | contributors, reviewers | define protected assets, trust boundaries, and artifact rules | [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md), [`privacy_coverage.md`](privacy_coverage.md), [`security/encryption_model.md`](security/encryption_model.md) |
| [`security/encryption_model.md`](security/encryption_model.md) | contributors, reviewers | document encryption behavior and key-handling model | [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md), [`REFERENCE.md`](REFERENCE.md), [`security/threat_model.md`](security/threat_model.md) |

## Profiles And Focused Quickstarts

| Document | Audience | Purpose | Related docs |
|---|---|---|---|
| [`PROFILES.md`](PROFILES.md) | operators, contributors | entry point for built-in families and custom profile authoring | [`PROFILES_LTE.md`](PROFILES_LTE.md), [`PROFILES_5G.md`](PROFILES_5G.md), [`PROFILES_VOICE.md`](PROFILES_VOICE.md), [`PROFILES_2G3G.md`](PROFILES_2G3G.md) |
| [`PROFILES_LTE.md`](PROFILES_LTE.md) | LTE/EPC users | LTE / EPC profile family guide | [`PROFILES.md`](PROFILES.md), [`WORKFLOWS.md`](WORKFLOWS.md), [`QUICKSTART_LTE_EPC.md`](QUICKSTART_LTE_EPC.md) |
| [`PROFILES_5G.md`](PROFILES_5G.md) | 5GC users | 5G SA core profile family guide | [`PROFILES.md`](PROFILES.md), [`WORKFLOWS.md`](WORKFLOWS.md), [`QUICKSTART_5GC.md`](QUICKSTART_5GC.md) |
| [`PROFILES_VOICE.md`](PROFILES_VOICE.md) | IMS voice users | VoLTE / VoNR profile family guide | [`PROFILES.md`](PROFILES.md), [`WORKFLOWS.md`](WORKFLOWS.md) |
| [`PROFILES_2G3G.md`](PROFILES_2G3G.md) | legacy-core users | 2G/3G / GERAN profile family guide | [`PROFILES.md`](PROFILES.md), [`WORKFLOWS.md`](WORKFLOWS.md) |
| [`QUICKSTART_LTE_EPC.md`](QUICKSTART_LTE_EPC.md) | LTE/EPC users | smallest LTE/EPC-oriented starting pattern | [`PROFILES_LTE.md`](PROFILES_LTE.md), [`WORKFLOWS.md`](WORKFLOWS.md), [`REFERENCE.md`](REFERENCE.md) |
| [`QUICKSTART_5GC.md`](QUICKSTART_5GC.md) | 5GC users | smallest 5G core-oriented starting pattern | [`PROFILES_5G.md`](PROFILES_5G.md), [`WORKFLOWS.md`](WORKFLOWS.md), [`QUICKSTART_HTTP2_SBI.md`](QUICKSTART_HTTP2_SBI.md) |
| [`QUICKSTART_HTTP2_SBI.md`](QUICKSTART_HTTP2_SBI.md) | SBI users | shortest HTTP/2/SBI-focused command pattern | [`PROFILES_5G.md`](PROFILES_5G.md), [`QUICKSTART_5GC.md`](QUICKSTART_5GC.md), [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md) |

## Product Surface, Compatibility, And Status

| Document | Audience | Purpose | Related docs |
|---|---|---|---|
| [`PROJECT_STATUS.md`](PROJECT_STATUS.md) | all readers, especially integrators | maturity, intended use, public interface, known limits | [`SUPPORTED_ENVIRONMENTS.md`](SUPPORTED_ENVIRONMENTS.md), [`REFERENCE.md`](REFERENCE.md), [`LLM_MODE.md`](LLM_MODE.md) |
| [`SUPPORTED_ENVIRONMENTS.md`](SUPPORTED_ENVIRONMENTS.md) | users, maintainers | tested Python and TShark environment baseline | [`PROJECT_STATUS.md`](PROJECT_STATUS.md), [`REFERENCE.md`](REFERENCE.md) |
| [`schema/detail.schema.md`](schema/detail.schema.md) | integrators, contributors | stable contract for `detail.json` | [`schema/summary.schema.md`](schema/summary.schema.md), [`REFERENCE.md`](REFERENCE.md), [`architecture/current_pipeline.md`](architecture/current_pipeline.md) |
| [`schema/summary.schema.md`](schema/summary.schema.md) | integrators, contributors | stable contract for `summary.json` | [`schema/detail.schema.md`](schema/detail.schema.md), [`REFERENCE.md`](REFERENCE.md), [`architecture/current_pipeline.md`](architecture/current_pipeline.md) |

## Contributor Internals

| Document | Audience | Purpose | Related docs |
|---|---|---|---|
| [`architecture/current_pipeline.md`](architecture/current_pipeline.md) | contributors | current stage model from inspect to serialize | [`architecture/scaling_plan.md`](architecture/scaling_plan.md), [`schema/detail.schema.md`](schema/detail.schema.md), [`schema/summary.schema.md`](schema/summary.schema.md) |
| [`architecture/scaling_plan.md`](architecture/scaling_plan.md) | contributors | two-pass scaling behavior, guards, and future work | [`architecture/current_pipeline.md`](architecture/current_pipeline.md), [`REFERENCE.md`](REFERENCE.md), [`PROJECT_STATUS.md`](PROJECT_STATUS.md) |
| [`golden_corpus.md`](golden_corpus.md) | contributors, reviewers | regression fixture policy for stable public artifact behavior | [`schema/detail.schema.md`](schema/detail.schema.md), [`schema/summary.schema.md`](schema/summary.schema.md), [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) |
| [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) | maintainers | release readiness checks for contract, docs, tests, and corpus | [`golden_corpus.md`](golden_corpus.md), [`PROJECT_STATUS.md`](PROJECT_STATUS.md), [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md) |

## What Is Documented Overall

Across the full set, the documentation now covers:

- product scope, maturity, and supported environments
- installation and first-run entry paths
- German quickstart and German practical usage guidance
- complete English CLI reference
- discovery, recommendation, and session-based orchestration
- optional signaling-flow visualization with `flow.json`, `flow.svg`, and `visualize`
- protocol-family workflows for LTE, 5G, voice/IMS, and legacy SS7/GERAN
- profile selection and custom profile authoring
- privacy profiles, sharing rules, and encryption model
- machine-readable `--llm-mode` behavior
- external LLM handoff workflow
- stable `detail.json` and `summary.json` schema contracts
- contributor internals for pipeline and scaling behavior
- regression corpus and release checks
