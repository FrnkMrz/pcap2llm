# LTE/EPC Quickstart

Use this page for the shortest LTE / EPC-oriented starting pattern.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROFILES_LTE.md`](PROFILES_LTE.md)
- [`WORKFLOWS.md`](WORKFLOWS.md)
- [`REFERENCE.md`](REFERENCE.md)

Use `pcap2llm inspect` first, narrow the capture with `-Y`, then generate artifacts:

```bash
pcap2llm inspect sample.pcapng --profile lte-core
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2 || s1ap" --privacy-profile share
```

Treat `detail.json` as the primary handoff artifact for the downstream LLM step.
