# LTE/EPC Quickstart

Use `pcap2llm inspect` first, narrow the capture with `-Y`, then generate artifacts:

```bash
pcap2llm inspect sample.pcapng --profile lte-core
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2 || s1ap" --privacy-profile share
```

Treat `detail.json` as the primary handoff artifact for the downstream LLM step.
