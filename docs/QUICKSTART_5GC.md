# 5G Core Quickstart

For 5G control-plane troubleshooting, keep captures narrow and protocol-focused:

```bash
pcap2llm inspect sample.pcapng --profile 5g-core
pcap2llm analyze sample.pcapng --profile 5g-core -Y "ngap || pfcp || http2" --privacy-profile share
```

Review `summary.json` for coverage and truncation before sharing `detail.json`.
