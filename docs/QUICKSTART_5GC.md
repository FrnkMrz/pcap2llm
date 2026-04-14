# 5G Core Quickstart

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROFILES_5G.md`](PROFILES_5G.md)
- [`WORKFLOWS.md`](WORKFLOWS.md)
- [`QUICKSTART_HTTP2_SBI.md`](QUICKSTART_HTTP2_SBI.md)

For 5G SA troubleshooting, start broad only if you must. As soon as the
interface is known, switch to the narrower 5G profile:

```bash
pcap2llm inspect sample.pcapng --profile 5g-core
pcap2llm analyze sample.pcapng --profile 5g-n2 -Y "ngap" --privacy-profile share
pcap2llm analyze sample.pcapng --profile 5g-sbi -Y "http2" --privacy-profile prod-safe --two-pass
```

Review `summary.json` for coverage and truncation before sharing `detail.json`.
