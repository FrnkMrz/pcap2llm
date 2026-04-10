# HTTP/2 / SBI Quickstart

When troubleshooting service-based interfaces, focus on the relevant control-plane exchange:

```bash
pcap2llm analyze sample.pcapng --profile 5g-sbi-auth -Y "http2" --privacy-profile prod-safe --two-pass
```

Cookies, authorization headers, and embedded URLs should be handled through the privacy policy before sharing artifacts.
