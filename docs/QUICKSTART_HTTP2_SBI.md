# HTTP/2 / SBI Quickstart

Use this page for the shortest HTTP/2 and SBI-focused command pattern.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`QUICKSTART_5GC.md`](QUICKSTART_5GC.md)
- [`PROFILES_5G.md`](PROFILES_5G.md)
- [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md)

When troubleshooting service-based interfaces, focus on the relevant control-plane exchange:

```bash
pcap2llm analyze sample.pcapng --profile 5g-sbi-auth -Y "http2" --privacy-profile prod-safe --two-pass
```

Cookies, authorization headers, and embedded URLs should be handled through the privacy policy before sharing artifacts.
