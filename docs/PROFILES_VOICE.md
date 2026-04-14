# Voice-Over-IMS Profiles

Use this guide when the problem is IMS voice service rather than generic LTE or
5GC control plane.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROFILES.md`](PROFILES.md)
- [`WORKFLOWS.md`](WORKFLOWS.md)
- [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md)

## Built-In Voice-Over-IMS Profiles

| Profile | Best used for |
|---|---|
| `volte-sip` | Broad VoLTE / IMS SIP troubleshooting on LTE / EPS |
| `volte-sip-register` | IMS registration and challenge-flow analysis for VoLTE |
| `volte-sip-call` | VoLTE call setup and teardown analysis |
| `volte-diameter-cx` | Cx / Dx subscriber and registration context in IMS |
| `volte-diameter-rx` | Rx policy and media authorization signaling |
| `volte-diameter-sh` | Sh subscriber-profile retrieval and service data access |
| `volte-dns` | IMS DNS and service-discovery issues in LTE / EPS |
| `volte-rtp-signaling` | SDP, RTP, and RTCP as supporting evidence for VoLTE signaling |
| `volte-sbc` | Session Border Controller boundary issues in VoLTE |
| `volte-ims-core` | Broad mixed SIP + Diameter + DNS VoLTE incidents |
| `vonr-sip` | Broad VoNR / IMS SIP troubleshooting on 5GS |
| `vonr-sip-register` | IMS registration and readiness analysis for VoNR |
| `vonr-sip-call` | VoNR call setup and teardown analysis |
| `vonr-ims-core` | Broad mixed SIP + SBI + DNS + N1/N2 VoNR incidents |
| `vonr-policy` | Voice-relevant policy and QoS control in 5GS |
| `vonr-dns` | IMS DNS and service-discovery issues in 5GS |
| `vonr-n1-n2-voice` | Voice-relevant NGAP and NAS-5GS state on N1/N2 |
| `vonr-sbi-auth` | Auth-related SBI flows affecting VoNR readiness |
| `vonr-sbi-pdu` | Voice-relevant PDU and session-control SBI flows |
| `vonr-sbc` | Session Border Controller boundary issues in VoNR |

## Important distinctions

- `volte-sip` vs `volte-sip-register` vs `volte-sip-call`: use `volte-sip` for a broad first pass, `volte-sip-register` when IMS readiness and challenge flow are the issue, and `volte-sip-call` when call establishment or abnormal release is the main symptom.
- `vonr-sip` vs `vonr-sip-register` vs `vonr-sip-call`: same SIP family split, but always framed in the 5GS voice context rather than LTE / EPS service readiness.
- `volte-diameter-cx` vs `volte-diameter-rx` vs `volte-diameter-sh`: Cx tracks IMS subscriber and registration context, Rx tracks policy and authorization, and Sh tracks service-data access and profile retrieval.
- `volte-dns` vs `vonr-dns`: both are discovery-focused, but `volte-dns` is for LTE / EPS IMS reachability while `vonr-dns` is for voice over 5GS readiness and service setup.
- `volte-sbc` vs `vonr-sbc`: both target Session Border Controllers, but `vonr-sbc` stays explicit about the 5GS voice context instead of reusing LTE / EPS assumptions.
- `volte-ims-core` vs `vonr-ims-core`: both are intentionally broad, but `volte-ims-core` mixes SIP, Diameter, and DNS around LTE / EPS IMS service, while `vonr-ims-core` mixes SIP, SBI, DNS, and voice-relevant N1/N2 state in a 5GS context.
- Discovery separates these subprofiles with a few specific cues: SDP/media-like
  markers help `*-sip-call`, registrar/auth-style IMS context helps
  `*-sip-register`, explicit SBC peer hints help `*-sbc`, and Diameter plus
  IMS/CSCF hints help `*-ims-core`.

## Selection Rule

- Choose `volte-*` when the operational voice problem is anchored in LTE / EPS IMS service.
- Choose `vonr-*` when the same voice problem has to be interpreted through 5GS registration, N1/N2 state, or SBI policy and session flows.
- Do not use these as generic SIP profiles; they are voice-service profiles on purpose.

Family overview: [`PROFILES.md`](PROFILES.md)
