# 5G SA Core Profiles

Use this guide when the capture belongs to 5G SA core control-plane
troubleshooting.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROFILES.md`](PROFILES.md)
- [`WORKFLOWS.md`](WORKFLOWS.md)
- [`QUICKSTART_5GC.md`](QUICKSTART_5GC.md)
- [`QUICKSTART_HTTP2_SBI.md`](QUICKSTART_HTTP2_SBI.md)

## Built-In 5G SA Core Profiles

| Profile | Best used for |
|---|---|
| `5g-core` | Broad mixed 5GC overview across PFCP, NGAP, NAS-5GS, and SBI |
| `5g-n1-n2` | Broad AMF-facing registration/service view across NGAP and NAS-5GS |
| `5g-n2` | N2-only NGAP troubleshooting between gNB and AMF |
| `5g-nas-5gs` | NAS-5GS-centric registration, mobility, and session signaling |
| `5g-sbi` | Generic HTTP/2 SBI troubleshooting across 5GC network functions |
| `5g-sbi-auth` | Authorization-heavy SBI captures with token/header focus |
| `5g-n8` | UDM-facing SBI on N8 |
| `5g-n10` | UDM ↔ AUSF authentication exchanges on N10 |
| `5g-n11` | SMF-facing SBI control on N11 |
| `5g-n12` | AUSF ↔ UDM subscriber identity/authentication data on N12 |
| `5g-n13` | UDM ↔ UDR subscriber data access on N13 |
| `5g-n14` | Inter-AMF mobility/context coordination on N14 |
| `5g-n15` | AMF/SMF ↔ PCF policy interactions on N15 |
| `5g-n16` | SMF ↔ PCF session/policy influence on N16 |
| `5g-n22` | NSSF / roaming-oriented SBI selection context on N22 |
| `5g-n26` | Hybrid EPC/5GC interworking and mobility context transfer |
| `5g-n40` | SMF ↔ CHF charging-related SBI on N40 |
| `5g-dns` | 5GC-adjacent DNS troubleshooting |
| `5g-cbc-cbs` | Public-warning / cell-broadcast signaling in a 5G context |

## Important distinctions

- `5g-core` vs interface-specific profiles: use `5g-core` as the first-pass mixed 5GC overview, then move to the narrower profile once the real interface is known.
- `5g-n1-n2` vs `5g-n2` vs `5g-nas-5gs`: use `5g-n1-n2` for the combined AMF-facing picture, `5g-n2` when NGAP procedures/cause values are primary, and `5g-nas-5gs` when NAS sequencing, registration state, or SM signaling are the real subject.
- `5g-sbi` vs `5g-sbi-auth`: use `5g-sbi` for broad HTTP/2 SBI work, and `5g-sbi-auth` when OAuth-style tokens, authorization headers, or identity exchanges dominate the evidence.
- `5g-n8` / `5g-n10` / `5g-n12` / `5g-n13`: these are all UDM/AUSF/UDR-oriented, but each is framed around a narrower control relationship to keep artifacts smaller and heuristics more precise.
- `5g-n11` / `5g-n15` / `5g-n16` / `5g-n40`: these center on SMF/PCF/CHF policy, session, and charging decisions rather than generic HTTP/2 traffic.
- `5g-n22` vs `5g-n26`: `5g-n22` remains SBI-oriented around slicing/selection context, while `5g-n26` is intentionally hybrid because EPC/5GC interworking often mixes 4G and 5G evidence.

## Selection Rule

- Start with `5g-core` if the failing 5GC path is not yet isolated.
- Move to the interface profile as soon as you know whether the problem is NGAP, NAS-5GS, generic SBI, auth, policy, charging, DNS, or mixed N26 interworking.

Family overview: [`PROFILES.md`](PROFILES.md)
