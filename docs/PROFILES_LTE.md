# LTE / EPC Profiles

Use this guide when the capture belongs to LTE / EPC control-plane
troubleshooting.

Related docs:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- [`PROFILES.md`](PROFILES.md)
- [`WORKFLOWS.md`](WORKFLOWS.md)
- [`QUICKSTART_LTE_EPC.md`](QUICKSTART_LTE_EPC.md)

## Built-In LTE Interface Profiles

| Profile | Best used for |
|---|---|
| `lte-core` | Broad EPC overview across Diameter, GTPv2-C, S1AP, NAS-EPS, DNS |
| `lte-s1` | General S1-MME control-plane troubleshooting |
| `lte-s1-nas` | NAS-centric Attach, TAU, authentication, and ESM analysis |
| `lte-s6a` | Diameter on S6a between MME and HSS |
| `lte-s11` | MME ↔ SGW GTPv2-C control-plane procedures |
| `lte-s10` | Inter-MME relocation and context transfer |
| `lte-sgs` | SGsAP paging, CS fallback, and legacy interworking |
| `lte-s5` | SGW ↔ PGW EPC context with control-plane emphasis |
| `lte-s8` | Roaming-oriented SGW ↔ PGW / inter-PLMN context |
| `lte-dns` | LTE/EPC/IMS-adjacent DNS issues |
| `lte-sbc-cbc` | SBc between MME and CBC for Cell Broadcast / ETWS / CMAS |

## Important distinctions

- `lte-s1` vs `lte-s1-nas`: use `lte-s1` when the main question is procedure flow or S1AP cause handling; use `lte-s1-nas` when NAS sequencing and reject causes are the main signal.
- `lte-s5` vs `lte-s8`: both are GTP-heavy, but `lte-s8` is intentionally documented for roaming and inter-PLMN interpretation rather than pure intra-EPC handling.
- `lte-sbc-cbc` means Cell Broadcast SBc, not Session Border Controller traffic.

## Selection rule

- Start with `lte-core` if the failing LTE interface is not yet clear.
- Move to the narrower interface profile once the capture is known to be S1, S6a, S11, S10, SGs, S5/S8, or IMS-adjacent DNS.

Back to the overview: [`docs/PROFILES.md`](PROFILES.md)
