# 2G/3G Core and GERAN Profiles

Use this guide when the capture belongs to legacy 2G/3G core or GERAN-side
signaling troubleshooting.

## Built-In 2G/3G Core and GERAN Profiles

| Profile | Best used for |
|---|---|
| `2g3g-ss7-geran` | Broad legacy bundle across MAP, CAP, ISUP, BSSAP, and GERAN |
| `2g3g-gn` | Intra-PLMN Gn GTPv1 control plane |
| `2g3g-gp` | Roaming/inter-PLMN Gp GTPv1 control plane |
| `2g3g-gr` | Gr MAP signaling between SGSN and HLR |
| `2g3g-gs` | Gs paging and combined CS/PS coordination |
| `2g3g-geran` | Broader GERAN/A-interface-adjacent core-side view |
| `2g3g-dns` | Legacy/core DNS troubleshooting |
| `2g3g-map-core` | Generic MAP-core analysis beyond one interface |
| `2g3g-cap` | CAP/CAMEL service-control flows |
| `2g3g-bssap` | Focused BSSAP/BSSMAP/DTAP technical analysis |
| `2g3g-isup` | Voice/circuit-signaling call flows |
| `2g3g-sccp-mtp` | Lower-layer SCCP/MTP routing and transport issues |

## Important distinctions

- `2g3g-gn` vs `2g3g-gp`: both use GTPv1, but `2g3g-gp` is documented and heuristically framed for roaming and inter-PLMN interpretation.
- `2g3g-gr` vs `2g3g-map-core`: use `2g3g-gr` when you know the path is SGSN ↔ HLR; use `2g3g-map-core` when the MAP question spans mixed HLR/VLR/SGSN roles.
- `2g3g-geran` vs `2g3g-bssap`: use `2g3g-geran` for the broader core-side 2G signaling picture; use `2g3g-bssap` when the technical A-interface mechanics matter more than the broader context.
- `2g3g-isup` vs `2g3g-sccp-mtp`: use `2g3g-isup` for call sequence and release-cause interpretation; use `2g3g-sccp-mtp` when routing and lower-layer SS7 delivery are the real issue.

## Selection rule

- Start with `2g3g-ss7-geran` if the legacy interface is still unclear.
- Move to the narrower profile once you know whether the problem sits on Gn/Gp, Gr, Gs, MAP-core, GERAN/A-interface, CAP, ISUP, or lower-layer SCCP/MTP routing.

Back to the overview: [`docs/PROFILES.md`](PROFILES.md)
