# pcap2llm — Schnellstart (Deutsch)

## Voraussetzungen

- Python 3.11+
- `tshark` im PATH (Wireshark-Paket)

```bash
python3 --version
tshark -v
```

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

Falls du hinter einem Proxy arbeitest:

```powershell
$env:HTTP_PROXY="http://proxy.example.com:8080"
$env:HTTPS_PROXY="http://proxy.example.com:8080"
python -m pip install --proxy http://proxy.example.com:8080 -e .[dev]
```

## Drei Befehle reichen fuer den Einstieg

**Schritt 1 — Was steckt in der Datei?**
```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

**Schritt 2 — Analyse-Artefakte erzeugen:**
```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

**Schritt 3 — Danach in `./artifacts` nachschauen:**

| Datei | Inhalt |
|---|---|
| `YYYYMMDD_HHMMSS_detail_V_01.json` | Normalisierte Pakete — das geht ans LLM |
| `YYYYMMDD_HHMMSS_summary_V_01.json` | Statistiken, Anomalien, Coverage |
| `YYYYMMDD_HHMMSS_summary_V_01.md` | Menschenlesbare Zusammenfassung |

## Welches Profil?

| Profil | Fuer was |
|---|---|
| `lte-core` | LTE / EPC — Diameter, GTPv2-C, S1AP, NAS-EPS |
| `5g-core` | 5G Core — PFCP, NGAP, NAS-5GS, HTTP/2 SBI |
| `2g3g-ss7-geran` | Legacy 2G/3G — SS7, MAP, CAP, ISUP, BSSAP |

## Haeufige Optionen

```bash
# Nur bestimmte Protokolle analysieren
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2"

# Subscriber-Daten schuetzen (IMSI pseudonymisieren, Tokens entfernen)
pcap2llm analyze sample.pcapng --profile lte-core --privacy-profile share

# Alle Pakete (kein Limit)
pcap2llm analyze sample.pcapng --profile lte-core --all-packets

# Plan anzeigen ohne tshark aufzurufen
pcap2llm analyze sample.pcapng --profile lte-core --dry-run

# Knoten benennen
pcap2llm analyze sample.pcapng --profile lte-core \
  --mapping-file ./examples/mapping.sample.yaml
```

> **Sweetspot:** Gezielte Captures mit wenigen hundert Signalisierungsnachrichten. Kein mehrstundiger Dump — der erzeugt ein `detail.json`, das kein LLM verarbeiten kann.

## Weiterfuehrendes

- Vollstaendige deutsche Anleitung: [`docs/ANLEITUNG_DE.md`](ANLEITUNG_DE.md)
- Englische Referenz: [`README.md`](../README.md)
- Workflows fuer LTE / 5G / SS7: [`docs/WORKFLOWS.md`](WORKFLOWS.md)
