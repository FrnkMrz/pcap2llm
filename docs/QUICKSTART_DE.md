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
| `analyze_<capture>_start_<n>_V_01_detail.json` | Normalisierte Pakete — das geht ans LLM |
| `analyze_<capture>_start_<n>_V_01_summary.json` | Statistiken, Anomalien, Coverage |
| `analyze_<capture>_start_<n>_V_01_summary.md` | Menschenlesbare Zusammenfassung |

## Welches Profil?

Die Startregel ist einfach:

- `lte-*` fuer LTE / EPC
- `5g-*` fuer 5G SA Core
- `volte-*` und `vonr-*` fuer Voice-over-IMS
- `2g3g-*` fuer Legacy 2G/3G / GERAN

Wenn das genaue Interface noch unklar ist, nimm zuerst das breitere
Ueberblicksprofil der Familie, zum Beispiel `lte-core`, `5g-core`,
`volte-ims-core`, `vonr-ims-core` oder `2g3g-ss7-geran`.

Die vollstaendige Profilreferenz findest du hier:

- Uebersicht: [`docs/PROFILES.md`](PROFILES.md)
- LTE / EPC: [`docs/PROFILES_LTE.md`](PROFILES_LTE.md)
- 5G SA Core: [`docs/PROFILES_5G.md`](PROFILES_5G.md)
- Voice / IMS: [`docs/PROFILES_VOICE.md`](PROFILES_VOICE.md)
- 2G/3G / GERAN: [`docs/PROFILES_2G3G.md`](PROFILES_2G3G.md)

## Haeufige Optionen

```bash
# Nur bestimmte Protokolle analysieren
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2"

# Subscriber-Daten schuetzen (IMSI pseudonymisieren, Tokens entfernen)
pcap2llm analyze sample.pcapng --profile lte-core --privacy-profile share

# 5G N2 gezielt untersuchen
pcap2llm analyze sample.pcapng --profile 5g-n2 -Y "ngap"

# 5G SBI mit strengerem Datenschutz
pcap2llm analyze sample.pcapng --profile 5g-sbi-auth -Y "http2" --privacy-profile prod-safe --two-pass

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
- Profilreferenz: [`docs/PROFILES.md`](PROFILES.md)
- Workflows fuer LTE / 5G / SS7: [`docs/WORKFLOWS.md`](WORKFLOWS.md)
