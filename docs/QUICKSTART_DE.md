# pcap2llm - Schnellstart (Deutsch)

Dieses Dokument ist bewusst kurz. Es soll dich in wenigen Minuten vom Klonen
bis zum ersten sinnvollen Lauf bringen.

Wenn du danach tiefer einsteigen willst:

- komplette Dokumentationslandkarte: [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md)
- deutsche Praxisanleitung: [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md)
- englische Vollreferenz: [`REFERENCE.md`](REFERENCE.md)

## Voraussetzungen

- Python 3.11+
- `tshark` im PATH

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

## Vier Schritte fuer den Einstieg

### 1. Schnell sehen, was in der Capture steckt

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Nutze `inspect`, wenn du schon ungefaehr weisst, in welche Profilfamilie der
Trace gehoert.

### 2. Wenn der Trace noch unklar ist: `discover`

```bash
pcap2llm discover sample.pcapng
```

`discover` ist der breite Scout-Lauf fuer unbekannte Captures. Er hilft dir bei
der Frage:

> Welches Profil sollte ich danach gezielt fahren?

Optional:

```bash
pcap2llm recommend-profiles artifacts/discover_sample_start_1_V_01.json
```

### 3. Die eigentliche Analyse schreiben

```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

Danach findest du typischerweise:

| Datei | Inhalt |
|---|---|
| `...detail.json` | Normalisierte Pakete, primaeres LLM-Artefakt |
| `...summary.json` | Statistik, Anomalien, Coverage |
| `...summary.md` | Menschenlesbare Zusammenfassung |
| `...flow.json` | Optionales Flow-Modell bei `--render-flow-svg` |
| `...flow.svg` | Optionale Signalisierungs-Grafik bei `--render-flow-svg` |

### 4. Erst dann feinjustieren

Zum Beispiel:

```bash
# Nur bestimmte Protokolle
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2"

# Datenschutz fuer Weitergabe
pcap2llm analyze sample.pcapng --profile lte-core --privacy-profile share

# Nur den Plan anzeigen
pcap2llm analyze sample.pcapng --profile lte-core --dry-run

# Signalisierungs-Flow als SVG erzeugen
pcap2llm analyze sample.pcapng --profile lte-core --render-flow-svg --out ./artifacts

# Vorhandenes Flow-JSON ohne neuen TShark-Lauf neu rendern
pcap2llm visualize ./artifacts/analyze_sample_start_1_V_01_flow.json --width 1800
```

## Welche Profilfamilie?

Die Daumenregel fuer den Anfang:

- `lte-*` fuer LTE / EPC
- `5g-*` fuer 5G SA Core
- `volte-*` und `vonr-*` fuer Voice-over-IMS
- `2g3g-*` fuer 2G/3G / GERAN / SS7

Wenn du das genaue Interface noch nicht kennst, nimm zuerst ein breiteres
Familienprofil wie `lte-core`, `5g-core`, `volte-ims-core`, `vonr-ims-core`
oder `2g3g-ss7-geran`.

## Was du hier nicht suchen musst

Diese Schnellstartseite erklaert **nicht** alle Optionen.

Dafuer gibt es die naechsten Ebenen:

- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md): kompletter Ueberblick ueber alle Doku-Seiten
- [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md): typische Nutzung in Deutsch
- [`REFERENCE.md`](REFERENCE.md): exakte englische Befehls- und Optionsreferenz
- [`DISCOVERY.md`](DISCOVERY.md): was `discover` genau macht
