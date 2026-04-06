# pcap2llm Quickstart auf Deutsch

## In 5 Minuten starten

### 1. Voraussetzungen pruefen

```bash
python3 --version
tshark -v
```

Du brauchst:

- Python 3.11+
- `tshark` im `PATH`

### 2. Installation

Im Projektordner:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### 3. Ersten Ueberblick ueber eine Capture-Datei holen

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Das zeigt dir unter anderem:

- Paketanzahl
- erkannte Protokolle
- Transportzaehlungen
- erste Auffaelligkeiten

### 4. Analyse-Artefakte erzeugen

```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

Danach findest du im Ordner `./artifacts` typischerweise:

- `summary.json`
- `detail.json`
- `summary.md`

### 5. Sinnvolle erste Sichtung

Schau zuerst in dieser Reihenfolge:

1. `artifacts/summary.md`
2. `artifacts/summary.json`
3. `artifacts/detail.json`

## Nuetzliche Befehle

Nur Planung anzeigen:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --dry-run
```

Mit Display-Filter:

```bash
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2"
```

Mit Hosts-Datei und Alias-Mapping:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample \
  --mapping-file ./examples/mapping.sample.yaml \
  --out ./artifacts
```

Mit Privacy-Einstellungen:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --ip-mode keep \
  --imsi-mode pseudonymize \
  --msisdn-mode pseudonymize \
  --token-mode remove \
  --out ./artifacts
```

## Wenn etwas nicht funktioniert

Hilfe anzeigen:

```bash
pcap2llm --help
pcap2llm inspect --help
pcap2llm analyze --help
```

Falls `tshark` fehlt:

```bash
which tshark
tshark -v
```

## Weiterfuehrende Doku

- Ausfuehrliche deutsche Anleitung: [`docs/ANLEITUNG_DE.md`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/docs/ANLEITUNG_DE.md)
- Hauptdokumentation: [`README.md`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/README.md)
