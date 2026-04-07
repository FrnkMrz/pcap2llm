# pcap2llm Quickstart auf Deutsch

## In 5 Minuten starten

### 1. Voraussetzungen pruefen

```bash
python3 --version
tshark -v
```

Du brauchst:

- Python 3.11+
- `tshark` im `PATH` (Wireshark-Paket)

Verfuegbare Standardprofile:

- `lte-core` fuer LTE / EPC (Diameter, GTPv2-C, S1AP, NAS-EPS)
- `5g-core` fuer 5G Core (PFCP, NGAP, NAS-5GS, HTTP/2 SBI)
- `2g3g-ss7-geran` fuer SS7 plus GERAN ohne UTRAN

### 2. Installation

Im Projektordner:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Mit Verschluesselungsunterstuetzung:

```bash
pip install -e .[dev,encrypt]
```

### 3. Ersten Ueberblick ueber eine Capture-Datei holen

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Das zeigt dir unter anderem:

- Paketanzahl
- erkannte Protokolle
- Transportzaehlungen
- erste Auffaelligkeiten (Transport + Applikations-Layer)
- Conversation-Uebersicht

### 4. Analyse-Artefakte erzeugen

```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

Danach findest du im Ordner `./artifacts` typischerweise:

| Datei | Inhalt |
|---|---|
| `summary.json` | Kompakter Ueberblick: Protokolle, Conversations, Anomalien, Timing |
| `detail.json` | Normalisierte Paket-/Nachrichtendetails (Standard: max. 1 000 Pakete) |
| `summary.md` | Menschenlesbare Zusammenfassung |
| `pseudonym_mapping.json` | Nur bei aktiver Pseudonymisierung |
| `vault.json` | Nur bei aktiver Verschluesselung |

`summary.json` enthaelt immer `schema_version`, `generated_at` (ISO 8601 UTC) und `capture_sha256` fuer Reproduzierbarkeit.

> **Grosse Captures:** Standardmaessig werden nur die ersten 1 000 Pakete in `detail.json` geschrieben. `summary.json` und alle Statistiken basieren aber immer auf dem vollstaendigen Export. Wurde gekuerzt, erscheint in `summary.json` ein `detail_truncated`-Eintrag mit der Gesamtzahl.

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

Paketlimit steuern:

```bash
# Alle Pakete in detail.json aufnehmen (Achtung: grosse Dateien)
pcap2llm analyze sample.pcapng --profile lte-core --all-packets

# Eigenes Limit setzen
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 500
```

Mit Display-Filter:

```bash
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2"
```

Fuer andere Netze zum Beispiel:

```bash
pcap2llm analyze sample-5g.pcapng --profile 5g-core -Y "pfcp || ngap || http2"
pcap2llm analyze sample-ss7.pcapng --profile 2g3g-ss7-geran -Y "gsm_map || cap || bssap || isup"
```

Mit Hosts-Datei und Alias-Mapping (inkl. CIDR-Bereichen):

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample \
  --mapping-file ./examples/mapping.sample.yaml \
  --out ./artifacts
```

Beispiel-Mapping mit CIDR-Unterstuetzung:

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: Frankfurt
  - cidr: 10.20.0.0/16
    alias: HSS_CLUSTER
    role: hss
    site: Munich
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

Pseudonyme sind **stabil ueber mehrere Laeufe**: gleiche IMSI ergibt immer denselben Alias (BLAKE2s-Hash), z. B. `IMSI_a3f2b1c4`.

## Wenn etwas nicht funktioniert

Hilfe anzeigen:

```bash
pcap2llm --help
pcap2llm inspect --help
pcap2llm analyze --help
```

Falls `tshark` fehlt oder an einem anderen Pfad liegt:

```bash
which tshark
tshark -v
# alternativer Pfad:
pcap2llm analyze sample.pcapng --tshark-path /usr/local/bin/tshark --profile lte-core
```

Falls `tshark` eine alte Version hat (< 3.6) oder die Ausgabe kein gueltiges JSON liefert:
Wireshark/TShark aktualisieren oder die Capture neu erstellen.

## Weiterfuehrende Doku

- Ausfuehrliche deutsche Anleitung: [`docs/ANLEITUNG_DE.md`](ANLEITUNG_DE.md)
- Hauptdokumentation: [`README.md`](../README.md)
- Eigene Profile erstellen: [`docs/PROFILES.md`](PROFILES.md)
