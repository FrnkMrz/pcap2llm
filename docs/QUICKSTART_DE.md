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

Unter Windows in PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

Mit Verschluesselungsunterstuetzung:

```bash
pip install -e .[dev,encrypt]
```

Wenn die Umgebung aktiv ist, zeigt der Prompt in der Regel `(.venv)` an. Dann laufen `python`, `pip`, `pytest` und `pcap2llm` innerhalb dieser virtuellen Umgebung.

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

- Dateinamen mit Zeitpraefix aus dem ersten Paket, z. B. `20240406_075320_summary.json`
- bei erneutem Lauf mit gleichem Zeitstempel automatisch ein Versionssuffix wie `_V1`

| Datei | Inhalt |
|---|---|
| `YYYYMMDD_HHMMSS_summary.json` | Kompakter Ueberblick: Protokolle, Conversations, Anomalien, Timing |
| `YYYYMMDD_HHMMSS_detail.json` | Normalisierte Paket-/Nachrichtendetails (Standard: max. 1 000 Pakete) |
| `YYYYMMDD_HHMMSS_summary.md` | Menschenlesbare Zusammenfassung |
| `YYYYMMDD_HHMMSS_pseudonym_mapping.json` | Nur bei aktiver Pseudonymisierung |
| `YYYYMMDD_HHMMSS_vault.json` | Nur bei aktiver Verschluesselung |

Die JSON-Ausgabe der CLI enthaelt ausserdem `artifact_prefix` und `artifact_version`, damit Skripte den erzeugten Dateisatz eindeutig erkennen koennen.

Das erzeugte `*_summary.json` enthaelt immer `schema_version`, `generated_at` (ISO 8601 UTC) und `capture_sha256` fuer Reproduzierbarkeit.

> **Grosse Captures:** Standardmaessig werden nur die ersten 1 000 Pakete in `*_detail.json` geschrieben. `*_summary.json` und alle Statistiken basieren aber immer auf dem vollstaendigen Export. Wurde gekuerzt, erscheint in `*_summary.json` ein `detail_truncated`-Eintrag mit der Gesamtzahl.

### 5. Sinnvolle erste Sichtung

Schau zuerst in dieser Reihenfolge:

1. `artifacts/*_summary.md`
2. `artifacts/*_summary.json`
3. `artifacts/*_detail.json`

## Nuetzliche Befehle

Nur Planung anzeigen:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --dry-run
```

Paketlimit steuern:

```bash
# Alle Pakete in das erzeugte Detail-Artefakt aufnehmen (Achtung: grosse Dateien)
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

## Protokoll vollstaendig durchreichen (verbatim)

Standardmaessig filtert pcap2llm Protokoll-Felder und vereinfacht TShark-Werte. Wenn du ein Protokoll **komplett und ungekuerzt** im erzeugten `*_detail.json` haben willst, trag es in `verbatim_protocols` in deinem Profil ein:

```yaml
# in deiner Profil-YAML
verbatim_protocols:
  - gtpv2   # komplette TShark-Schicht, kein Filtern, kein Flatten
```

Das komplette TShark-Layer-Dict landet dann unveraendert in `message.fields` — nur `_ws.*`-Schluesseln werden entfernt. Mehrere Protokolle koennen gleichzeitig eingetragen werden.

Weitere Details: [`docs/ANLEITUNG_DE.md`](ANLEITUNG_DE.md) und [`docs/PROFILES.md`](PROFILES.md).

## Weiterfuehrende Doku

- Ausfuehrliche deutsche Anleitung: [`docs/ANLEITUNG_DE.md`](ANLEITUNG_DE.md)
- Hauptdokumentation: [`README.md`](../README.md)
- Eigene Profile erstellen: [`docs/PROFILES.md`](PROFILES.md)
