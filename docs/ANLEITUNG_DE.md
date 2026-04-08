# pcap2llm: Anleitung auf Deutsch

## Zweck des Tools

`pcap2llm` verarbeitet `.pcap`- und `.pcapng`-Dateien mit `tshark` und erzeugt daraus bereinigte, strukturierte Artefakte fuer die Analyse durch Menschen oder LLMs.

Das Tool arbeitet profilbasiert und ist fuer LTE-/EPC-, 5G-Core- sowie Legacy-2G/3G-Analysen mit SS7 und GERAN vorbereitet. Es reduziert die Paketdaten so, dass:

- Layer 2 standardmaessig ausgeblendet wird
- IP-Kontext erhalten bleibt
- Transportdaten nur in kompakter Form erhalten bleiben
- das fachlich wichtigste Protokoll pro Paket moeglichst vollstaendig sichtbar bleibt

## LLM-Vorbereitung

`pcap2llm` ist fuer die Vorbereitung eines nachgelagerten LLM-Schritts gedacht.

- Das wichtigste Uebergabe-Artefakt ist `*_detail.json`.
- `*_summary.json` und `*_summary.md` sind Begleit-Artefakte fuer Abdeckung, Privacy, Auffaelligkeiten und Nachvollziehbarkeit.
- Das Tool selbst macht keine generative Analyse und keine automatische Root-Cause-Erklaerung.
- Fuer maschinenlesbare Orchestrierung gibt es `pcap2llm analyze ... --llm-mode`.

Wenn du genau nach diesem Workflow suchst, sind diese Stellen relevant:

- [`docs/LLM_MODE.md`](LLM_MODE.md)
- [`docs/schema/detail.schema.md`](schema/detail.schema.md)
- [`docs/schema/summary.schema.md`](schema/summary.schema.md)

## Wofuer eignet sich das Tool — und wofuer nicht?

pcap2llm ist fuer **gezielte, fokussierte Captures** gebaut: ein fehlgeschlagener Attach-Vorgang, ein Diameter-Exchange mit unerwartetem Fehler, eine einzelne GTPv2-C-Session, ein Callflow mit einigen Dutzend bis wenigen hundert Signalisierungsnachrichten. Das ist der Sweetspot.

**Gut geeignet fuer:**
- Gefilterte Captures einer einzelnen Signalisierung oder weniger zusammenhaengender Transaktionen
- Analyse eines konkreten Fehlers: ein abgelehnter Call, eine fehlgeschlagene Session, ein Timeout
- Captures von Sekunden bis wenigen Minuten, auf relevante Protokolle gefiltert
- Ein `detail.json` mit einigen hundert Paketen passt problemlos in jedes LLM-Kontextfenster

**Nicht gut geeignet fuer:**
- Megabytes an Rolling-Captures einfach reinschmeissen und erwarten, dass das LLM die Nadel im Heuhaufen findet
- Vollstaendige Traffic-Dumps von Produktionsknoten mit Zehntausenden Paketen — das erzeugte `detail.json` wird zu gross fuer jedes LLM
- Lange Captures mit vielen unzusammenhaengenden Flows — das LLM sieht alles, aber versteht nichts

**Faustregel:** Wenn dein gefilterter Capture mehr als ~2 000 Signalisierungsnachrichten enthaelt, lohnt es sich, ihn vorher nach Flow oder SCTP-/TCP-Stream aufzuteilen. Erst `pcap2llm inspect` nutzen, um den Inhalt zu verstehen, dann mit `-Y` eingrenzen, bevor du `analyze` laeuft.

Das `--max-packets`-Limit (Standard: 1 000) ist eine Sicherheitsbremse, kein Zielwert. Ein enger Filter und ein fokussiertes Zeitfenster liefern deutlich bessere LLM-Ergebnisse als ein grosser Capture, der nachtraeglich abgeschnitten wird.

## Voraussetzungen

Du brauchst:

- Python 3.11 oder neuer
- `tshark` im `PATH` (Wireshark-Paket)

Pruefen:

```bash
python3 --version
tshark -v
```

## Installation

Im Projektverzeichnis:

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

Falls du die Verschluesselungsfunktion nutzen willst:

```bash
pip install -e .[dev,encrypt]
```

Ist die virtuelle Umgebung aktiv, zeigt der Prompt meist `(.venv)` an. Dann beziehen sich `python`, `pip`, `pytest` und `pcap2llm` auf genau diese lokale Umgebung.

## Grundprinzip

Das Tool kennt drei Hauptbefehle:

- `pcap2llm init-config`
- `pcap2llm inspect`
- `pcap2llm analyze`

Hilfe anzeigen:

```bash
pcap2llm --help
pcap2llm inspect --help
pcap2llm analyze --help
```

## 1. Konfigurationsdatei erzeugen

Mit diesem Befehl wird eine Beispiel-Konfiguration angelegt:

```bash
pcap2llm init-config
```

Standardname:

```text
pcap2llm.config.yaml
```

Eine Konfigurationsdatei ist praktisch, wenn du haeufig mit denselben Privacy- oder Mapping-Einstellungen arbeitest. Du kannst dort auch `hosts_file`, `mapping_file` und `display_filter` hinterlegen, damit du sie nicht jedes Mal auf der Kommandozeile angeben musst.

## 2. Capture nur inspizieren

Mit `inspect` bekommst du einen kompakten Ueberblick ueber die Datei, ohne die kompletten Analyse-Artefakte zu erzeugen.

Beispiel:

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Typische Informationen:

- Anzahl Pakete
- erkannte relevante Protokolle
- Transport- und Protokollzaehlung
- Auffaelligkeiten (Transport-Layer und Applikations-Layer)
- Conversation-Uebersicht (konfigurierbar ueber `max_conversations` im Profil)

Mit Display-Filter:

```bash
pcap2llm inspect sample.pcapng --profile lte-core -Y "diameter || gtpv2"
```

Als Datei speichern:

```bash
pcap2llm inspect sample.pcapng --profile lte-core --out inspect.json
```

## 3. Vollstaendige Analyse

Mit `analyze` erzeugst du die eigentlichen Artefakte.

Einfaches Beispiel:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

Das erzeugt standardmaessig:

- Dateinamen beginnen immer mit dem Zeitstempel des ersten Pakets, z. B. `20240406_075320_...`
- jeder Lauf bekommt immer ein Versionssuffix: `_V_01`, `_V_02` usw. (wird automatisch hochgezaehlt, wenn die Datei schon existiert)

| Datei | Inhalt |
|---|---|
| `artifacts/YYYYMMDD_HHMMSS_summary_V_01.json` | Kompakter Ueberblick: Protokolle, Conversations, Anomalien, Timing |
| `artifacts/YYYYMMDD_HHMMSS_detail_V_01.json` | Normalisierte Paket-/Nachrichtendetails |
| `artifacts/YYYYMMDD_HHMMSS_summary_V_01.md` | Menschenlesbare Zusammenfassung |
| `artifacts/YYYYMMDD_HHMMSS_pseudonym_mapping_V_01.json` | Nur bei aktiver Pseudonymisierung |
| `artifacts/YYYYMMDD_HHMMSS_vault_V_01.json` | Nur bei aktiver Verschluesselung |

Die JSON-Ausgabe von `pcap2llm analyze` enthaelt zusaetzlich:
- `artifact_prefix` — den verwendeten Zeitpraefix
- `artifact_version` — `null`, `1`, `2`, ... je nach Dateikollision

Das erzeugte `*_summary.json` enthaelt immer:
- `schema_version` — fuer kuenftige Kompatibilitaetspruefung
- `generated_at` — Erzeugungszeitpunkt als ISO 8601 UTC
- `capture_sha256` — SHA-256-Fingerprint der Eingabedatei fuer Reproduzierbarkeit und Audit

### Maschinenlesbare CLI-Ausgabe fuer LLM-Workflows

Wenn ein zweites Tool oder ein Agent den Lauf direkt auswerten soll, nutze:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --llm-mode
```

Dann bleibt der erzeugte Artefaktsatz gleich, aber stdout enthaelt nur noch ein klar strukturiertes JSON mit:

- Status
- Dateipfaden
- Coverage- und Truncation-Informationen
- Limits
- Warnungen
- stabilen Fehlercodes bei Fehlschlaegen

## Wichtige Optionen

### Profil waehlen

Verfuegbare Profile:

```bash
--profile lte-core
--profile 5g-core
--profile 2g3g-ss7-geran
```

Faustregel:

- `lte-core` fuer LTE / EPC mit Diameter, GTPv2-C, S1AP und NAS-EPS
- `5g-core` fuer 5G Core mit PFCP, NGAP, NAS-5GS und HTTP/2 SBI
- `2g3g-ss7-geran` fuer Legacy-Signalisierung mit SS7, MAP, CAP, ISUP, BSSAP und GERAN ohne UTRAN

### Display-Filter verwenden

Beispiel:

```bash
-Y "diameter"
```

oder:

```bash
--display-filter "s1ap || nas-eps"
```

Beispiele fuer andere Profile:

```bash
pcap2llm inspect sample-5g.pcapng --profile 5g-core -Y "pfcp || ngap || http2"
pcap2llm inspect sample-ss7.pcapng --profile 2g3g-ss7-geran -Y "gsm_map || cap || bssap || isup"
```

### Ausgabeverzeichnis festlegen

```bash
--out ./artifacts
```

### Dry Run

Wenn du nur sehen willst, wie der Lauf geplant ist (kein tshark-Aufruf):

```bash
pcap2llm analyze sample.pcapng --profile lte-core --dry-run
```

### Ausgabemenge begrenzen (--max-packets / --all-packets)

Standardmaessig schreibt `analyze` nur die ersten **1 000 Pakete** in `*_detail.json`. Die Inspektion und alle Statistiken in `*_summary.json` laufen jedoch immer auf dem vollstaendigen Export — das Limit betrifft ausschliesslich den Detail-Output.

```bash
# Standard: erste 1 000 Pakete
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts

# Eigenes Limit
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 500 --out ./artifacts

# Kein Limit – alle Pakete (Achtung: grosses `*_detail.json` bei langen Captures)
pcap2llm analyze sample.pcapng --profile lte-core --all-packets --out ./artifacts
```

Wurde die Ausgabe gekuerzt, enthaelt `*_summary.json` einen `detail_truncated`-Eintrag:

```json
"detail_truncated": {
  "included": 1000,
  "total_exported": 47312,
  "note": "detail.json contains only the first 1,000 of 47,312 packets. Use --all-packets to include all."
}
```

Der `dry-run` zeigt das aktive Limit an:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 500 --dry-run
# → "max_packets": 500

pcap2llm analyze sample.pcapng --profile lte-core --all-packets --dry-run
# → "max_packets": "unlimited"
```

### TShark-Pfad und Two-Pass-Modus

Falls `tshark` nicht im `PATH` liegt:

```bash
pcap2llm analyze sample.pcapng --tshark-path /usr/local/bin/tshark --profile lte-core
```

Fuer Captures mit IP-Fragmentierung oder TCP-Reassembly (z. B. HTTP):

```bash
pcap2llm analyze sample.pcapng --profile lte-core --two-pass
```

## Hostnamen und Aliase aufloesen

Es gibt zwei Mechanismen, die kombiniert werden koennen.

**Vorrang**: Das explizite Mapping hat Vorrang vor der Hosts-Datei. Wenn fuer eine IP keine Zuordnung gefunden wird, wird anhand des Ports auf eine Rolle geschlossen (z. B. Port 3868 → `diameter`, Port 2123 → `gtpc`, Port 8805 → `pfcp`).

### A. Wireshark-Hosts-Datei

Beispiel:

```text
10.10.1.11 mme-fra-a
10.20.8.44 hss-core-1
```

Verwendung:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample \
  --out ./artifacts
```

### B. Eigene Mapping-Datei (mit CIDR-Unterstuetzung)

Einzelne IPs und ganze Subnetze koennen kombiniert werden:

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: Frankfurt
  - ip: 10.20.8.44
    alias: HSS_CORE_1
    role: hss
    site: Munich
  - cidr: 10.30.0.0/16
    alias: eNB_CLUSTER
    role: enb
    site: Berlin
```

Verwendung:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --mapping-file ./examples/mapping.sample.yaml \
  --out ./artifacts
```

Wenn beides gesetzt ist, hat das explizite Mapping Vorrang.

## Anomalie-Erkennung

Das Tool erkennt Auffaelligkeiten auf zwei Ebenen:

### Transport-Layer

- TCP-Retransmissions
- Out-of-Order-Segmente
- SCTP-Analysis-Warnungen

### Applikations-Layer

**Diameter:**
- Unantwortete Requests (kein Answer innerhalb der Capture)
- Fehler-Result-Codes (≥ 3000)
- Doppelte Hop-by-Hop-IDs

**GTPv2-C:**
- Unantwortete Create Session Requests
- Abgelehnte Sessions (Cause ≠ 16)
- Error Indications

Alle Anomalien erscheinen im erzeugten `*_summary.json` unter `anomalies` und werden nach Layer gruppiert in `anomaly_counts_by_layer` ausgegeben.

## Zeitliche Analyse

Das erzeugte `*_summary.json` enthaelt unter `timing_stats` statistische Auswertungen:

- Gesamtdauer der Capture
- min/max/mean/p95 der Inter-Paket-Abstands-Zeiten
- Erkannte Burst-Perioden (`burst_periods`): Zeitabschnitte mit ungewoehnlich dichtem Traffic

Dies hilft, kaskadenartige Fehler ("Timeout bei Paket N → Retransmissions danach") und Verkehrsspitzen zu identifizieren.

## Datenschutz- und Privacy-Modi

Die Schutzmodi werden pro Datenklasse gesetzt.

| Datenklasse | Standard (lte-core) |
|---|---|
| `ip` | `keep` |
| `hostname` | `keep` |
| `subscriber_id` | `pseudonymize` |
| `msisdn` | `pseudonymize` |
| `imsi` | `pseudonymize` |
| `imei` | `mask` |
| `email` | `mask` |
| `distinguished_name` | `pseudonymize` |
| `token` | `remove` |
| `uri` | `mask` |
| `apn_dnn` | `keep` |
| `diameter_identity` | `pseudonymize` |
| `payload_text` | `mask` |

Unterstuetzte Modi (Aliases in Klammern):

- `keep` (alias: `off`) — keine Aenderung
- `mask` (alias: `redact`) — Ersatz durch `[redacted]`
- `pseudonymize` — stabiler hash-basierter Alias, z. B. `IMSI_a3f2b1c4`
- `encrypt` — Fernet-Verschluesselung (benoetigt `cryptography`-Extra)
- `remove` — Feld wird vollstaendig entfernt

**Pseudonyme sind stabil ueber mehrere Laeufe**: Gleicher Originalwert ergibt immer denselben Alias (BLAKE2s-Hash). Das erlaubt Korrelation zwischen verschiedenen Analysen.

### Beispiele

IP-Adressen behalten:

```bash
--ip-mode keep
```

Hostnamen maskieren:

```bash
--hostname-mode mask
```

IMSI pseudonymisieren:

```bash
--imsi-mode pseudonymize
```

Tokens entfernen:

```bash
--token-mode remove
```

Komplettes Beispiel:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --ip-mode keep \
  --hostname-mode mask \
  --subscriber-id-mode pseudonymize \
  --msisdn-mode pseudonymize \
  --imsi-mode pseudonymize \
  --email-mode mask \
  --dn-mode pseudonymize \
  --token-mode remove \
  --mapping-file ./examples/mapping.sample.yaml \
  --hosts-file ./examples/wireshark_hosts.sample \
  --out ./artifacts
```

### Verschluesselung (encrypt-Modus)

1. Extra-Abhaengigkeit installieren:
   ```bash
   pip install -e .[dev,encrypt]
   ```

2. Fernet-Key generieren:
   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. Key als Umgebungsvariable setzen:
   ```bash
   export PCAP2LLM_VAULT_KEY=<dein-key>
   ```

4. Analyse mit Verschluesselung starten:
   ```bash
   pcap2llm analyze sample.pcapng --imsi-mode encrypt --profile lte-core --out ./artifacts
   ```

Wird `PCAP2LLM_VAULT_KEY` nicht gesetzt, erzeugt das Tool einen temporaeren Key fuer diesen Lauf und speichert ihn im erzeugten `*_vault.json`. Ohne den Key koennen die verschluesselten Werte nicht wiederhergestellt werden.

## Bedeutung der Ausgabedateien

### Erzeugtes `*_summary.json`

Gedacht fuer:

- schnellen Ueberblick
- LLM-Prompts
- Automatisierung

Enthaelt unter anderem:

- `capture_metadata`: Dateiname, Paketanzahl, Zeitbereich, erkannte Protokolle
- `protocol_counts` und `transport_counts`: Verteilung nach Protokoll und Transport
- `conversations`: Conversation-Tabelle (Anzahl durch `max_conversations` im Profil begrenzt)
- `anomalies`: Liste aller erkannten Auffaelligkeiten
- `anomaly_counts_by_layer`: Anomalien nach Layer gruppiert
- `timing_stats`: Inter-Paket-Zeiten (min/max/mean/p95) und Gesamtdauer
- `burst_periods`: Zeitabschnitte mit ungewoehnlich dichtem Traffic
- `privacy_modes`: verwendete Datenschutz-Einstellungen
- `schema_version`, `generated_at`, `capture_sha256`: Metadaten fuer Reproduzierbarkeit
- `dropped_packets`: Anzahl nicht verarbeitbarer Pakete (falls > 0)

### Erzeugtes `*_detail.json`

Enthaelt die normalisierten Einzelobjekte. Jedes Paket-Objekt hat:

```json
{
  "packet_no": 4711,
  "time_rel_ms": 12345.67,
  "top_protocol": "diameter",
  "src": { "ip": "10.10.1.11", "alias": "MME_FRA_A", "role": "mme" },
  "dst": { "ip": "10.20.8.44", "alias": "HSS_CORE_1", "role": "hss" },
  "transport": { "proto": "sctp", "stream": 3, "anomaly": false },
  "privacy": { "modes": { "ip": "keep", "imsi": "pseudonymize" } },
  "anomalies": [],
  "message": { "protocol": "diameter", "fields": { "diameter.cmd.code": "316" } }
}
```

### Erzeugtes `*_summary.md`

Gedacht fuer Menschen. Gut geeignet fuer:

- Ticket-Dokumentation
- Incident-Notizen
- Weitergabe im Team

### Erzeugtes `*_pseudonym_mapping.json`

Wird nur erzeugt, wenn `pseudonymize` aktiv ist. Darin stehen die stabilen Ersetzungen fuer diesen Fall (BLAKE2s-Hash, reproduzierbar).

### Erzeugtes `*_vault.json`

Wird nur erzeugt, wenn `encrypt` aktiv ist. Enthaelt Hinweise zur Schluesselquelle. Ohne den Key koennen verschluesselte Werte nicht wiederhergestellt werden.

## Eigene Profile erstellen

Du kannst eigene Profile als YAML-Datei anlegen, ohne Python-Code zu aendern. Lege die Datei in `src/pcap2llm/profiles/` ab und verwende sie mit `--profile <name>`.

Ausfuehrliche Anleitung mit Schema, Beispiel und TShark-Tipps: [`docs/PROFILES.md`](PROFILES.md)

### Protokoll vollstaendig (verbatim) durchreichen

Standardmaessig filtert und normalisiert pcap2llm alle Protokoll-Felder: nur die in `full_detail_fields` gelisteten Felder werden bevorzugt uebernommen, und TShark-Werte werden per `_flatten` vereinfacht (z. B. werden einelementige Listen aufgeloest).

Wenn du ein Protokoll **vollstaendig und ungekuerzt** im erzeugten `*_detail.json` haben moechtest, trags einfach in `verbatim_protocols` ein:

```yaml
verbatim_protocols:
  - gtpv2
```

Was das bewirkt:

- Das **komplette TShark-Layer-Dict** wird unveraendert in `message.fields` geschrieben
- Kein Filtern nach `full_detail_fields`, kein `_flatten`
- Nur `_ws.*`-Schluesseln (Wireshark-interne Metadaten) werden entfernt
- Mehrere Protokolle koennen gleichzeitig eingetragen werden

Beispiel fuer ein LTE-Profil, das GTPv2 komplett behalten soll:

```yaml
# lte-custom.yaml
name: lte-custom
description: LTE-Profil mit vollstaendigem GTPv2

relevant_protocols: [diameter, gtpv2, s1ap]
top_protocol_priority: [diameter, gtpv2, s1ap, sctp, tcp, udp, ip]

verbatim_protocols:
  - gtpv2          # komplette TShark-Schicht, nichts wird herausgefiltert

full_detail_fields:
  diameter:
    - diameter.cmd.code
    - diameter.origin_host
    - diameter.imsi
  # gtpv2 ist hier nicht noetig – verbatim hat Vorrang

reduced_transport_fields: [proto, src_port, dst_port, stream, sctp_stream, anomaly, notes]
tshark:
  two_pass: false
  extra_args: []
```

> **Hinweis:** `verbatim_protocols` hat Vorrang vor `full_detail_fields` fuer dasselbe Protokoll. Wenn du `gtpv2` in beiden eintraegst, gilt verbatim.

## Typische Arbeitsablaeufe

### Schnellpruefung einer Datei

```bash
pcap2llm inspect trace.pcapng --profile lte-core
```

### Analyse mit Aliasen und Privacy-Modi

```bash
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample \
  --mapping-file ./examples/mapping.sample.yaml \
  --imsi-mode pseudonymize \
  --msisdn-mode pseudonymize \
  --token-mode remove \
  --out ./artifacts
```

### Vorab pruefen, was ausgefuehrt wuerde

```bash
pcap2llm analyze trace.pcapng --profile lte-core --dry-run
```

### 5G-Core-Capture mit SBI-Traffic

```bash
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-core \
  -Y "pfcp || ngap || http2" \
  --two-pass \
  --out ./artifacts
```

### SS7-Analyse

```bash
pcap2llm analyze trace-ss7.pcapng \
  --profile 2g3g-ss7-geran \
  -Y "gsm_map || cap || isup || bssap" \
  --out ./artifacts
```

## Fehlersuche

### `tshark was not found in PATH`

`tshark` ist nicht installiert oder nicht im `PATH`.

```bash
tshark -v
which tshark
# macOS:
brew install wireshark
# Ubuntu:
sudo apt install tshark
# Alternativer Pfad:
pcap2llm analyze sample.pcapng --tshark-path /usr/local/bin/tshark --profile lte-core
```

### `tshark output is not valid JSON`

Meistens eine zu alte TShark-Version (< 3.6) oder eine beschaedigte Capture.
TShark aktualisieren oder Capture neu erstellen.

### `PCAP2LLM_VAULT_KEY is not a valid Fernet key`

Der Key muss ein URL-sicherer Base64-kodierter 32-Byte-Wert sein:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Erzeugtes `*_detail.json` enthaelt weniger Pakete als erwartet

Standardmaessig werden nur die ersten 1 000 Pakete in `*_detail.json` geschrieben. Pruefen:

```bash
# Wie viele Pakete wurden tatsaechlich exportiert?
# → im erzeugten `*_summary.json` unter capture_metadata.packet_count

# Wurde gekuerzt?
# → das erzeugte `*_summary.json` enthaelt dann "detail_truncated" mit total_exported

# Alle Pakete aufnehmen:
pcap2llm analyze sample.pcapng --profile lte-core --all-packets

# Oder eigenes Limit:
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 5000
```

### Leeres `*_detail.json` / gar keine Pakete

- Display-Filter pruefen: filtert er alles raus?
- Zuerst ohne Filter testen
- Profil pruefen: passt es zum Traffic? (z. B. `5g-core` fuer 5G-Captures)

### Keine oder unerwartete Ergebnisse

Pruefen:

- passt der Display-Filter?
- ist das richtige Profil gesetzt?
- sind die Mapping-Dateien korrekt?
- enthaelt die Capture wirklich die erwarteten Protokolle?

### Verschluesselung funktioniert nicht

Dann fehlt wahrscheinlich die optionale Abhaengigkeit:

```bash
pip install -e .[dev,encrypt]
```

## Empfehlung fuer den Einstieg

Wenn du neu mit dem Tool startest, ist diese Reihenfolge sinnvoll:

1. `pcap2llm inspect trace.pcapng --profile lte-core`
2. `pcap2llm analyze trace.pcapng --profile lte-core --dry-run`
3. `pcap2llm analyze trace.pcapng --profile lte-core --out ./artifacts`
4. danach zuerst `*_summary.md` und `*_summary.json` ansehen

## Dateien im Repo

Wichtige Stellen im Projekt:

- [`README.md`](../README.md) — englische Hauptdokumentation
- [`docs/PROFILES.md`](PROFILES.md) — eigene Profile erstellen
- `pcap2llm init-config` — erzeugt eine lokale Beispiel-Konfiguration fuer `--config`
- [`examples/mapping.sample.yaml`](../examples/mapping.sample.yaml) — Beispiel-Alias-Mapping
- [`examples/wireshark_hosts.sample`](../examples/wireshark_hosts.sample) — Beispiel-Hosts-Datei
