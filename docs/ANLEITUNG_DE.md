# pcap2llm: Anleitung auf Deutsch

## Zweck des Tools

`pcap2llm` verarbeitet `.pcap`- und `.pcapng`-Dateien mit `tshark` und erzeugt daraus bereinigte, strukturierte Artefakte fuer die Analyse durch Menschen oder LLMs.

Das Tool ist besonders fuer LTE-/EPC-Troubleshooting vorbereitet. Es reduziert die Paketdaten so, dass:

- Layer 2 standardmaessig ausgeblendet wird
- IP-Kontext erhalten bleibt
- Transportdaten nur in kompakter Form erhalten bleiben
- das fachlich wichtigste Protokoll pro Paket moeglichst vollstaendig sichtbar bleibt

## Voraussetzungen

Du brauchst:

- Python 3.11 oder neuer
- `tshark` im `PATH`

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

Falls du die Verschluesselungsfunktion nutzen willst:

```bash
pip install -e .[dev,encrypt]
```

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

Eine Konfigurationsdatei ist praktisch, wenn du haeufig mit denselben Privacy- oder Mapping-Einstellungen arbeitest.

## 2. Capture nur inspizieren

Mit `inspect` bekommst du einen kompakten Ueberblick ueber die Datei, ohne die kompletten Analyse-Artefakte zu erzeugen.

Beispiel:

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Typische Informationen:

- Anzahl Pakete
- erkannte relevante Protokolle
- einfache Transport- und Protokollzaehlung
- erste Auffaelligkeiten
- einfache Conversation-Uebersicht

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

- `artifacts/summary.json`
- `artifacts/detail.json`
- `artifacts/summary.md`

## Wichtige Optionen

### Profil waehlen

Aktuell ist vor allem dieses Profil vorgesehen:

```bash
--profile lte-core
```

### Display-Filter verwenden

Beispiel:

```bash
-Y "diameter"
```

oder:

```bash
--display-filter "s1ap || nas-eps"
```

### Ausgabeverzeichnis festlegen

```bash
--out ./artifacts
```

### Dry Run

Wenn du nur sehen willst, wie der Lauf geplant ist:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --dry-run
```

## Hostnamen und Aliase aufloesen

Es gibt zwei Mechanismen:

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

### B. Eigene Mapping-Datei

Beispiel:

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: fra
  - ip: 10.20.8.44
    alias: HSS_CORE_1
    role: hss
    site: dc1
```

Verwendung:

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --mapping-file ./examples/mapping.sample.yaml \
  --out ./artifacts
```

Wenn beides gesetzt ist, hat das explizite Mapping Vorrang.

## Datenschutz- und Privacy-Modi

Die Schutzmodi werden pro Datenklasse gesetzt. Wichtige Datenklassen sind zum Beispiel:

- `ip`
- `hostname`
- `subscriber_id`
- `msisdn`
- `imsi`
- `imei`
- `email`
- `distinguished_name`
- `token`
- `uri`
- `apn_dnn`
- `diameter_identity`
- `payload_text`

Unterstuetzte Modi:

- `keep`
- `mask`
- `pseudonymize`
- `encrypt`
- `remove`

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

## Bedeutung der Ausgabedateien

### `summary.json`

Gedacht fuer:

- schnellen Ueberblick
- LLM-Prompts
- Automatisierung

Enthaelt unter anderem:

- Capture-Metadaten
- relevante Protokolle
- Flow-/Conversation-Uebersicht
- Paket- und Message-Zaehlungen
- Auffaelligkeiten
- verwendetes Profil
- verwendete Privacy-Modi

### `detail.json`

Enthaelt die normalisierten Einzelobjekte.

Typische Inhalte:

- Paketnummer
- Zeitinformationen
- `src` und `dst`
- Transportkontext
- oberstes relevantes Protokoll
- ausgewaehlte Message-Felder

### `summary.md`

Gedacht fuer Menschen. Gut geeignet fuer:

- Ticket-Dokumentation
- Incident-Notizen
- Weitergabe im Team

### `pseudonym_mapping.json`

Wird nur erzeugt, wenn `pseudonymize` aktiv ist. Darin stehen die stabilen Ersetzungen innerhalb eines Falls.

### `vault.json`

Wird nur erzeugt, wenn `encrypt` aktiv ist. Enthält Hinweise zur lokalen Schluesselverwendung.

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

## Fehlersuche

### `tshark was not found in PATH`

Dann ist `tshark` nicht installiert oder nicht im `PATH`.

Pruefe:

```bash
tshark -v
which tshark
```

### Keine oder unerwartete Ergebnisse

Pruefe:

- passt der Display-Filter?
- ist das richtige Profil gesetzt?
- sind die Mapping-Dateien korrekt?
- enthaelt die Capture-Datei wirklich die erwarteten Protokolle?

### Verschluesselung funktioniert nicht

Dann fehlt wahrscheinlich die optionale Abhaengigkeit:

```bash
pip install -e .[dev,encrypt]
```

Optional kannst du einen lokalen Key setzen:

```bash
export PCAP2LLM_VAULT_KEY="..."
```

## Empfehlung fuer den Einstieg

Wenn du neu mit dem Tool startest, ist diese Reihenfolge sinnvoll:

1. `pcap2llm inspect trace.pcapng --profile lte-core`
2. `pcap2llm analyze trace.pcapng --profile lte-core --dry-run`
3. `pcap2llm analyze trace.pcapng --profile lte-core --out ./artifacts`
4. danach `summary.md` und `summary.json` zuerst ansehen

## Dateien im Repo

Wichtige Stellen im Projekt:

- [`README.md`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/README.md)
- [`docs/ANLEITUNG_DE.md`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/docs/ANLEITUNG_DE.md)
- [`examples/config.sample.yaml`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/examples/config.sample.yaml)
- [`examples/mapping.sample.yaml`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/examples/mapping.sample.yaml)
- [`examples/wireshark_hosts.sample`](/Users/frank/Library/Mobile%20Documents/com~apple~CloudDocs/GitHub/pcap4llm/examples/wireshark_hosts.sample)
