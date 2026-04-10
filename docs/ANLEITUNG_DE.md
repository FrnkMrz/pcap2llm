# pcap2llm — Vollstaendige Anleitung (Deutsch)

## Was ist das Tool?

`pcap2llm` liest `.pcap`- und `.pcapng`-Dateien ein, normalisiert die Pakete, schutzt sensible Daten und schreibt strukturierte JSON-Artefakte heraus. Das primaere Ausgabe-Artefakt (`detail.json`) ist darauf ausgelegt, einem LLM als Eingabe zu dienen — du kannst es direkt in einen Prompt einfuegen.

Das Tool fuehrt selbst keine KI-Analyse durch. Es formatiert und bereitet vor.

**Sweetspot:** Ein fehlgeschlagener Call, ein Diameter-Fehler, eine GTPv2-Session, ein Callflow mit einigen Dutzend bis wenigen hundert Signalisierungsnachrichten.

**Nicht geeignet fuer:** Mehrstundige Rolling-Captures mit Zehntausenden Paketen. Das erzeugte `detail.json` waere zu gross fuer jedes LLM-Kontextfenster. Im Zweifel zuerst mit `-Y` filtern und `pcap2llm inspect` nutzen, um den Inhalt zu verstehen.

---

## Voraussetzungen und Installation

**Benoetigt:**
- Python 3.11 oder neuer
- `tshark` im PATH (Wireshark-Paket)

```bash
# Pruefen
python3 --version
tshark -v

# Installieren (mit Entwickler-Tools)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]

# Mit Verschluesselungsunterstuetzung
pip install -e .[dev,encrypt]
```

**Windows (PowerShell):**
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

**Falls du hinter einem Unternehmens-Proxy arbeitest:**
```powershell
$env:HTTP_PROXY="http://proxy.example.com:8080"
$env:HTTPS_PROXY="http://proxy.example.com:8080"
python -m pip install --proxy http://proxy.example.com:8080 -e .[dev]
```

Wenn `pip` mit Meldungen wie `getaddrinfo failed` oder `Could not find a version that satisfies the requirement setuptools>=69` scheitert, ist das in der Regel ein Proxy-/Netzwerkproblem und kein Problem mit `setuptools` oder dem Projekt selbst.

---

## Die drei Befehle

### `init-config` — Konfigurationsdatei anlegen

```bash
pcap2llm init-config
```

Legt `pcap2llm.config.yaml` im aktuellen Verzeichnis an. Dort kannst du Standardwerte hinterlegen (Profil, Privacy, Mapping, Display-Filter), damit du sie nicht jedes Mal auf der Kommandozeile angeben musst.

```bash
pcap2llm init-config my-project.yaml   # anderer Dateiname
pcap2llm init-config --force           # vorhandene Datei ueberschreiben
```

### `inspect` — Uebersicht ohne Artefakte

```bash
pcap2llm inspect sample.pcapng --profile lte-core
```

Zeigt: Paketanzahl, erkannte Protokolle, Transportverteilung, Conversations, Anomalien. Schreibt keine Ausgabedateien (ausser mit `--out`). Gut als erster Schritt, um den Inhalt einer unbekannten Capture einzuschaetzen.

```bash
# Mit Display-Filter
pcap2llm inspect sample.pcapng --profile lte-core -Y "diameter || gtpv2"

# Ergebnis in Datei schreiben
pcap2llm inspect sample.pcapng --profile lte-core --out inspect.json

# Nur den tshark-Befehl anzeigen
pcap2llm inspect sample.pcapng --profile lte-core --dry-run
```

### `analyze` — Vollstaendige Analyse

```bash
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts
```

Fuehrt die komplette Pipeline aus und schreibt die Ausgabedateien.

---

## Ausgabedateien

Jeder Lauf erzeugt einen Dateinamen-Satz mit Zeitstempel des ersten Pakets und Versionsnummer:

| Datei | Inhalt |
|---|---|
| `YYYYMMDD_HHMMSS_detail_V_01.json` | Normalisierte Pakete — primaeres LLM-Artefakt |
| `YYYYMMDD_HHMMSS_summary_V_01.json` | Statistiken, Anomalien, Coverage, Privacy-Metadaten |
| `YYYYMMDD_HHMMSS_summary_V_01.md` | Menschenlesbare Zusammenfassung |
| `YYYYMMDD_HHMMSS_pseudonym_mapping_V_01.json` | Nur bei aktiver Pseudonymisierung |
| `YYYYMMDD_HHMMSS_vault_V_01.json` | Nur bei aktiver Verschluesselung |

- `_V_01` ist immer gesetzt; wird automatisch auf `_V_02`, `_V_03` hochgezaehlt wenn Dateien schon existieren
- Beide JSON-Dateien enthalten `schema_version`, `generated_at` (ISO 8601 UTC) und `capture_sha256`
- `summary.json` enthaelt einen `coverage`-Block der zeigt, wie viele Pakete exportiert und wie viele in `detail.json` aufgenommen wurden

---

## Profile

Profile steuern, welche Protokolle extrahiert werden, welche Felder erhalten
bleiben und wie TShark konfiguriert wird.

Fuer die Auswahl reicht im Alltag meist diese Gruppierung:

- `lte-*` fuer LTE / EPC
- `5g-*` fuer 5G SA Core
- `volte-*` und `vonr-*` fuer Voice-over-IMS
- `2g3g-*` fuer Legacy 2G/3G / GERAN

Wenn das genaue Interface noch unklar ist, starte mit dem breiteren
Ueberblicksprofil der Familie, z. B. `lte-core`, `5g-core`, `volte-ims-core`,
`vonr-ims-core` oder `2g3g-ss7-geran`.

Die vollstaendige Profilreferenz ist bewusst ausgelagert:

- Uebersicht: [`docs/PROFILES.md`](PROFILES.md)
- LTE / EPC: [`docs/PROFILES_LTE.md`](PROFILES_LTE.md)
- 5G SA Core: [`docs/PROFILES_5G.md`](PROFILES_5G.md)
- Voice / IMS: [`docs/PROFILES_VOICE.md`](PROFILES_VOICE.md)
- 2G/3G / GERAN: [`docs/PROFILES_2G3G.md`](PROFILES_2G3G.md)

### Protokoll vollstaendig durchreichen (verbatim)

Standardmaessig filtert pcap2llm Protokollfelder und vereinfacht TShark-Werte. `verbatim_protocols` behaelt ein Protokoll mit minimaler Transformation, wenn du mehr Dissektor-Detail brauchst:

```yaml
verbatim_protocols:
  - gtpv2
```

Top-Level-Felder bleiben erhalten, wiederholte verschachtelte Felder koennen in flache `protokoll.*`-Keys hochgezogen werden, und `_ws.*`-Schluessel werden entfernt. Bei Protokollen wie Diameter koennen rohe Decoder-Bloecke wie `diameter.avp`, `diameter.avp_tree` und verwandte `*_tree`-Strukturen mit `keep_raw_avps: false` unterdrueckt werden. Mehr dazu: [`docs/PROFILES.md`](PROFILES.md)

---

## Ausgabemenge steuern

Standardmaessig werden die ersten **1 000 Pakete** in `detail.json` geschrieben. Die Inspektion und alle Statistiken in `summary.json` laufen immer auf dem vollstaendigen Export.

```bash
# Standard: erste 1 000 Pakete
pcap2llm analyze sample.pcapng --profile lte-core --out ./artifacts

# Eigenes Limit
pcap2llm analyze sample.pcapng --profile lte-core --max-packets 300

# Kein Limit (Vorsicht: grosse Dateien bei langen Captures)
pcap2llm analyze sample.pcapng --profile lte-core --all-packets

# Fehler erzeugen wenn Limit ueberschritten wird
pcap2llm analyze sample.pcapng --profile lte-core --fail-on-truncation

# Sehr grosse Captures ablehnen (Standard: 250 MiB, 0=deaktiviert)
pcap2llm analyze sample.pcapng --profile lte-core --max-capture-size-mb 100
```

Wurde gekuerzt, enthaelt `summary.json` einen `detail_truncated`-Eintrag:

```json
"detail_truncated": {
  "included": 1000,
  "total_exported": 47312,
  "note": "detail.json contains only the first 1,000 of 47,312 packets."
}
```

---

## Display-Filter

TShark-Display-Filter grenzen den analysierten Traffic ein. Sie werden vor der Normalisierung angewendet.

```bash
# Nur Diameter
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter"

# Diameter oder GTPv2
pcap2llm analyze sample.pcapng --profile lte-core -Y "diameter || gtpv2"

# 5G N2 / NGAP
pcap2llm analyze sample-5g.pcapng --profile 5g-n2 -Y "ngap"

# 5G SBI / HTTP2
pcap2llm analyze sample-5g.pcapng --profile 5g-sbi -Y "http2"

# SS7
pcap2llm analyze sample-ss7.pcapng --profile 2g3g-ss7-geran -Y "gsm_map || cap || isup"
```

---

## Endpunkte benennen

Zwei Mechanismen, die kombiniert werden koennen:

### A. Wireshark-Hosts-Datei

```text
10.10.1.11 mme-fra-a
10.20.8.44 hss-core-1
```

```bash
pcap2llm analyze sample.pcapng --profile lte-core \
  --hosts-file ./examples/wireshark_hosts.sample
```

### B. Eigene Mapping-Datei (mit CIDR-Unterstuetzung)

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
    site: Frankfurt
  - ip: 10.20.8.44
    alias: HSS_CORE_1
    role: hss
  - cidr: 10.30.0.0/16
    alias: eNB_CLUSTER
    role: enb
    site: Berlin
```

```bash
pcap2llm analyze sample.pcapng --profile lte-core \
  --mapping-file ./examples/mapping.sample.yaml
```

**Vorrang:** Explizites Mapping hat Vorrang vor der Hosts-Datei. Wenn keine Zuordnung gefunden wird, wird anhand des Ports auf eine Rolle geschlossen (Port 3868 → `diameter`, Port 2123 → `gtpc`, Port 8805 → `pfcp`).

---

## Datenschutz und Privacy-Modi

### Privacy-Profile (empfohlener Weg)

| Privacy-Profil | Was es tut |
|---|---|
| `internal` | Alles behalten |
| `share` | Subscriber-IDs pseudonymisieren, Tokens entfernen |
| `lab` | Subscriber-Daten pseudonymisieren, IPs maskieren |
| `prod-safe` | Maximaler Schutz: IPs maskieren, alles PII pseudonymisieren oder entfernen |

```bash
pcap2llm analyze sample.pcapng --profile lte-core --privacy-profile share
```

### Einzelne Datenklassen ueberschreiben

Alle 13 Datenklassen koennen individuell gesteuert werden:

```
--ip-mode               IP-Adressen
--hostname-mode         Hostnamen
--subscriber-id-mode    Allgemeine Subscriber-IDs
--msisdn-mode           MSISDN
--imsi-mode             IMSI
--imei-mode             IMEI
--email-mode            E-Mail-Adressen
--dn-mode               Distinguished Names
--token-mode            Tokens / Credentials
--uri-mode              URIs
--apn-dnn-mode          APN / DNN
--diameter-identity-mode  Diameter-Identitaeten
--payload-text-mode     Payload-Text
```

**Verfuegbare Modi:**
- `keep` (Alias: `off`) — unveraendert behalten
- `mask` (Alias: `redact`) — durch `[redacted]` ersetzen
- `pseudonymize` — stabiler hash-basierter Alias, z. B. `IMSI_a3f2b1c4`
- `encrypt` — Fernet-Verschluesselung (benoetigt `cryptography`-Extra)
- `remove` — Feld vollstaendig entfernen

**Pseudonyme sind stabil ueber mehrere Laeufe:** Gleicher Originalwert ergibt immer denselben Alias (BLAKE2s-Hash). Das erlaubt Korrelation zwischen verschiedenen Analysen.

### Beispiel: Share-Profil mit Ueberschreibung

```bash
pcap2llm analyze sample.pcapng \
  --profile lte-core \
  --privacy-profile share \
  --imei-mode remove \
  --ip-mode keep \
  --out ./artifacts
```

### Verschluesselung

```bash
# Extra-Abhaengigkeit installieren
pip install -e .[dev,encrypt]

# Fernet-Key generieren
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Key als Umgebungsvariable setzen
export PCAP2LLM_VAULT_KEY=<dein-key>

# Analyse mit Verschluesselung
pcap2llm analyze sample.pcapng --imsi-mode encrypt --profile lte-core --out ./artifacts
```

Wird `PCAP2LLM_VAULT_KEY` nicht gesetzt, erzeugt das Tool einen temporaeren Key und speichert ihn in `vault.json`. Ohne den Key koennen die verschluesselten Werte nicht wiederhergestellt werden.

---

## Anomalie-Erkennung

Das Tool erkennt automatisch:

**Transport-Layer:**
- TCP-Retransmissions
- Out-of-Order-Segmente
- SCTP-Analysis-Warnungen

**Diameter:**
- Unantwortete Requests
- Fehler-Result-Codes (≥ 3000)
- Doppelte Hop-by-Hop-IDs

**GTPv2-C:**
- Unantwortete Create Session Requests
- Abgelehnte Sessions (Cause ≠ 16)
- Error Indications

Alle Anomalien erscheinen in `summary.json` unter `anomalies` und `anomaly_counts_by_layer`.

---

## Zeitliche Analyse

`summary.json` enthaelt unter `timing_stats`:

- Gesamtdauer der Capture
- min / max / mean / p95 der Inter-Paket-Zeiten
- Erkannte Burst-Perioden (`burst_periods`): Zeitabschnitte mit ungewoehnlich dichtem Traffic

Hilfreich um kaskadenartige Fehler (Timeout → Retransmissions danach) und Verkehrsspitzen zu identifizieren.

---

## TShark-Optionen

```bash
# tshark nicht im PATH
pcap2llm analyze sample.pcapng --tshark-path /usr/local/bin/tshark --profile lte-core

# Two-Pass fuer bessere Reassembly (z. B. HTTP, fragmentierte Pakete)
pcap2llm analyze sample.pcapng --profile lte-core --two-pass

# Benutzerdefinierter Port-Decoder
pcap2llm analyze sample.pcapng --profile 5g-core \
  --tshark-arg "-d" --tshark-arg "tcp.port==8443,http2"
```

---

## Automatisierung und LLM-Mode

Mit `--llm-mode` gibt die CLI ein maschinenlesbares JSON aus (statt normalem Text). Geeignet fuer Skripte und Agenten:

```bash
pcap2llm analyze sample.pcapng --profile lte-core --llm-mode --out ./artifacts
```

Das JSON enthaelt `status`, `coverage`, `artifact_prefix`, `artifact_version` und bei Fehlern einen `error_code`. Mehr dazu: [`docs/LLM_MODE.md`](LLM_MODE.md)

---

## Fehlersuche

**`tshark was not found in PATH`**
```bash
which tshark
tshark -v
# macOS: brew install wireshark
# Ubuntu: sudo apt install tshark
# Alternativer Pfad: --tshark-path /usr/local/bin/tshark
```

**`tshark output is not valid JSON`**
Zu alte TShark-Version (< 3.6) oder beschaedigte Capture. TShark aktualisieren.

**`PCAP2LLM_VAULT_KEY is not a valid Fernet key`**
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**`detail.json` enthaelt weniger Pakete als erwartet**
Standard-Limit ist 1 000. `summary.json` enthaelt einen `detail_truncated`-Eintrag mit der Gesamtzahl. `--all-packets` oder `--max-packets N` verwenden.

**Leeres `detail.json`**
Display-Filter pruefen — filtert er alles raus? Ohne Filter testen. Profil pruefen: passt es zum Traffic?

**Verschluesselung schlaegt fehl**
```bash
pip install -e .[dev,encrypt]
```

---

## Typische Arbeitsablaeufe

```bash
# 1. Unbekannte Datei einschaetzen
pcap2llm inspect trace.pcapng --profile lte-core

# 2. Gefilterte Analyse
pcap2llm analyze trace.pcapng --profile lte-core \
  -Y "diameter" \
  --privacy-profile share \
  --mapping-file ./mapping.yaml \
  --out ./artifacts

# 3. 5G Core
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-core \
  -Y "pfcp || ngap || http2" \
  --two-pass \
  --out ./artifacts

# 4. SS7
pcap2llm analyze trace-ss7.pcapng \
  --profile 2g3g-ss7-geran \
  -Y "gsm_map || cap || isup || bssap" \
  --out ./artifacts
```

---

## Dokumentation im Ueberblick

| Dokument | Inhalt |
|---|---|
| [`../README.md`](../README.md) | Englischer Ueberblick und Schnellstart |
| [`REFERENCE.md`](REFERENCE.md) | Vollstaendige englische Referenz |
| [`QUICKSTART_DE.md`](QUICKSTART_DE.md) | Deutscher Schnellstart (1 Seite) |
| [`WORKFLOWS.md`](WORKFLOWS.md) | Schritt-fuer-Schritt-Workflows fuer LTE, 5G, SS7 |
| [`PROFILES.md`](PROFILES.md) | Eigene Analyse-Profile erstellen |
| [`LLM_MODE.md`](LLM_MODE.md) | Maschinenlesbarer JSON-Modus |
| [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md) | Privacy-Modell und Datenweitergabe |
| [`schema/`](schema/) | JSON-Schema-Referenz fuer Ausgabedateien |
| [`security/`](security/) | Bedrohungsmodell, Verschluesselungsmodell |
| [`architecture/`](architecture/) | Pipeline-Internals |
