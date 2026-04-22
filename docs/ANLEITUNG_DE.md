# pcap2llm - Praxisanleitung (Deutsch)

Diese Anleitung erklaert die normale Arbeit mit `pcap2llm` in Deutsch:

- wie du von einer Capture zum passenden Analyse-Lauf kommst
- wann du `inspect`, `discover` oder `analyze` verwendest
- was die wichtigsten Stellschrauben im Alltag sind

Sie ist **bewusst keine komplette Optionsreferenz**. Die exakte englische
Referenz liegt in [`REFERENCE.md`](REFERENCE.md).

## Welche Doku wofuer?

Die Dokumente haben jetzt bewusst getrennte Rollen:

- [`../README.md`](../README.md): erster Einstieg und Doku-Navigation
- [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md): komplette Landkarte aller Doku-Dateien
- [`QUICKSTART_DE.md`](QUICKSTART_DE.md): der kuerzeste deutsche Einstieg
- [`ANLEITUNG_DE.md`](ANLEITUNG_DE.md): alltagstaugliche Nutzung in Deutsch
- [`REFERENCE.md`](REFERENCE.md): technische Vollreferenz in Englisch
- [`DISCOVERY.md`](DISCOVERY.md): tieferer Guide fuer `discover`

Wenn du neu im Projekt bist, starte im README oder im deutschen Quickstart.
Wenn du exakt wissen willst, wie ein Befehl oder eine Option heisst, geh direkt
in die englische Referenz.

## Was das Tool macht

`pcap2llm` liest `.pcap`- und `.pcapng`-Dateien, normalisiert Protokollinhalte,
schuetzt sensible Daten und schreibt strukturierte Artefakte fuer Troubleshooting
und LLM-Handoffs.

Das Tool fuehrt selbst **keine** KI-Analyse durch. Es bereitet die Daten nur so
auf, dass du sie sauber weiterverarbeiten oder mit einem externen LLM teilen
kannst.

**Sweetspot:** fokussierte Signalisierungs-Traces mit einigen Dutzend bis wenigen
hundert relevanten Paketen.

## Der normale Ablauf

Im Alltag gibt es zwei typische Startpunkte.

### Fall A - Du kennst die Richtung schon

Zum Beispiel: "Das ist wahrscheinlich S6a", "das ist NGAP", "das ist SIP/IMS".

Dann ist der normale Weg:

```bash
pcap2llm inspect trace.pcapng --profile lte-s6a
pcap2llm analyze trace.pcapng --profile lte-s6a --out ./artifacts
```

`inspect` gibt dir eine schnelle Uebersicht, ohne Artefakte zu schreiben.
`analyze` macht danach den eigentlichen, speicherbaren Lauf.

### Fall B - Die Capture ist noch unklar

Dann solltest du nicht direkt raten, sondern gestuft vorgehen:

```bash
pcap2llm discover trace.pcapng
pcap2llm recommend-profiles artifacts/discover_trace_start_1_V_01.json
pcap2llm analyze trace.pcapng --profile <ausgewaehltes-profil> --out ./artifacts
```

Das ist besonders sinnvoll, wenn:

- die Capture mehrere Protokollfamilien mischt
- das Interface noch nicht klar ist
- du die Auswahl spaeter reproduzierbar dokumentieren willst
- ein Agent oder Script den naechsten Schritt entscheiden soll

## `inspect`, `discover`, `analyze` - wann was?

### `inspect`

Nutze `inspect`, wenn du schnell als Mensch verstehen willst, was in der Datei
steckt, ohne gleich Artefakte zu erzeugen.

Typische Fragen:

- Wie viele Pakete sind das?
- Welche Protokolle tauchen auf?
- Ist das eher LTE, 5G, IMS oder Legacy?
- Ist mein geplanter Filter sinnvoll?

Beispiel:

```bash
pcap2llm inspect trace.pcapng --profile 5g-core
pcap2llm inspect trace.pcapng --profile lte-core -Y "diameter || gtpv2"
```

### `discover`

`discover` ist der breite Scout-Lauf fuer unbekannte oder gemischte Captures.
Er schreibt bewusst zwei kleine Artefakte:

- `discover_...json` fuer Maschinen, Agenten und reproduzierbare Auswahl
- `discover_...md` fuer Menschen

`discover` beantwortet nicht die Endfrage "wo ist der Fehler?", sondern die
Vorfrage:

> Welche Profilfamilie oder welches Interface sollte ich als Naechstes gezielt analysieren?

Beispiel:

```bash
pcap2llm discover trace.pcapng
pcap2llm discover trace.pcapng -Y "ngap || nas-5gs || http2"
```

### `analyze`

`analyze` ist der eigentliche Produktivlauf. Hier entstehen die Artefakte, die
du lokal auswertest oder spaeter an ein externes LLM weitergibst.

```bash
pcap2llm analyze trace.pcapng --profile 5g-n11 --out ./artifacts
```

Wenn du den Lauf erst pruefen willst:

```bash
pcap2llm analyze trace.pcapng --profile 5g-n11 --dry-run
```

## Welche Dateien entstehen?

Jeder `analyze`-Lauf schreibt einen logisch benannten Dateisatz:

| Datei | Bedeutung |
|---|---|
| `analyze_<capture>_start_<n>_V_01_detail.json` | Primaeres LLM-Artefakt mit normalisierten Paketen |
| `analyze_<capture>_start_<n>_V_01_summary.json` | Statistik, Anomalien, Timing, Coverage |
| `analyze_<capture>_start_<n>_V_01_summary.md` | Menschenlesbare Zusammenfassung |
| `analyze_<capture>_start_<n>_V_01_flow.json` | Optionales Signalisierungs-Flow-Modell bei `--render-flow-svg` |
| `analyze_<capture>_start_<n>_V_01_flow.svg` | Optionale Sequenzdiagramm-Grafik bei `--render-flow-svg` |
| `analyze_<capture>_start_<n>_V_01_pseudonym_mapping.json` | Nur bei Pseudonymisierung |
| `analyze_<capture>_start_<n>_V_01_vault.json` | Nur bei Verschluesselung |

Die Ausgaben von `inspect`, `discover` und `analyze` beginnen einheitlich mit:

1. action
2. capture file
3. start packet
4. artifact version

Das ist gut fuer Vergleiche zwischen mehreren Laeufen.

## Signalisierungs-Flow visualisieren

Wenn du neben JSON und Markdown eine schnelle visuelle Orientierung brauchst,
aktiviere beim Analyse-Lauf die Flow-Ausgabe:

```bash
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  --render-flow-svg \
  --out ./artifacts
```

Dann entstehen zusaetzlich `flow.json` und `flow.svg`. Das Flow-JSON enthaelt
Lanes, Events, Phasen, Korrelationen und Repeat-Metadaten; das SVG ist ein
Sequenzdiagramm mit Hover-Tooltips. Die Labels nutzen, soweit im Trace
vorhanden, protokollspezifische Details wie Diameter Result-Code, GTPv2
Message/Cause, NGAP Procedure, NAS-EPS/NAS-5GS Message Type, HTTP/2
Methode/Pfad/Status und DNS Query/Rcode/Antwortzahl. Fehlerhafte Antworten
werden visuell hervorgehoben.

Wenn du nur die Darstellung neu erzeugen willst, ohne TShark oder die Pipeline
erneut zu starten:

```bash
pcap2llm visualize ./artifacts/analyze_trace_start_1_V_01_flow.json --width 1800
```

## Profile sinnvoll waehlen

Im Alltag reicht zuerst die Familienwahl:

- `lte-*` fuer LTE / EPC
- `5g-*` fuer 5G SA Core
- `volte-*` und `vonr-*` fuer Voice-over-IMS
- `2g3g-*` fuer 2G/3G / GERAN / SS7

Wenn das Interface noch unklar ist, starte breit:

- `lte-core`
- `5g-core`
- `volte-ims-core`
- `vonr-ims-core`
- `2g3g-ss7-geran`

Wenn das Interface klar ist, wechsle auf das engere Profil, zum Beispiel:

- `lte-s6a` statt `lte-core`
- `5g-n11` statt `5g-core`
- `volte-sip-call` statt `volte-ims-core`

Die eigentlichen Profilkataloge sind ausgelagert:

- [`PROFILES.md`](PROFILES.md)
- [`PROFILES_LTE.md`](PROFILES_LTE.md)
- [`PROFILES_5G.md`](PROFILES_5G.md)
- [`PROFILES_VOICE.md`](PROFILES_VOICE.md)
- [`PROFILES_2G3G.md`](PROFILES_2G3G.md)

## Filter und Datenmenge

Der wichtigste Hebel fuer gute Ergebnisse ist fast immer der Display-Filter
`-Y`, nicht eine immer groessere Paketgrenze.

Beispiele:

```bash
# Diameter oder GTPv2 in LTE
pcap2llm analyze trace.pcapng --profile lte-core -Y "diameter || gtpv2"

# Nur NGAP
pcap2llm analyze trace.pcapng --profile 5g-n2 -Y "ngap"

# HTTP/2 SBI
pcap2llm analyze trace.pcapng --profile 5g-sbi -Y "http2" --two-pass
```

Wichtige Regel:

- `detail.json` ist standardmaessig auf 1.000 Pakete begrenzt
- die Voranalyse und Summary betrachten trotzdem die komplette gefilterte Menge
- ein engerer `-Y`-Filter ist meist wertvoller als `--all-packets`

Nutze groessere Limits nur, wenn du wirklich weisst, dass der exportierte
Fensterbereich trotzdem noch fachlich zusammenhaengt.

## Datenschutz und Weitergabe

Privacy ist absichtlich von der Profilwahl getrennt.

Typische Startpunkte:

- `internal`: lokal, unveraendert
- `share`: intern teilen, Subscriber-Daten pseudonymisieren
- `prod-safe`: staerker schuetzen, bevor du nach aussen gehst
- `llm-telecom-safe`: guter Standard fuer externe LLMs

Beispiel:

```bash
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  --privacy-profile share \
  --out ./artifacts
```

Fuer externe LLMs gilt:

- niemals die rohe PCAP teilen
- `pseudonym_mapping.json`, `vault.json` und Schluesselmaterial getrennt halten
- moeglichst nur `summary.json` plus einen gezielten Ausschnitt aus `detail.json` weitergeben

Mehr dazu:

- [`PRIVACY_SHARING.md`](PRIVACY_SHARING.md)
- [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md)

## Endpunkte lesbarer machen

Du kannst rohe IPs durch bekannte Knoten- oder Rollennamen anreichern.

### Einfache Variante: `.local/hosts`

Lege eine Wireshark-kompatible Hosts-Datei lokal ab:

```text
.local/hosts
```

Beispiel:

```text
10.10.1.11 mme-fra-a
10.20.8.44 hss-core-1
```

Dann wird sie automatisch genutzt.

### Strukturierte Variante: Mapping-Datei

```yaml
nodes:
  - ip: 10.10.1.11
    alias: MME_FRA_A
    role: mme
  - cidr: 10.30.0.0/16
    alias: ENB_CLUSTER
    role: enb
```

```bash
pcap2llm analyze trace.pcapng \
  --profile lte-core \
  --mapping-file ./mapping.yaml
```

### CIDR-Fallback mit `.local/Subnets`

Fuer groessere Infrastruktur-, Partner- oder Roaming-Netze kannst du eine
lokale CIDR-Fallback-Datei hinterlegen:

```text
.local/Subnets
```

Format: pro Zeile ein CIDR und ein Alias, getrennt durch Leerzeichen oder Tab.

```text
10.10.0.0/16 EPC_CORE
198.51.100.0/24 ROAMING_PARTNER_A
```

Optional kannst du den Pfad explizit uebergeben:

```bash
pcap2llm analyze trace.pcapng --profile lte-core \
  --subnets-file ./Subnets
```

Exakte Treffer aus Hosts- oder Mapping-Dateien haben Vorrang. Die Subnet-Datei
wird nur als Fallback genutzt. Wenn danach immer noch nichts aufgeloest ist,
kann `pcap2llm` Rollen zusaetzlich ueber typische Ports ableiten.

### SS7-Point-Codes mit `.local/ss7pcs`

Fuer SS7- und MTP3-Traces kannst du zusaetzlich eine lokale Point-Code-Datei
hinterlegen:

```text
.local/ss7pcs
```

Format: pro Zeile ein Point Code und ein Alias, getrennt durch Leerzeichen
oder Tab.

```text
0-5093 VZB
INAT0-6316 Verizon_WestOrange_INAT0
```

Optional kannst du auch hier den Pfad explizit setzen:

```bash
pcap2llm analyze trace.pcapng --profile 2g3g-sccp-mtp \
  --ss7pcs-file ./ss7pcs
```

Die Datei wird als Fallback fuer `mtp3.opc` und `mtp3.dpc` genutzt. Exakte
IP-, Hostname- und Subnet-Zuordnungen behalten weiterhin Vorrang.

## Automatisierung, LLM-Mode und direkte Provider-Handoffs

Fuer den Alltag brauchst du das nicht sofort im README oder Quickstart, aber es
ist Teil der Plattform:

- `--llm-mode` fuer strikt maschinenlesbare CLI-Ausgaben
- `discover` + `recommend-profiles` + `session ...` fuer gestufte Orchestrierung
- `ask-chatgpt`, `ask-claude`, `ask-gemini` fuer direkten Provider-Handoff aus der CLI

Diese Themen sind absichtlich ausgelagert:

- [`REFERENCE.md`](REFERENCE.md) fuer die exakten Befehle
- [`DISCOVERY.md`](DISCOVERY.md) fuer den Scout-Workflow
- [`SESSIONS.md`](SESSIONS.md) fuer Multi-Run-Orchestrierung
- [`LLM_TROUBLESHOOTING_WORKFLOW.md`](LLM_TROUBLESHOOTING_WORKFLOW.md) fuer den dokumentierten LLM-Ablauf

## Typische Startmuster

### Unbekannte Datei

```bash
pcap2llm discover trace.pcapng
pcap2llm recommend-profiles artifacts/discover_trace_start_1_V_01.json
pcap2llm analyze trace.pcapng --profile <empfohlenes-profil> --out ./artifacts
```

### Bekannte LTE-/EPC-Frage

```bash
pcap2llm inspect trace.pcapng --profile lte-s6a
pcap2llm analyze trace.pcapng \
  --profile lte-s6a \
  -Y "diameter" \
  --privacy-profile share \
  --out ./artifacts
```

### Bekannte 5G-SBI-Frage

```bash
pcap2llm inspect trace-5g.pcapng --profile 5g-sbi
pcap2llm analyze trace-5g.pcapng \
  --profile 5g-sbi \
  -Y "http2" \
  --two-pass \
  --privacy-profile prod-safe \
  --out ./artifacts
```

## Haeufige Stolperstellen

**`tshark was not found in PATH`**

Wireshark/TShark installieren und den Pfad pruefen.

**`detail.json` ist kleiner als erwartet**

Das ist oft nur das Standardlimit von 1.000 Paketen. Erst `summary.json`
pruefen, dann besser filtern statt blind zu vergroessern.

**Leeres `detail.json`**

Meist filtert `-Y` alles weg oder das Profil passt nicht zur Capture.
Ohne Filter und mit breiterem Profil gegenpruefen.

## Weiterfuehrende Doku

| Dokument | Wofuer es gedacht ist |
|---|---|
| [`../README.md`](../README.md) | Einstieg und Navigation |
| [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md) | Vollstaendige Doku-Landkarte |
| [`QUICKSTART_DE.md`](QUICKSTART_DE.md) | Kurzer deutscher Einstieg |
| [`REFERENCE.md`](REFERENCE.md) | Exakte englische Referenz |
| [`DISCOVERY.md`](DISCOVERY.md) | `discover` sauber verstehen |
| [`WORKFLOWS.md`](WORKFLOWS.md) | Protokoll- und Einsatz-spezifische Workflows |
| [`LLM_MODE.md`](LLM_MODE.md) | Maschinenlesbarer Modus |
| [`schema/`](schema/) | Ausgabeschemata |
