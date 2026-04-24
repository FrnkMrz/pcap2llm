# WEB GUI (lokales Mockup)

Dieses erste Mockup ergaenzt pcap2llm um eine lokal gehostete Web-Oberflaeche.

## Start

```bash
pcap2llm-web
```

Alternativ:

```bash
python -m pcap2llm.web.app
```

Default-URL:

```text
http://127.0.0.1:8765
```

## Ablauf

1. Capture hochladen (.pcap/.pcapng)
2. Optional Discovery starten
3. Empfohlenes Profil pruefen oder manuell waehlen
4. Analyze starten
5. Artefakte herunterladen

## Bereits in der Analyze-UI verfuegbar

- `profile`
- `privacy-profile`
- `display-filter`
- `max-packets`
- `all-packets`
- `fail-on-truncation`
- `max-capture-size-mb`
- `oversize-factor`
- `render-flow-svg`
- `flow-title`
- `flow-max-events`
- `flow-svg-width`
- `collapse-repeats`
- `hosts-file`
- `mapping-file`
- `subnets-file`
- `ss7pcs-file`
- Optional auch als Datei-Upload pro Job (werden unter `input/support/` gespeichert)
- `tshark-path`
- `two-pass`

## Umgebungsvariablen

- `PCAP2LLM_WEB_HOST` (default `127.0.0.1`)
- `PCAP2LLM_WEB_PORT` (default `8765`)
- `PCAP2LLM_WEB_WORKDIR` (default `./web_runs`)
- `PCAP2LLM_WEB_MAX_UPLOAD_MB` (default `250`)
- `PCAP2LLM_WEB_COMMAND_TIMEOUT_SECONDS` (default `600`)
- `PCAP2LLM_WEB_TSHARK_PATH` (optional)
- `PCAP2LLM_WEB_DEFAULT_PRIVACY_PROFILE` (default `share`)

## Job-Layout

```text
<workdir>/<job_id>/
  job.json
  input/
  discovery/
  artifacts/
  logs/
```

## Sicherheit

- Lokaler Bind per Default (`127.0.0.1`)
- Nur `.pcap` und `.pcapng`
- Upload-Groessenlimit konfigurierbar
- Dateiname wird sanitisiert
- Downloads nur aus dem jeweiligen Job-Verzeichnis
- Keine externen API-Calls aus der Web-GUI

## Logs

Bei Discovery/Analyze werden folgende Dateien geschrieben:

- `logs/stdout.log`
- `logs/stderr.log`
- `logs/command.json`

## Downloads

- Konsolidierte Einzeldateien in der Job-Seite mit Kategorie (`artifacts`, `discovery`, `logs`) und Dateigroesse
- Scoped Download-Route: `/jobs/<job_id>/files/<section>/<filename>`
- ZIP-Buendel ueber `/jobs/<job_id>/files.zip` (enthaelt `artifacts/`, `discovery/`, `logs/`)

## UX-Details

- Die Analyze-Form merkt sich pro Job die zuletzt verwendeten Werte.
- Bei Fehlern wird neben der Meldung auch ein maschinenlesbarer Fehlercode angezeigt.
- Manuelles Aufraeumen: `Delete job` entfernt den kompletten Job-Ordner.

## Aktuelle Grenzen des Mockups

- Keine Benutzerverwaltung
- Keine Datenbank
- Keine automatische Bereinigung alter Jobs
- Keine externe LLM-Integration
