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
- `PCAP2LLM_WEB_CLEANUP_ENABLED` (default `true`) — Automatisches Loeschen alter Jobs aktivieren
- `PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS` (default `7`) — Jobs aelter als N Tage loeschen

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
- **Security Headers:** X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- **Input Validation:**
  - Profile Names: nur Alphanumerisch, _, -, Spaces, . (1-255 chars)
  - Descriptions: max 1000 chars
  - Owner: max 255 chars
  - Comments: max 500 chars
  - Session Timeout: 1-1440 Minuten (1 Tag)
  - Enum Validation: Access Level, Network Access, Logging Level

## ⚠️ Sicherheitslücken (bekannt, dokumentiert)

Siehe [`docs/SECURITY_AUDIT_WEB_GUI.md`](SECURITY_AUDIT_WEB_GUI.md) für Details:

- ❌ **CSRF-Protection:** FEHLT (TODO Phase 1)
- ❌ **Authentication/Authorization:** FEHLT (TODO Phase 2)
- ❌ **Rate Limiting:** FEHLT (TODO Phase 2)
- ✅ Path Traversal Prevention
- ✅ File Upload Validation  
- ✅ Input Validation & Length Limits
- ✅ Security Headers

**Note:** Die App ist für **lokal-only** Nutzung konzipiert (127.0.0.1:8765 per Default). Für Remote-Zugriff/Production muss die Sicherheit erweitert werden.

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
- Dashboard verfuegbar unter `/dashboard` mit Job-/Profil-Statistiken und Recent Jobs.
- Jobs koennen auf der Startseite per Multi-Select gesammelt geloescht werden.
- Dark-Mode Toggle in der Kopfzeile (persistiert im Browser via `localStorage`).
- Responsive Tabellenansicht fuer kleinere Displays.

## Automatische Bereinigung (Cleanup)

**Aktiviert per Default.** Beim App-Start werden Jobs geloescht, die aelter als `PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS` sind (Standard: 7 Tage).

### Cleanup deaktivieren

```bash
export PCAP2LLM_WEB_CLEANUP_ENABLED=false
pcap2llm-web
```

### Cleanup-Verhalten konfigurieren

```bash
export PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS=14  # Jobs aelter als 14 Tage loeschen
export PCAP2LLM_WEB_CLEANUP_ENABLED=true
pcap2llm-web
```

### Manuelles Cleanup triggern (API)

```bash
curl -X POST http://127.0.0.1:8765/admin/cleanup
# Antwort: {"status": "ok", "deleted_jobs": 2, "max_age_days": 7}
```

Mit allen Tagen:
```bash
curl -X POST http://127.0.0.1:8765/admin/cleanup -H "Content-Type: application/json" -d '{"max_age_days": 1}'
# Antwort: {"status": "ok", "deleted_jobs": 5, "max_age_days": 1}
```

Wenn `PCAP2LLM_WEB_CLEANUP_ENABLED=false`, laeuft das Startup-Cleanup nicht, aber die Admin-API ist immer noch verfuegbar.

## Security Profiles

Die Seite `http://127.0.0.1:8765/profiles` verwaltet zentrale Sicherheitsprofile.

### Funktionen

- **Profil erstellen:** Button "New Profile" oben rechts
- **Profil bearbeiten:** Links auf Profil klicken, rechts Formular ausfuellen
- **Profil speichern:** Button "Save Profile" unter dem Formular
- **Profil loeschen:** Button "Delete Profile" mit Sicherheitsabfrage
- **Profil duplizieren:** Button "Duplicate Profile" uebernimmt alle Einstellungen in ein neues Profil
- **Bulk Delete:** Mehrere Profile markieren und gesammelt loeschen
- **Export:** Profile als JSON oder CSV herunterladen
- **Profile durchsuchen:** Suchfeld links zum Filtern nach Name/Beschreibung

### Profil-Einstellungen

**Allgemein:**
- Name (Pflichtfeld, muss eindeutig sein)
- Beschreibung (Pflichtfeld)
- Status (Active/Inactive)
- Owner (Optional, z.B. "Security Team")
- Comment (Optional, Freitext)

**Authentication:**
- Password Required (Checkbox)
- Multi-Factor Authentication (Checkbox)
- Certificate Authentication (Checkbox)

**Authorization:**
- Access Level: read-only, standard, oder admin

**Session:**
- Session Timeout (Minuten, Minimum 1)

**Network Access:**
- internal-only (nur Intranetz)
- vpn (nur VPN)
- public (oeffentlich zulaessig)

**Logging:**
- basic (Mindestprotokollierung)
- detailed (Detaillierte Logs)
- security-events (Nur Sicherheitsereignisse)

### API-Endpunkte

**Alle Profile als JSON auflisten:**
```bash
curl http://127.0.0.1:8765/api/profiles
```

**Profile exportieren (JSON):**
```bash
curl -L "http://127.0.0.1:8765/profiles/export?fmt=json" -o security_profiles.json
```

**Profile exportieren (CSV):**
```bash
curl -L "http://127.0.0.1:8765/profiles/export?fmt=csv" -o security_profiles.csv
```

Antwort:
```json
[
  {
    "id": "...",
    "name": "Standard Profile",
    "description": "...",
    "status": "active",
    "owner": "...",
    "auth_password": true,
    "auth_mfa": false,
    "auth_access_level": "standard",
    "session_timeout_minutes": 30,
    "network_access": "internal-only",
    "logging_level": "security-events",
    "created_at": "2026-04-24T...",
    "updated_at": "2026-04-24T..."
  }
]
```

## Aktuelle Grenzen des Mockups

- Keine Benutzerverwaltung
- Keine Datenbank
- Keine externe LLM-Integration

## Weiterfuehrende Doku

- Netzwerk-Element-Erkennung: [`docs/NETWORK_ELEMENT_DETECTION.md`](NETWORK_ELEMENT_DETECTION.md)
- Referenz (EN): [`docs/REFERENCE.md`](REFERENCE.md)
- Sicherheits-Audit Web GUI: [`docs/SECURITY_AUDIT_WEB_GUI.md`](SECURITY_AUDIT_WEB_GUI.md)
