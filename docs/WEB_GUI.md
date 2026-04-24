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

## Lokaler Standard-Check

Fuer lokale Aenderungen an der Web-GUI hat sich dieser Ablauf als kleinster sinnvoller Standard bewaehrt:

```bash
python3 -m venv .venv
./.venv/bin/pip install -e '.[dev]'
./.venv/bin/ruff check .
./.venv/bin/python -m pytest tests/web/test_jobs.py tests/web/test_profiles.py tests/web/test_security_validation.py tests/web/test_pcap_runner.py tests/web/test_profiles_routes.py tests/web/test_web_upload.py
./.venv/bin/python -m pytest tests/test_resolver_extended.py
bash scripts/smoke_test_web_gui.sh
```

Der Smoke-Run startet die Web-GUI lokal, prueft die wichtigsten HTML-Routen und testet einen echten Upload bis zur Job-Seite.

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

## Analyze-Optionen kurz erklaert

- `max-packets`: begrenzt, wie viele Pakete in `detail.json` landen.
- `Export all packets to detail.json`: hebt dieses Limit auf. Sinnvoll nur fuer kleine, bereits eng gefilterte Captures.
- `Fail if the detail export would be cut off`: bricht den Lauf ab, wenn wegen `max-packets` nur ein Teil der exportierten Pakete in `detail.json` landen wuerde.
- `Better TShark reassembly for fragmented traffic`: aktiviert TShark Two-Pass-Dissection. Das hilft besonders bei HTTP/2, SIP, Diameter oder anderer fragmentierter/reassemblierter Nutzlast, kostet aber etwas mehr Laufzeit.
- `Render flow diagram`: erzeugt zusaetzlich `flow.json` und `flow.svg`.
- `Merge repeated messages`: fasst direkt aufeinanderfolgende identische Events im Flow zu `xN` zusammen.

## Umgebungsvariablen

- `PCAP2LLM_WEB_HOST` (default `127.0.0.1`)
- `PCAP2LLM_WEB_PORT` (default `8765`)
- `PCAP2LLM_WEB_WORKDIR` (default `./web_runs`)
- `PCAP2LLM_WEB_MAX_UPLOAD_MB` (default `1`)
- `PCAP2LLM_WEB_COMMAND_TIMEOUT_SECONDS` (default `600`)
- `PCAP2LLM_WEB_TSHARK_PATH` (optional)
- `PCAP2LLM_WEB_DEFAULT_PRIVACY_PROFILE` (default `share`)
- `PCAP2LLM_WEB_CLEANUP_ENABLED` (default `true`) — Automatisches Loeschen alter Jobs aktivieren
- `PCAP2LLM_WEB_CLEANUP_MAX_AGE_DAYS` (default `7`) — Jobs aelter als N Tage loeschen

## Lokale `.local`-Defaults

Wenn die Web-GUI lokal gegen einen lokalen Arbeitsbereich laeuft, uebernimmt sie
die gleichen Helper-Datei-Konventionen wie die CLI:

- `.local/hosts`
- `.local/Subnets`
- `.local/ss7pcs`
- optional `.local/mapping.yaml`, `.local/mapping.yml` oder `.local/mapping.json`

Bei einem lokalen Start mit `PCAP2LLM_WEB_WORKDIR=.local/web_runs` werden diese
Pfade automatisch in der Analyze-Maske vorbefuellt und auch ohne manuelle
Eingabe verwendet.

Lokale Privacy Profiles werden in diesem Modus unter `.local/profiles/` gespeichert
und bei jedem Neustart der Web-GUI wieder geladen. Aeltere Profile aus dem
frueheren Pfad `.local/web_runs/profiles/` werden automatisch in den neuen
lokalen Profil-Ordner uebernommen.

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
  - Protection Modes: nur `keep`, `mask`, `pseudonymize`, `encrypt`, `remove`

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

Bei Discovery/Analyze werden getrennte Log-Dateien geschrieben:

- `logs/discovery_stdout.log`
- `logs/discovery_stderr.log`
- `logs/discovery_command.json`
- `logs/recommend_stdout.log`
- `logs/recommend_stderr.log`
- `logs/recommend_command.json`
- `logs/analyze_stdout.log`
- `logs/analyze_stderr.log`
- `logs/analyze_command.json`

Auf der Job-Seite ist die Log-Sektion standardmaessig eingeklappt. Sie bleibt
damit aus dem Weg, bis man sie fuer Fehlersuche oder Nachvollziehbarkeit
bewusst oeffnet.

## Downloads

- Konsolidierte Einzeldateien in der Job-Seite mit Kategorie (`artifacts`, `discovery`, `logs`) und Dateigroesse
- Scoped Download-Route: `/jobs/<job_id>/files/<section>/<filename>`
- Markdown-Artefakte (`*.md`) koennen auf der Job-Seite direkt im Browser angezeigt werden
- ZIP-Buendel ueber `/jobs/<job_id>/files.zip` (enthaelt `artifacts/`, `discovery/`, `logs/`)

## UX-Details

- Die Analyze-Form merkt sich pro Job die zuletzt verwendeten Werte.
- Bei Fehlern wird neben der Meldung auch ein maschinenlesbarer Fehlercode angezeigt.
- Manuelles Aufraeumen: `Delete job` entfernt den kompletten Job-Ordner.
- Dashboard verfuegbar unter `/dashboard` mit Job-/Privacy-Profile-Statistiken und Recent Jobs.
- Jobs koennen auf der Startseite per Multi-Select gesammelt geloescht werden.
- Dark-Mode Toggle in der Kopfzeile (persistiert im Browser via `localStorage`).
- Responsive Tabellenansicht fuer kleinere Displays.
- Das Flow-Preview wird inline als interaktives SVG dargestellt, nicht als statisches Bild.
- Hover im Flow-Preview funktioniert direkt auf der Job-Seite; im SVG selbst bleibt das gleiche Verhalten auch nach dem Download erhalten.
- Das Flow-Preview ist als grosser, scrollbarer Viewer ausgelegt, damit breite Sequenzdiagramme ohne Browser-Zoom lesbar bleiben.
- Privacy-Profile in der Analyze-Maske werden kompakter nach Inhalt statt als unnoetig breite Vollbreiten-Karten dargestellt.

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

## Privacy Profiles

Die Seite `http://127.0.0.1:8765/profiles` verwaltet Privacy Profiles fuer die Web-GUI.

### Funktionen

- **Built-ins ansehen:** Mitgelieferte Privacy Profiles (`internal`, `share`, `lab`, `prod-safe`, `llm-telecom-safe`) oben als Karten
- **Built-in duplizieren:** Button "Duplicate as Local Profile" erzeugt eine editierbare lokale Kopie
- **Lokales Profil erstellen:** Button "New Profile" oben rechts
- **Lokales Profil bearbeiten:** Links auf Profil klicken, rechts die Datenklassen-/Mode-Zuordnung anpassen
- **Profil speichern:** Button "Save Profile"
- **Profil loeschen:** Button "Delete Profile" mit Sicherheitsabfrage
- **Profil duplizieren:** Button "Duplicate Profile" uebernimmt alle Privacy-Modes in ein neues Profil
- **Bulk Delete:** Mehrere Profile markieren und gesammelt loeschen
- **Export:** Profile als JSON oder CSV herunterladen
- **Profile durchsuchen:** Suchfeld links zum Filtern nach Name/Beschreibung

### Profil-Einstellungen

**Allgemein:**
- Name (Pflichtfeld, muss eindeutig sein)
- Beschreibung (Pflichtfeld)

**Privacy-Modes pro Datenklasse:**
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

**Verfuegbare Aktionen:**
- `keep`
- `mask`
- `pseudonymize`
- `encrypt`
- `remove`
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
