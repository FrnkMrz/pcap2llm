# Security Audit: Web GUI Changes (2026-04-24)

## Executive Summary

Der Web GUI sind grundlegende Sicherheitsmaßnahmen implementiert (Path Traversal Prevention, Upload Validation), aber es gibt kritische Lücken:

- ⚠️ **CSRF-Protection:** FEHLT
- ⚠️ **Authentication/Authorization:** FEHLT (jeder hat Zugriff auf alle Jobs/Profile)
- ⚠️ **Input Length Limits:** FEHLT (sehr lange Strings möglich)
- ⚠️ **Rate Limiting:** FEHLT
- ✅ Path Traversal Prevention: OK
- ✅ File Upload Validation: OK
- ✅ Filename Sanitization: OK

## Details & Empfehlungen

### 1. CSRF-Protection (KRITISCH)

**Problem:**
- POST-Routes haben keine CSRF-Token Validierung
- Ein Attacker könnte POST-Requests von einer anderen Domain triggern

**Beispiel-Angriff:**
```html
<!-- auf attacker.com -->
<form action="http://127.0.0.1:8765/profiles" method="POST">
  <input name="name" value="Hacked Profile">
  <input name="description" value="Malicious">
</form>
<script>document.forms[0].submit()</script>
```

**Lösung:**
- CSRF-Token in alle Forms einbauen
- Token in Session speichern
- Token bei POST validieren

**Status:** 🔴 NICHT IMPLEMENTIERT

---

### 2. Authentication & Authorization (KRITISCH)

**Problem:**
- Keine Benutzer-Authentifizierung
- Jeder kann jeden Job/Profil sehen/ändern/löschen
- Kein Unterschied zwischen Admin und Normal User

**Lösung - Phase 1 (Lokal-only):**
- Optional einfaches API-Key System
- Oder: Bearer Token in Authorization Header

**Lösung - Phase 2 (Multi-User):**
- Session-basierte Auth (Cookies)
- Role-Based Access Control (RBAC)

**Status:** 🔴 NICHT IMPLEMENTIERT

---

### 3. Input Length Limits (MITTEL)

**Problem:**
```python
# Diese Felder haben KEINE Längenbegrenzung
name: str = Form(...)
description: str = Form(...)
comment: str = Form(...)
```

Jemand könnte:
- 1 GB Text als Profilname schicken
- Server Speicher erschöpfen
- DoS-Attacke starten

**Lösung:**
```python
from pydantic import constr

# Max 255 chars
name: str = Form(..., max_length=255)
description: str = Form(..., max_length=1000)
comment: str = Form(..., max_length=500)
```

**Status:** 🔴 NICHT IMPLEMENTIERT

---

### 4. Rate Limiting (MITTEL)

**Problem:**
- Keine Limits auf POST-Requests
- jemand könnte:
  - 10000 neue Profile erstellen (Disk voll)
  - 10000 Delete-Requests schicken (Puffering)
  - Brute-Force Job-IDs (UUID sind aber sicher)

**Lösung:**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/profiles")
@limiter.limit("10/minute")  # Max 10 neue Profile pro Minute
async def create_profile(...):
    ...
```

**Status:** 🔴 NICHT IMPLEMENTIERT

---

### 5. Job ID Enumeration (LOW)

**Problem:**
- Job-IDs sind UUIDs (schwer zu raten)
- Aber: Wer weiß die UUID, kann den Job ansehen
- Keine offizielle Jobliste (außer auf Homepage)

**Bewertung:** LOW (UUID ist 2^122 Kombinationen, praktisch unmöglich)

**Status:** ✅ AKZEPTABEL

---

### 6. Output Escaping (XSS) (LOW)

**Problem:**
```jinja2
<!-- In job.html -->
{{ job.last_error }}
{{ artifact_name }}
```

Wenn `last_error` oder `artifact_name` HTML/JSenthalten, könnte XSS passieren.

**Status:** ✅ SICHER (Jinja2 auto-escapes per default)

Aber: Profile Name/Comment könnten unsicher ausgegeben werden:
```jinja2
{{ profile.name }}  <!-- auto-escaped ✅ -->
{{ profile.comment }}  <!-- auto-escaped ✅ -->
```

---

### 7. Command Execution (MITTEL)

**Problem:**
```python
# In pcap_runner.py
def build_analyze_command(self, ...):
    cmd = [
        "pcap2llm", "analyze",
        "--profile", profile,  # ← User Input!
        "--privacy-profile", privacy_profile,  # ← User Input!
    ]
    subprocess.run(cmd)  # ← Shell Injection möglich?
```

**Risiko:** MITTEL
- Nutzer kann `profile="foo; rm -rf /"` eingeben
- ABER: subprocess.run mit list (nicht string) ist SICHER
- list() bypassed Python shell expansion

**Status:** ✅ SICHER (subprocess mit list, nicht shell=True)

---

### 8. File Upload Security (MITTEL)

**Problem:**
```python
# Upload Größenlimit
if total_size > settings.max_upload_bytes:
    raise HTTPException(413, "...")
```

**Workarounds:**
- Nutzer lädt 249 MB upload, ... ✅ Limitiert
- Aber: Alle User teilen sich das Limit
  - User1 lädt 200 MB → bleibt 50 MB für alle anderen

**Lösung (Phase 2):**
- Per-User Quota einführen
- Temporary cleanup für fehlgeschlagene Uploads

**Status:** ⚠️ AKZEPTABEL FÜR LOKAL-ONLY

---

### 9. Directory Traversal (PATH TRAVERSAL)

**Status:** ✅ SICHER

Beispiele geschulter Schutz:
```python
# ✅ ensure_within() verhindert "../" Attacken
ensure_within(self.job_root(job_id), candidate)

# ✅ sanitize_filename() bereinigt Filenames
safe_name = sanitize_filename(capture.filename)

# ✅ reject_nested_filename() blockt "/" in Namen
reject_nested_filename(filename)
```

---

### 10. Profile Injection (MITTEL)

**Problem:**
```python
# In profiles.py
profile.name = name.strip()
profile_store.save(profile)
```

Wenn `name="\x00"`oder andere special chars:
- könnte JSON Parsing brechen
- könnte Dateisystem Probleme verursachen

**Lösung:**
```python
# Validieren
if not re.match(r'^[A-Za-z0-9_\-\s\.]{1,255}$', name):
    raise ValueError("Invalid profile name")
```

**Status:** ⚠️ TEILWEISE IMPLEMENTIERT (Basic strip() nur)

---

## Zusammenfassung der Fixes

| Priorität | Issue | Status |
|-----------|-------|--------|
| 🔴 Kritisch | CSRF-Protection | ❌ TODO |
| 🔴 Kritisch | Authentication/Authorization | ❌ TODO |
| 🟠 Mittel | Input Length Limits | ❌ TODO |
| 🟠 Mittel | Rate Limiting | ❌ TODO |
| 🟠 Mittel | Profile Name Validation | ⚠️ TODO |
| 🟢 Niedrig | XSS/Output Escaping | ✅ OK |
| 🟢 Niedrig | Command Injection | ✅ OK |
| 🟢 Niedrig | Directory Traversal | ✅ OK |

## Auswirkungen im Kontext "Lokal-Only"

**Hinweis:** Die App bound zu `127.0.0.1:8765` per default (nicht `0.0.0.0`).

- ✅ Nur localhost kann zugreifen
- ✅ Kein Remote-Zugriff ohne explizite Konfiguration
- ⚠️ ABER: `PCAP2LLM_WEB_HOST=0.0.0.0` macht die App global erreichbar
- ⚠️ DANN wären die oben genannten Lücken kritisch

## Recommended Action Plan

### Phase 1 (MVP) - Sofort
- [ ] CSRF-Token hinzufügen
- [ ] Input Length Limits für Profile
- [ ] Profile Name Validation (Regex)
- [ ] Security Headers (X-Frame-Options, etc.)

### Phase 2 (Production) - Vor Deployment
- [ ] Simple API-Key Auth implementieren
- [ ] Rate Limiting (slowapi)
- [ ] Audit Logging
- [ ] HTTPS enforcement
- [ ] Per-User Quotas

### Phase 3 (Enterprise) - Optional
- [ ] LDAP/OAuth2 Integration
- [ ] RBAC (Admin/Editor/Viewer)
- [ ] Session Management
- [ ] User Provisioning/Deprovisioning
