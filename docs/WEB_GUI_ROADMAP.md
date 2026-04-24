# Web GUI: Project Status & Roadmap

## ✅ MVP FERTIG (Phase 0)

### Infrastruktur
- ✅ FastAPI Framework + Jinja2 Templates
- ✅ JobStore (Filesystem-basiert)
- ✅ ProfileStore (JSON-basiert)
- ✅ Configuration Management (Environment Variables)
- ✅ Path Traversal Prevention
- ✅ File Upload Validation

### Features - Jobs
- ✅ Upload .pcap/.pcapng Dateien
- ✅ Discovery Workflow (mit Fallback zu Recommend)
- ✅ Analyze mit 19 Optionen
- ✅ Download (Single/Scoped/ZIP)
- ✅ Job Delete
- ✅ Form Persistence (Last-Used-Values)
- ✅ Error Classification (Machine-Readable Codes)

### Features - Profiles
- ✅ Profile CRUD (Create/Read/Update/Delete)
- ✅ Profile Search/Filter
- ✅ 19 Security Settings
- ✅ API Endpoint (/api/profiles)

### Features - Operations
- ✅ Automatic Job Cleanup (configurable)
- ✅ Manual Job Cleanup
- ✅ Admin Cleanup API

### Security
- ✅ Input Validation (Profile Names, Lengths)
- ✅ Enum Validation (Access Levels, etc.)
- ✅ Security Headers (X-Frame-Options, X-XSS-Protection, etc.)
- ✅ Session Timeout Limits (1-1440 min)
- ✅ Type Hints (Python 3.10+)

### Testing
- ✅ 13 Job Tests (upload, delete, form, error, zip, cleanup)
- ✅ 6 Profile Store Tests (CRUD, list, name validation)
- ✅ 12 Profile Route Tests (web integration)
- ✅ 4 Security Validation Tests

### Documentation
- ✅ docs/WEB_GUI.md (Features, Env Vars, Security)
- ✅ docs/SECURITY_AUDIT_WEB_GUI.md (10 Aspekte analysiert)

---

## 🔴 KRITISCH - Phase 1 (Production Readiness)

### CSRF-Protection
**Priority:** KRITISCH  
**Status:** ❌ NICHT IMPLEMENTIERT  
**Aufwand:** ~2 Stunden

```python
# Implementierung:
1. Session/State Store hinzufügen (Server-Side)
2. CSRF-Token in jeder Form generieren
3. Token vor POST validieren
4. Token bei GET neu generieren
```

**Files zu ändern:**
- src/pcap2llm/web/app.py (Middleware + Routes)
- src/pcap2llm/web/config.py (Session Storage)
- src/pcap2llm/web/templates/*

**Test Files:**
- tests/web/test_csrf_protection.py

---

### Authentication & Authorization
**Priority:** KRITISCH  
**Status:** ❌ NICHT IMPLEMENTIERT  
**Aufwand:** ~4 Stunden

**Option A (Lokal-only):** API-Key
```python
# .env oder Header
Authorization: Bearer <api-key>

# pro Job/Profile checken ob User berechtigt
```

**Option B (Enterprise):** Session-Based
```python
# Login-Seite
# Cookies + RBAC (Admin/Editor/Viewer)
```

**Empfehlung für MVP:** Option A (API-Key lokal via env var)

**Files zu ändern:**
- src/pcap2llm/web/security.py (add validate_api_key)
- src/pcap2llm/web/config.py (add PCAP2LLM_WEB_API_KEY)
- src/pcap2llm/web/app.py (add middleware)
- requests.auth.py (Helper)

---

### Rate Limiting
**Priority:** MITTEL  
**Status:** ❌ NICHT IMPLEMENTIERT  
**Aufwand:** ~1.5 Stunden

```python
# Installation
pip install slowapi

# Limits
10 neue Profile/Minute
20 Analyze/Minute
50 Delete/Minute
```

**Files zu ändern:**
- src/pcap2llm/web/app.py (add slowapi middleware)
- pyproject.toml (add slowapi dependency)

---

## 🟠 MITTEL - Phase 2 (Robustheit)

### Audit Logging
**Priority:** MITTEL  
**Status:** ❌ NICHT IMPLEMENTIERT  
**Aufwand:** ~3 Stunden

```python
# Events to log:
- Profile created/updated/deleted (who, what, when)
- Job created/analyzed/deleted
- Download accessed
- API access (rate limit hits)
- Errors (4xx, 5xx)
```

**Files:**
- src/pcap2llm/web/audit.py (new)
- workdir/audit/*.log (append-only)

---

### Per-User Quotas
**Priority:** MITTEL  
**Status:** ❌ NICHT IMPLEMENTIERT  
**Aufwand:** ~2 Stunden

```python
# Limits per User (falls Auth implementiert):
- Max 100 GB total disk
- Max 10 Jobs gleichzeitig
- Max 1000 Profiles
- Max 50 Downloads/Tag
```

---

### Database Migration (Optional)
**Priority:** NIEDRIG  
**Status:** ❌ NICHT IMPLEMENTIERT  
**Aufwand:** ~8 Stunden

**Aktuell:** Filesystem (Job/Profile als JSON)  
**Option:** SQLite / PostgreSQL

```python
# Benefit:
- Schnellere Queries (zB. all profiles mit status=active)
- Bessere Concurrency
- Backups einfacher
- Export/Import einfacher
```

---

## 🟢 NICE-TO-HAVE - Phase 3 (Polish)

### UI Improvements
- Dashboard mit Job-Statistiken
- Dark Mode
- Responsive Mobile UI
- Bulk Operations (multi-select delete)
- Profile Duplication
- Import/Export Profiles (CSV/JSON)

### Batch Operations
- Batch Job Upload
- Batch Analyze (Queue)
- Job Templates

### Monitoring
- Health Check Endpoint (/health)
- Metrics (/metrics)
- Grafana Dashboard

---

## 📋 RECOMMENDED ACTION PLAN

### Week 1: Security Foundation
- [ ] CSRF-Token Implementation
- [ ] API-Key Authentication
- [ ] Rate Limiting (slowapi)
- [ ] Security Tests

**Commit:** `feat(web): add csrf-protection, api-key auth, rate-limiting`

---

### Week 2: Observability
- [ ] Audit Logging
- [ ] Error Tracking
- [ ] Request Logging
- [ ] Performance Metrics

**Commit:** `feat(web): add audit-logging and observability`

---

### Week 3: Robustness
- [ ] Per-User Quotas
- [ ] Concurrent Access Testing
- [ ] Load Testing
- [ ] Failure Recovery

**Commit:** `feat(web): add quotas and resilience`

---

### (Optional) Week 4: Database
- [ ] SQLite Implementation
- [ ] Migration Tools
- [ ] Query Optimization

**Commit:** `refactor(web): add database layer (sqlite)`

---

## 🎯 MINIMAL PRODUCTION CHECKLIST

```
Code Quality:
  [ ] All functions have docstrings
  [ ] Type hints 100%
  [ ] Error handling comprehensive
  [ ] No secrets in code

Security:
  [X] Path traversal prevention
  [X] Input validation
  [X] Security headers
  [ ] CSRF protection
  [ ] Authentication
  [ ] Rate limiting

Testing:
  [ ] Unit tests > 80% coverage
  [ ] Integration tests for all flows
  [ ] Security tests
  [ ] Load tests (100 concurrent)

Monitoring:
  [ ] Error logging
  [ ] Audit trail
  [ ] Health checks
  [ ] Metrics collection

Documentation:
  [X] API Documentation
  [X] Security Guide
  [ ] Deployment Guide
  [ ] Troubleshooting Guide

Deployment:
  [ ] Docker Image
  [ ] Docker Compose (optional backend)
  [ ] Health check endpoint
  [ ] Graceful shutdown
```

---

## 📊 COMPLETION STATS

**MVP (Phase 0):** 100% ✅  
**Phase 1 (Critical):** 0%  
**Phase 2 (Medium):** 0%  
**Phase 3 (Polish):** 0%  

**Overall:** ~20% Production-Ready

---

## 🔗 RELATED DOCUMENTS

- [docs/WEB_GUI.md](WEB_GUI.md) — Feature Overview
- [docs/SECURITY_AUDIT_WEB_GUI.md](SECURITY_AUDIT_WEB_GUI.md) — Security Analysis
- [CLAUDE.md](../CLAUDE.md) — Main Project Overview
