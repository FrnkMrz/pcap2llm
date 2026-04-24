# TODO: Web GUI Production Readiness

## TIER 1: MUST HAVE (Nächste 2 Wochen)

### Security
- [ ] CSRF Token Implementation (app.py + templates)
  - [ ] Session Store (Redis or In-Memory)
  - [ ] Token Generator
  - [ ] Token Validation Middleware
  - [ ] Add to all POST forms

- [ ] API-Key Authentication
  - [ ] Config: PCAP2LLM_WEB_API_KEY env var
  - [ ] Middleware: Check Authorization header
  - [ ] Tests: test_api_key_validation.py

- [ ] Rate Limiting
  - [ ] Install: pip install slowapi
  - [ ] Configure: 10/min profile changes, 20/min analyze
  - [ ] Tests: test_rate_limiting.py

### Testing
- [ ] Increase test coverage to >80%
  - [ ] test_csrf_protection.py
  - [ ] test_api_key_validation.py
  - [ ] test_rate_limiting.py

### Monitoring
- [ ] Audit Logging (all Profile changes)
- [ ] Error Logging (structured logs)
- [ ] Health Check Endpoint (/health)

---

## TIER 2: SHOULD HAVE (Wochen 3-4)

- [ ] Per-User Quotas (if Auth implemented)
- [ ] Request Tracing (Request ID in all logs)
- [ ] Concurrent Access Tests
- [ ] Load Testing (100 concurrent users)

---

## TIER 3: NICE TO HAVE (Optional)

- [ ] Dashboard with stats
- [ ] Bulk Operations
- [ ] Export Profiles (CSV/JSON)
- [ ] Dark Mode UI
- [ ] Mobile Responsive

---

## Current Blockers / Known Issues

### None known at this time

Last verified: 2026-04-24 (Commit: 3941085)

---

## Quick Reference: What's Done vs. TODO

| Component | Status | Notes |
|-----------|--------|-------|
| Upload | ✅ Done | Validates .pcap/.pcapng, size limit |
| Discovery | ✅ Done | With fallback to recommendations |
| Analyze | ✅ Done | 19 options, form persistence |
| Download | ✅ Done | Single/Scoped/ZIP formats |
| Profiles CRUD | ✅ Done | Full lifecycle |
| Cleanup | ✅ Done | Auto + manual, configurable |
| Input Validation | ✅ Done | Lengths, patterns, enums |
| Security Headers | ✅ Done | X-Frame, X-XSS, Referrer-Policy |
| **CSRF Protection** | ❌ TODO | Phase 1 Critical |
| **Authentication** | ❌ TODO | Phase 1 Critical |
| **Rate Limiting** | ❌ TODO | Phase 1 Medium |
| **Audit Logging** | ❌ TODO | Phase 2 |
| **Quotas** | ❌ TODO | Phase 2 |
| **Database** | ❌ TODO | Phase 2+ (Optional) |
