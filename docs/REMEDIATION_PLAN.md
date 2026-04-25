# Remediation Plan

Plan zur Behebung aller Findings aus dem Repo-Code-Review vom 2026-04-25.
Reihenfolge ist nach Risiko priorisiert; innerhalb jeder Stufe nach Aufwand.

Legende:
- **Severity**: critical / high / medium / low
- **Effort**: S (≤1 h), M (½ Tag), L (1+ Tag)
- **Tests**: konkrete Test-Datei, in die die Regression-Abdeckung gehört

---

## Stufe 1 — Critical (sofort)

Diese drei Findings betreffen direkt das zentrale Versprechen des Tools (Privacy-Garantie, sichere Web-GUI). Sollten als zusammenhängende Serie gemerged werden.

### 1.1 Privacy-Leak: Summary/Conversations/Anomalies werden nicht protected
- **Severity**: critical · **Effort**: M
- **Files**: `src/pcap2llm/protector.py`, `src/pcap2llm/pipeline.py`, `src/pcap2llm/chatgpt.py`, `src/pcap2llm/claude.py`, `src/pcap2llm/gemini.py`
- **Problem**: `Protector.protect_packets` walkt nur die `messages`-Liste. `summary_payload` in `chatgpt.py:37-50` enthält `conversations`, `anomalies`, `deterministic_findings`, `relevant_protocols` direkt aus `artifacts.summary`. Conversations tragen rohe `src_ip`/`dst_ip` aus `normalizer.py:329`.
- **Fix**:
  1. Neue Methode `Protector.protect_artifact_payload(payload: dict) -> dict` einführen, die `_walk` über beliebige Dicts/Listen anwendet (ohne packet-Kontext, nur Generic-Rules).
  2. In `pipeline.py` nach `summary_payload = build_summary(...)` und nach Bau der `conversations`/`anomalies`-Substrukturen die sensiblen Top-Level-Schlüssel durch den Protector schleifen: mindestens `conversations`, `anomalies`, `deterministic_findings`, `probable_notable_findings`, `relevant_protocols` (falls Hostnames enthalten), `app_layer_anomalies`.
  3. Alternative (defensiver): in `build_chatgpt_prompt`/`build_claude_prompt`/`build_gemini_prompt` einen finalen Protector-Pass über das `summary_payload` ausführen, bevor es serialisiert wird. So greift der Schutz auch, wenn jemand `Protector` direkt aufruft.
  4. `protect_artifact_payload` muss ohne `packet`-Kontext arbeiten — `_PROTOCOL_RULES` greifen dann nicht, aber `_GENERIC_RULES` (IP/hostname/imsi/msisdn) tun es. Das ist für Conversation-Tabellen ausreichend.
- **Acceptance**: Neuer Test in `tests/test_protector.py`: Pipeline mit `share`-Profil → `summary.conversations` enthält keine rohen IPs/Hostnames mehr, `pseudonym_audit()` zählt sie korrekt.
- **Risiko**: Pseudonyme in conversations und messages müssen identisch sein → gleicher `Protector`-Instanz wiederverwenden, nicht neu instanziieren.

### 1.2 Web: `delete_job` und `delete_profile` ohne Pfad-Validierung
- **Severity**: critical · **Effort**: S
- **Files**: `src/pcap2llm/web/app.py:501-507`, `src/pcap2llm/web/profiles.py:50-56`, `src/pcap2llm/web/security.py`
- **Problem**: `shutil.rmtree(store.job_root(job_id))` und `path.unlink()` werden ohne `reject_nested_filename`/UUID-Check ausgeführt. Pfad-Traversal ermöglicht beliebiges Verzeichnis-/Datei-Löschen.
- **Fix**:
  1. Helper `validate_id(value: str) -> None` in `security.py` ergänzen, der UUIDv4-Format erzwingt (`uuid.UUID(value, version=4)` und String-Roundtrip-Vergleich). UUIDs werden bei Job- und Profile-Erstellung bereits via `uuid4()` generiert — also harter Constraint.
  2. `delete_job` (app.py:501), `delete_job_outputs` (app.py:492), `view_text_file`, `download_file`, alle weiteren `/jobs/{job_id}/...`-Routen rufen `validate_id(job_id)` als erste Anweisung.
  3. `delete_profile` (app.py:690) und `ProfileStore.delete`/`load`/`save` rufen `validate_id(profile_id)`.
  4. Zusätzlich `ensure_within(self.profiles_dir, path)` in `_profile_path` als Defense-in-Depth.
- **Acceptance**: `tests/web/test_security_validation.py`: `client.post("/jobs/..%2F..%2Ffoo/delete")` → 400, kein Filesystem-Effekt. Analog für `/profiles/{id}/delete`.

### 1.3 Web: CLI-Argv-Injection via Form-Felder
- **Severity**: critical · **Effort**: M
- **Files**: `src/pcap2llm/web/pcap_runner.py`, `src/pcap2llm/web/app.py:845-868`
- **Problem**: `display_filter`, `hosts_file`, `mapping_file`, `tshark_path`, `flow_title`, `subnets_file`, `ss7pcs_file`, `network_element_mapping_file` fließen direkt als Argv-Werte in `pcap2llm analyze`. Werte mit `-`-Präfix werden von Typer als Flags interpretiert.
- **Fix**:
  1. In `pcap_runner.py` zentralen Helper `_safe_argv_value(value: str, *, allow_dash: bool = False) -> str` einführen: bei `value.startswith("-")` `WebValidationError` werfen.
  2. Alle Form-Felder, die in argv landen, vor dem `cmd.append(...)` durch diesen Helper schicken.
  3. Pfad-Felder (`hosts_file`, `mapping_file`, `subnets_file`, `ss7pcs_file`, `network_element_mapping_file`) zusätzlich gegen `workdir`-Subtree validieren via `ensure_within(allowed_root, Path(value).resolve())`. Erlaubte Roots: das Job-Upload-Verzeichnis sowie ein optional konfigurierter `support_files_root` aus `web/config.py`.
  4. `display_filter` strikt gegen Whitelist-Charset prüfen (Wireshark-Filter-Syntax: `[A-Za-z0-9._=!&|()<>"' \-+:/]+`) — keine Steuerzeichen, keine Newlines.
  5. `tshark_path` aus User-Input ganz entfernen (Web-GUI muss systemweites tshark verwenden) oder per Allowlist/Settings-File pflegen.
- **Acceptance**: `tests/web/test_security_validation.py`: Submit mit `display_filter="--help"` → 400. Submit mit `hosts_file="/etc/passwd"` → 400.

---

## Stufe 2 — High (vor nächstem Release)

### 2.1 Falsche Timing-Statistik (Sortierung vor Diff-Bildung)
- **Severity**: high · **Effort**: S
- **Files**: `src/pcap2llm/summarizer.py:14-35`, `summarizer.py:48-84`
- **Problem**: `_timing_stats` sortiert `time_rel_ms`, bevor Inter-Packet-Diffs gebildet werden. Burst-Detection im selben Modul ebenfalls. `time_rel_ms` ist bereits monoton aus TShark — aber bei Reordering oder mehrkanaligen Captures ist die Annahme falsch und die Statistik wird zur reinen Verteilungs-Statistik der sortierten Werte.
- **Fix**:
  1. Sortierung entfernen, `times` direkt aus der `detail_packets`-Reihenfolge übernehmen.
  2. Falls Captures generell out-of-order ankommen können, optional `times.sort()` *nach* der Diff-Berechnung lassen — aber Diffs müssen aus der Originalreihenfolge stammen.
  3. p95-Index gleich mit korrigieren: `int((n - 1) * 0.95)` statt `min(int(n*0.95), n-1)` (verhindert p95==max bei kleinen n).
- **Acceptance**: Neuer Test in `tests/test_summarizer.py` mit nicht-monotoner Eingabeliste — bei der Original-Sortierung wäre p95 anders als bei der unsortierten.

### 2.2 SVG-Sanitizer unzureichend
- **Severity**: high · **Effort**: M
- **Files**: `src/pcap2llm/web/app.py:956-967`
- **Problem**: Substring-Check auf `<script` und `javascript:` blockt `onload`, `onerror`, `<foreignObject>`, `<use href="data:...">`, `xlink:href` etc. nicht.
- **Fix**:
  1. SVG nicht inlinen. Stattdessen als statische Datei via `<img src="...flow.svg">` einbetten — Browser rendert SVG ohne JS-Execution-Privilegien des Hosts.
  2. Falls Inline weiter benötigt wird (z. B. für Tooltip-Interaktion): `defusedxml` oder `bleach` als optionale Dependency aufnehmen und SVG-Whitelist-Sanitization durchführen. Whitelist: `svg`, `g`, `rect`, `line`, `path`, `text`, `title`, `desc`, `defs`, `marker`, `polyline`, `polygon`, `circle`, `tspan`, plus `xmlns`, `viewBox`, `width`, `height`, `fill`, `stroke`, `stroke-width`, `class`, `transform`, `x`, `y`, `cx`, `cy`, `r`, `d`, `points`, `text-anchor`, `font-size`, `font-family`, `dy`. Alle `on*`-Attribute, `xlink:href`, `href` mit `javascript:`/`data:`-Schemas verbieten.
  3. Empfehlung: Variante 1 (img-tag) als Default; Variante 2 nur bei aktiviertem Flag.
- **Acceptance**: `tests/web/test_security_validation.py`: SVG mit `<svg onload="alert(1)">` wird gestrippt oder das Job-Detail-Page rendert kein Inline-SVG.

---

## Stufe 3 — Medium

### 3.1 Reflected XSS in `view_text_file`
- **Severity**: medium · **Effort**: S
- **Files**: `src/pcap2llm/web/app.py:407-467` (Lines 459-460)
- **Problem**: `job_id`, `section`, `filename` werden ungeescaped in HTML interpoliert. `reject_nested_filename` blockt nur `/` und `\`.
- **Fix**: Alle drei Werte vor dem Einbau in das HTML-Template durch `html.escape(...)` schicken. Wenn ein Templating-Engine (`Jinja2` via `starlette.templating.Jinja2Templates`) bereits im Projekt aktiv ist, lieber `{{ var }}` mit Auto-Escape verwenden.
- **Acceptance**: Test mit `filename="<script>alert(1)</script>"` (URL-encoded) — Antwort enthält `&lt;script&gt;`.

### 3.2 `bulk_delete_jobs` schluckt Validation-Fehler still
- **Severity**: medium · **Effort**: S
- **Files**: `src/pcap2llm/web/app.py:516-523`
- **Problem**: Bei `WebValidationError` macht der Loop `continue`, ohne dem Aufrufer mitzuteilen, dass IDs übersprungen wurden. Im Kontrast zur destruktiven Single-Route (#1.2) inkonsistent.
- **Fix**: Nach Fix 1.2 prüfen — wenn beide Routen identisch validieren, im Bulk-Pfad fehlerhafte IDs sammeln und in der Redirect-Query (`?failed=2&deleted=5`) zurückgeben oder als 400 ablehnen, falls *alle* IDs ungültig.
- **Acceptance**: Bulk-POST mit gemischt gültigen/ungültigen IDs → die gültigen werden gelöscht, die ungültigen erscheinen im Response-Hint.

### 3.3 SCTP-Slot-Reservierung in `dominant_signaling_protocols`
- **Severity**: medium · **Effort**: S
- **Files**: `src/pcap2llm/signaling.py:196-208`
- **Problem**: `selected = selected[: max(0, limit - 1)]` reserviert immer einen Slot für SCTP, auch wenn am Ende kein SCTP angehängt wird. Resultat ist ggf. um einen Eintrag kürzer als `limit`.
- **Fix**: Slicing nach dem optionalen SCTP-Append vornehmen. Pseudo-Code:
  ```python
  candidates = ...                     # bereits bewertet
  if sctp_factor > 0:
      candidates.append(("sctp", sctp_factor))
  selected = candidates[:limit]
  ```
- **Acceptance**: Test in `tests/test_recommendation.py` (oder neu `test_signaling.py`): Capture ohne SCTP, `limit=10`, mind. 10 starke Kandidaten → genau 10 zurück.

### 3.4 `output_metadata` fängt `OSError` nicht ab
- **Severity**: medium · **Effort**: S
- **Files**: `src/pcap2llm/output_metadata.py:24-41`
- **Fix**: `except (OverflowError, ValueError, OSError)` statt `(OverflowError, ValueError)`. Fallback-Pfad ist bereits implementiert.
- **Acceptance**: Unit-Test mit `first_seen = "-9999999999999"` (out-of-range) → fällt auf `_start_<n>`-Form zurück, keine Exception.

### 3.5 Asymmetrie `serialize_summary_artifact` vs `serialize_detail_artifact`
- **Severity**: medium · **Effort**: S
- **Files**: `src/pcap2llm/serializers.py:94, ~129`
- **Fix**: In `serialize_detail_artifact` ebenfalls `model_dump(exclude_none=True)` verwenden. Schema-Vertrag (`extra="forbid"`) bleibt unberührt; Felder mit `None`-Default werden konsistent weggelassen.
- **Acceptance**: `tests/test_schema_contract.py` ergänzen — Detail-Artefakt enthält weder `selection: null` noch `capture_sha256: null` für ein Capture, das diese Werte nicht setzt.

---

## Stufe 4 — Low / Cleanup

### 4.1 `session start` Sub-Sekunden-Eindeutigkeit
- **Severity**: low · **Effort**: S
- **Files**: `src/pcap2llm/sessions.py:13-32`
- **Fix**: `_session_id()` um `f"{uuid4().hex[:6]}"` oder `microseconds` erweitern. `mkdir(exist_ok=False)` als Konsistenz-Check beibehalten.
- **Acceptance**: Test, der zweimal in derselben Sekunde `start_session()` aufruft, soll erfolgreich zwei verschiedene Session-Verzeichnisse anlegen.

### 4.2 Recommendation: post-gate `score=0.0` landet im falschen Bucket
- **Severity**: low · **Effort**: S
- **Files**: `src/pcap2llm/recommendation.py:1242-1255`
- **Fix**: Nach `_apply_profile_gates` prüfen, ob `score == 0.0` UND ein gate-suppressed-Marker gesetzt ist; in dem Fall ins `suppressed_profiles`-Bucket umrouten, nicht in `recommended_profiles` mit `score: 0.0`.
- **Acceptance**: `tests/test_recommendation.py`: Profil mit hartem Gate (z. B. ISUP-Suppressor) erscheint in `suppressed_profiles`, nicht in `recommended_profiles`.

### 4.3 Hardening: refuse external-LLM handoff bei `ip: keep`
- **Severity**: low (Konvention bereits dokumentiert) · **Effort**: S
- **Files**: `src/pcap2llm/cli.py` (`ask-chatgpt`, `ask-claude`, `ask-gemini` Command-Bodies)
- **Fix**: Bevor der Prompt gebaut wird, prüfen:
  ```python
  unsafe = {cls for cls in ("ip", "hostname", "imsi", "msisdn", "imei",
                             "subscriber_id", "diameter_identity")
            if modes.get(cls, "keep") == "keep"}
  if unsafe and not opt_in_unsafe:
      raise typer.BadParameter(
          f"Privacy modes {sorted(unsafe)} are 'keep' — refusing external "
          "LLM handoff. Use --privacy-profile llm-telecom-safe or pass "
          "--allow-keep to override."
      )
  ```
- Flag `--allow-keep` als explizites Opt-out für Test/Lab-Szenarien.
- **Acceptance**: `tests/test_chatgpt.py` ergänzen — Aufruf mit `--privacy-profile share` ohne `--allow-keep` → Exit 1.

### 4.4 `/admin/cleanup` und destruktive POSTs ohne CSRF-Schutz
- **Severity**: low (Localhost-Kontext) · **Effort**: M
- **Files**: `src/pcap2llm/web/app.py:527-550`, alle `POST /jobs/.../delete`, `/profiles/.../delete`, `/jobs/bulk-delete`
- **Fix**: Einer der folgenden Wege:
  1. **Origin-Header-Check**: Middleware lehnt POST-Requests ab, deren `Origin`/`Referer` nicht zu einer konfigurierten Allowlist (`http://127.0.0.1:<port>`) passt.
  2. **CSRF-Token**: Cookie `csrf_token` setzen und in jedem Form als Hidden-Field zurückerwarten. Vergleichen via constant-time.
- Empfehlung: Option 1 reicht für die Localhost-Tool-Annahme und ist aufwandsarm.
- **Acceptance**: `tests/web/test_security_validation.py`: POST ohne korrekten Origin → 403.

### 4.5 `pseudonym_mapping.json` und `vault.json` Download-Gating
- **Severity**: low (gemäß Workflow-Doku) · **Effort**: S
- **Files**: `src/pcap2llm/web/app.py:355-389`, `src/pcap2llm/web/jobs.py:179-180`
- **Fix**:
  1. Dateinamen `pseudonym_mapping.json` und `vault.json` in einer Konstante `SENSITIVE_SIDECARS` zusammenfassen.
  2. Download-Route lehnt diese Namen standardmäßig mit 403 ab; Header `X-Allow-Sensitive: yes` (oder Query `?confirm=1`) als bewusster Override.
  3. UI: Diese Sidecars werden in der Job-Detail-Liste mit Warn-Badge "Lokal halten — nicht teilen" angezeigt.
  4. Bind-Check: Bei Server-Start, falls `host` nicht in `{127.0.0.1, ::1, localhost}`, im Log eine `WARN`-Zeile für den Operator emitten.
- **Acceptance**: Test, der `GET /jobs/<id>/files/.../pseudonym_mapping.json` ohne Override → 403.

### 4.6 Doku-Drift `output_metadata` Fallback
- **Severity**: trivial · **Effort**: S
- **Files**: `CLAUDE.md`, ggf. `docs/`-Sektion zu Filenames
- **Fix**: Einen Satz ergänzen: "Falls `first_seen` nicht aus dem Capture ableitbar ist, fällt der Timestamp-Anteil auf `start_<N>` oder `start_unknown` zurück." So ist die `output_metadata.py:44-58`-Logik konform mit der Spec.

---

## Tests / CI-Erweiterungen (übergreifend)

- **Privacy-Regression-Korpus**: Mini-PCAP mit IPs/IMSIs/Hostnames in den Conversations → Pipeline mit verschiedenen Profilen, Snapshot-Test der `summary.json`. Greift sofort, sobald 1.1 implementiert ist.
- **Web-Security-Tests**: Eigene Test-Klasse in `tests/web/test_security_validation.py` für jeden Validierungspfad in 1.2/1.3/2.2/3.1/4.4/4.5.
- **CLI-Argv-Injection-Test** in `tests/web/test_pcap_runner.py`.
- **Linter**: `bandit -ll src/pcap2llm/web/` in CI als zusätzlichen Job.

## Reihenfolge / PR-Schnitt

Empfehlung: vier zusammenhängende PRs.

| PR | Inhalt | Gate |
|----|--------|------|
| `priv-summary-protection` | 1.1 + zugehörige Tests | Vor Stufe 2 |
| `web-input-hardening` | 1.2 + 1.3 + 3.1 + 4.4 + 4.5 + Tests | Vor Stufe 2 |
| `summary-correctness` | 2.1 + 3.4 + 3.5 + 4.1 + 4.2 + Tests | Vor Stufe 3 |
| `web-svg-and-cleanup` | 2.2 + 3.2 + 3.3 + 4.3 + 4.6 | Final |

Stufe 1 ist veröffentlichungsblockierend; Stufe 2 sollte vor dem nächsten Tag-Release landen; Stufen 3 und 4 dürfen rollend folgen.
