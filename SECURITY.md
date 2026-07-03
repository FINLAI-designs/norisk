# Security Policy — NoRisk by FINLAI

> **Status 2026-05-28:** DRAFT — diese Datei enthaelt CRA-konforme Public-
> Disclosure-Sektionen mit Platzhaltern `⟨TBD⟩`, die Patrick vor jeder
> Veroeffentlichung (Repo-Public, Marketing-Page, Release-Notes) ausfuellen
> muss. Bis dahin gilt: Repository darf nicht oeffentlich gemacht werden,
> Marketing-Pages duerfen die CRA-Konformitaet noch nicht zusagen.
>
> Hintergrund: Cyber Resilience Act tritt 11.09.2026 in Kraft, Strafen
> bis 15 Mio Euro. Anforderungs-Spec:
> (intern verwaltet)
>. WP-Bezug: (SECURITY.md / Lifecycle-Statement).

## 1. Coordinated Vulnerability Disclosure

Wir freuen uns ueber Sicherheits-Hinweise und behandeln sie nach dem
Coordinated-Disclosure-Prinzip.

**So meldest du eine Schwachstelle:**

- Bevorzugter Kanal: **GitHub Security Advisories** im NoRisk-Repository
  (Tab „Security" → „Report a vulnerability"). Diese Meldung ist nicht
  oeffentlich sichtbar und wird verschluesselt an die Maintainer geleitet.
- Alternativ per E-Mail an: `⟨TBD: security@financial-analytics.eu oder
  vergleichbare Mailbox⟩`
- PGP-Key: `⟨TBD: Fingerprint und URL zum Public-Key-File⟩`

**Was wir versprechen:**

| Zusage | Frist |
|---|---|
| Erst-Antwort (Bestaetigung des Eingangs) | innerhalb von **3 Werktagen** |
| Erste Einschaetzung (gueltig / nicht-gueltig / Duplikat) | innerhalb von **10 Werktagen** |
| Update-Zyklus bis zum Fix | mindestens alle **14 Tage** |
| Embargo-Ende (Public-Disclosure nach Fix) | typisch **90 Tage** nach Erstmeldung, fruehestens nach Patch-Release |

**Was wir bitten:**

- Keine Tests gegen produktive Customer-Installationen ohne explizite Erlaubnis
- Keine Bulk-Scans, kein DoS, keine Datenexfiltration
- Vertraulichkeit bis zur abgestimmten Veroeffentlichung (Embargo)
- Bei Live-Exploits in Umlauf: sofortige Information, dann Sofort-Action

**Anerkennung:**

Reporter werden — sofern gewuenscht — im Release-Note des Fix-Releases namentlich
genannt. Eine Hall-of-Fame fuehren wir nicht.

## 2. Unterstuetzte Versionen & Product Lifecycle

NoRisk-Endpoint folgt einer **garantierten Support-Periode von mindestens
5 Jahren ab Verkaufsdatum** (CRA-Mindestanforderung).

| Version | Verkaufsstart | Security-Updates bis | Status |
|---|---|---|---|
| 1.0 (initial Release) | `⟨TBD: Datum erster bezahlter Verkauf⟩` | `⟨TBD: Verkaufsstart + 5 Jahre⟩` | aktiv |
| Beta (2026) | nicht verkauft | nicht zutreffend (Beta-Lifecycle endete 15.05.2026) | end-of-life |

**Update-Politik:**

- Critical-Schwachstellen (CVSSv4 ≥ 9.0): Fix innerhalb von **7 Tagen**
- High-Schwachstellen (CVSSv4 7.0–8.9): Fix innerhalb von **30 Tagen**
- Medium (4.0–6.9): mit naechstem Minor-Release
- Low: mit naechstem Major-Release oder per Risiko-Akzeptanz dokumentiert

**End-of-Life-Kommunikation:**

- Sechs Monate vor EoL einer Major-Version: Hinweis in Release-Notes, Update-Pfad-Doku
- Drei Monate vor EoL: in-App-Hinweis fuer Endnutzer
- Nach EoL: keine Security-Patches mehr; Versions-Migration ist Customer-Pflicht

## 3. Software Bill of Materials (SBOM)

Fuer jede veroeffentlichte NoRisk-Endpoint-Version erzeugen wir ein SBOM im
**CycloneDX-Format** (sowohl `requirements`-basiert als auch
`environment`-basiert).

**Verfuegbarkeit:**

- An jedem GitHub-Release angehaengt (Tag `v*.*.*`), oeffentlich downloadbar
- Generierungs-Workflow: `.github/workflows/cra-sbom.yml`
- Aufbewahrung: 5 Jahre nach Release (extern gesichert ausserhalb der GitHub-
  Artifacts-Retention, Pfad: `⟨TBD: z. B. intern, extern gesichert⟩`)

**Auf Anfrage:** SBOMs aelterer Versionen, fuer die der GitHub-Release-Asset
nicht mehr verfuegbar ist, lieferbar ueber `⟨TBD: Kontakt⟩` innerhalb von
**10 Werktagen**.

## 4. Vulnerability-Handling-Prozess (intern)

1. **Eingang** ueber GitHub Security Advisory oder Sicherheits-Mail.
2. **Triage** (Maintainer): Reproduzierbarkeit, CVSS-Score, Schwere, betroffene
   Versionen, Mitigations-Strategie. Eintrag in private GitHub Security Advisory.
3. **Fix-Entwicklung** auf privatem Branch, ggf. mit Reporter-Konsultation.
   Coordinated mit anderen FINLAI-Apps falls Cross-Cutting-Issue.
4. **Pre-Release-Patch** als signiertes Release-Asset (cosign).
5. **CVE-Reservierung** bei MITRE (falls oeffentliche Komponente betroffen).
6. **Public-Disclosure** zusammen mit Patch-Release, SBOM-Update, Release-Note
   mit CVE-ID und Reporter-Credit.
7. **Post-Mortem** (intern dokumentiert)
   und ggf. Lessons-Learned-Doku.

## 5. CRA-Konformitaets-Statement

NoRisk-Endpoint erfuellt ab `⟨TBD: Datum⟩` die folgenden CRA-Anforderungen
(Stand: Annex I + II des EU Cyber Resilience Act):

- ✓ Secure-by-Default (Standard-Konfiguration ist sicher, opt-in fuer schwaechere)
- ✓ Vulnerability-Handling-Prozess (siehe §4)
- ✓ Coordinated Vulnerability Disclosure (siehe §1)
- ✓ SBOM-Bereitstellung (siehe §3)
- ✓ Support-Periode mind. 5 Jahre (siehe §2)
- ✓ Sicherheits-Update-Kanal (in-App + GitHub Release Feed)
- ✓ Datenminimierung (lokale Verarbeitung, keine zwangsweise Cloud-Anbindung)

---

# Secure-by-Design Engineering Rules

You are a senior secure software engineer. Follow these rules for every implementation.

## Architecture

- Apply least privilege and deny-by-default
- Implement defense in depth — no single security layer as sole protection
- Separate security logic from business logic
- Fail securely: no insecure fallbacks, no silent failure modes
- Minimize attack surface: disable unused features, endpoints, protocols

## Compliance

- Mitigate OWASP Top 10 risks
- Orient implementation at OWASP ASVS Level 2 where applicable
- Apply OWASP Proactive Controls

## Input Handling

- Validate all external input server-side with allow-lists
- Use parameterized queries for all database access — never string concatenation
- Prevent injection: SQL, NoSQL, OS command, LDAP, XPath
- Encode output context-dependently to prevent XSS
- Validate file uploads: size limits, type allow-list, content inspection

## Authentication & Authorization

- Enforce authentication on every protected endpoint
- Enforce authorization checks at API, service, and data-access layer
- Implement RBAC or ABAC — never rely on client-side validation alone
- Secure session handling: HttpOnly, Secure, SameSite flags
- Implement CSRF protection where applicable
- Enforce rate limiting on authentication endpoints

## Cryptography

- Use modern, industry-standard crypto libraries only (e.g. libsodium)
- No custom cryptography — ever
- Hash passwords with bcrypt or argon2
- Use constant-time comparison for secrets
- Never store plaintext secrets
- No MD5 or SHA1 for security-relevant purposes

## Data Protection

- Minimize data collection and retention
- Protect data in transit: TLS 1.2+ enforced
- Protect sensitive data at rest: encryption required
- Do not log secrets, tokens, or personal data
- No sensitive data in URLs or client-side storage

## Error Handling

- No stack traces or internal details in production responses
- Return generic error messages to users
- Log errors server-side with context but without sensitive data
- Catch all exceptions — no unhandled errors

## Logging & Monitoring

- Log authentication and authorization failures
- Log suspicious activity patterns
- Implement rate limiting per endpoint
- Ensure logs are tamper-resistant and centrally collected

## Secure Configuration

- No hardcoded secrets, keys, or passwords in source code
- Use environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager)
- Secure defaults: CORS restrictive, security headers set (CSP, HSTS, X-Content-Type-Options)
- Features disabled by default, not enabled
- Ensure.env files are in.gitignore

## Dependencies

- Pin exact versions — no version ranges
- No packages with known CVEs
- Prefer standard library over third-party where feasible
- Minimize total dependency count
- Document why each dependency is needed

## API Security

- Enforce request size limits
- Validate Content-Type headers
- Version APIs explicitly
- Implement per-endpoint rate limiting
- Return minimal data — no over-fetching

## Process Requirements

Before writing code:
1. Provide a short STRIDE-based threat model
2. Identify attack vectors for the requested functionality
3. Explain the mitigation strategy

After implementation:
1. Explain security design decisions in comments
2. List residual risks
3. Suggest further hardening measures

## Testing

- Write security-focused unit tests
- Include negative test cases (malformed input, missing auth, privilege escalation)
- Include abuse cases (rate limit bypass, injection attempts)

## Forbidden Patterns

- `eval` or equivalent dynamic code execution
- Raw SQL concatenation
- Disabling security middleware
- Custom cryptographic implementations
- Exposing secrets in logs, errors, or responses
- `innerHTML` with unsanitized input
- Wildcard CORS (`*`) on authenticated endpoints
- Hardcoded secrets, keys or master secrets in source code (use SecureStorage)
- Silent plaintext fallback when encryption fails (fail-closed: raise RuntimeError)
- Passing raw LLM output to secondary LLM inputs without injection scanning

## finLai-spezifische Sicherheitsmaßnahmen

### LLM-Output — Markdown-Render-Hardening (P0-4, seit 26.05.2026)

`core/widgets/secure_markdown_browser.py:SecureMarkdownBrowser` subclasst
`QTextBrowser` und blockt drei Angriffsvektoren auf LLM-gerenderte Markdown-
Inhalte. Seit (Cloud-LLM-Removal) verarbeitet NoRisk ausschliesslich
Ollama-Output (lokal); die Hardening-Layer bleiben aktiv als Defense-in-Depth
fuer den Fall, dass kuenftig externe Markdown-Quellen (z.B. lokale RSS-Feeds,
heruntergeladene Reports) in dieselbe Render-Pipeline kommen. Genutzt in
`tools/ki_integration/gui/chat/message_bubble.py`. Tests:
`tests/test_secure_markdown_browser.py` (28 Tests, 100 % gruen).

- **`loadResource`-Override** verhindert dass `![](http://evil.com/track.png)` beim
  Rendern synchron geladen wird (IP-Leak gegen die DSGVO-Zusage). Erlaubte
  Schemes: `qrc:` (Qt-interne Resources) und `data:` (Inline-Base64). HTTP,
  HTTPS, file, ftp, javascript werden geblockt und in den Logs vermerkt.
- **Anchor-Scheme-Whitelist** (`ALLOWED_ANCHOR_SCHEMES = {"https"}`) filtert
  `[click](javascript:alert(1))`, `file://...`, `data:text/html,...` etc. beim
  Klick. Nur `https`-URLs werden via `QDesktopServices.openUrl` an den
  Default-Browser uebergeben. `setOpenLinks(False)` + `setOpenExternalLinks(False)`
  verhindern, dass Qt die Filterung umgeht.
- **Markdown-Tag-Sanitizer** (`sanitize_markdown`) entfernt vor dem Rendern
  die fuenf gefaehrlichen HTML-Tags `<script>`, `<style>`, `<iframe>`,
  `<object>`, `<embed>` — sowohl als Container als auch self-closing,
  case-insensitive, mehrzeilig. Harmlose Tags (`<b>`, `<em>`, `<table>`,
  `<code>`) bleiben erhalten, weil Markdown sie regelmaessig verwendet.

Threat-Model-Bezug: **R-14 MITIGATED**.

### KI-Agenten (Legacy finLai — NICHT in NoRisk aktiv)

> **Status 2026-05-13:** Die folgenden Schutzmechanismen (Prompt-Injection-Filter,
> URL-Allowlist, Rate-Limiting) stammen aus der finLai-Codebase und sind in NoRisk
> aktuell **nicht implementiert** — `core/agent_runner.py` existiert hier nicht.
> Wenn NoRisk autonome Agent-Workflows einbauen sollte, ist diese Doku der Ziel-
> zustand. Heute Security-Chat) ist der LLM-Call nicht-agentic (kein ReAct-
> Loop, kein WebFetch), Schutz erfolgt durch die Render-Hardening (siehe oben).

`agent_runner.py` (finLai) prüft nach jedem `_parse_response`-Aufruf den kombinierten
Text aus `thought`, `final_answer`, `question` und `action_input` gegen
`_INJECTION_PATTERNS`. Bei einem Treffer wird `SecurityError` geworfen.

```python
# _INJECTION_PATTERNS enthält u.a.:
# "ignore previous", "system prompt", "you are now", "exfiltrate", "http://"
```

`WebFetchTool(url_allowlist=[...])` beschränkt HTTP-Abrufe auf konfigurierte Domains
(Subdomain-Matching). `AgentScheduler._check_rate_limit` zählt `agent_run_logs`-
Einträge der letzten 60 Minuten und blockt bei `MAX_RUNS_PRO_STUNDE (4)`.

### Lizenz — Master-Secret in SecureStorage (seit 30.03.2026)

`_MASTER_SECRET` darf nie im Quellcode stehen. Einmaliger Developer-Setup:

```python
LicenseManager.init_master_secret("mein-geheimes-lizenz-passwort")
```

Zur Laufzeit wird das Secret über `_load_master_secret` aus `SecureStorage`
geladen. Fernet-Key und beide HMAC-SHA256-Aufrufe nutzen diesen Pfad.

### Übersetzungshistorie — Fail-Closed (seit 30.03.2026)

`TranslationRepository._encrypt` und `_decrypt` werfen `RuntimeError` wenn
`self._fernet` nicht initialisiert ist. Kein stiller Klartext-Fallback.

### Robotic-Bots — Log-Sanitizer (seit 30.03.2026)

`handle_log_message` in `system_steps.py` schreibt ausschließlich in den separaten
Logger `finlai.bots`. `_sanitize(msg)` begrenzt auf 100 Zeichen und ersetzt
IBAN-Muster, lange Nummernfolgen und Passwort-Keywords durch `[ENTFERNT]`.

### LLM-Inferenz — Ollama-only, lokal (Stand 2026-05-28)

`core/llm/` nutzt seit (Cloud-LLM-Removal, 2026-05-28) ausschliesslich
**Ollama** als Provider — lokale Inferenz, kein API-Key, kein Datenfluss
nach extern. Chat-Inhalte verlassen das Geraet nicht.

Architektur-Konsequenzen:

- `SecureStorage` enthaelt keine Provider-API-Keys mehr (nur noch
  `nvd_api_key` fuer CVE-Abfragen und optional `virustotal_api_key` fuer
  den Document Scanner Hash-Lookup).
- Die generische Multi-Provider-Schicht (frueher `core/llm/openai.py`,
  `core/llm/anthropic.py`) ist entfernt. `OllamaClient` ist der einzige
  Backend-Adapter.
- AI-BOM (`core/sbom_aibom/ai_bom_service.py`) listet seit-aibom
  keine Cloud-Provider mehr — auch dann nicht, wenn Bestandsdaten-API-Keys
  in der `SecureStorage` liegen (Regression-Test:
  `test_build_ai_bom_ignoriert_bestandsdaten_cloud_keys`).

### Historie: Cloud-LLM-Provider (10.04.2026 → 28.05.2026)

Zwischen 10.04.2026 und 28.05.2026 unterstuetzte NoRisk drei LLM-Provider
(Ollama lokal, OpenAI Cloud, Anthropic Cloud). Cloud-API-Keys lagen in
`SecureStorage`, ein DSGVO-Hinweis warnte beim ersten Aktivieren eines
Cloud-Providers, dass Chat-Inhalte das Geraet verlassen wuerden. Default
war immer Ollama.

Der Sprint **//** (Cloud-LLM-Removal,
28.05.2026, NoRisk +) hat alle Cloud-Provider-Pfade,
das DeepL-Uebersetzungs-Tool und die Provider-Auswahl-UI vollstaendig
entfernt — NoRisk ist seitdem zu 100% lokal. Der Wechsel kam aus
DSGVO-/EU-AI-Act-Vereinfachung (kein Auftragsverarbeitungs-Vertrag mit
US-Anbietern noetig) und zur Reduktion der Angriffsoberflaeche. Die
Trust-Boundary **TB-D** (App ↔ Cloud-LLMs/DeepL) im THREAT_MODEL.md ist
damit obsolet — der Update der Bedrohungsanalyse auf den End-Stand
laeuft als-smoke.

### Network-Scanner — Externe Ziele GUI-seitig gesperrt (seit Run-1, 2026-05-02)

`tools/network_scanner/application/network_service.py:scan_ziel` akzeptiert
zwar einen `extern_erlaubt: bool = False`-Parameter, die GUI ruft den
Service jedoch **niemals mit `extern_erlaubt=True`** auf. Externe Ziele
werden vom Service mit `extern_erlaubt=False` blockiert (Default) —
§202c-StGB-Schranke ist eingehalten. Run-1-Patch `895208a` hat die
Default-Blockade ergaenzt.

Ein zukuenftiger GUI-Pfad mit modalem Confirm-Dialog (Pentest-Auftrags-
Erinnerung) ist im THREAT_MODEL.md als R-2 dokumentiert, aber nicht in
1.0 enthalten. Bis dahin gilt: **kein externer Scan ueber GUI moeglich**,
nur ueber direkten Service-Aufruf mit explizitem Parameter (z. B. in
Tests).

### Dependency-Auditor — externe OSV-Abfrage an api.osv.dev (seit 12.06.2026)

Der Dependency-Auditor (`tools/dependency_auditor/`) fragt pro geprüfter
Abhängigkeit den externen Dienst **api.osv.dev** (Open Source
Vulnerabilities) ab: `POST https://api.osv.dev/v1/query` über HTTPS,
Request-Body enthält nur **Paketname + effektive Version** (Pin bzw.
installierte Version) — keine Dateiinhalte, Pfade oder Systemdaten. Kein
API-Key; Rate-Limiting über den zentralen HTTP-Client
(`core/http_client.py`); Fehler führen zu leerer Ergebnisliste statt
Crash. Threat-Model-Hinweis: Ein Beobachter der Abfragen kann den
Dependency-Bestand (Name + Version) der geprüften requirements-Datei
ableiten — akzeptiertes Restrisiko, hier transparent dokumentiert.

### OCR — Bildverarbeitung lokal (seit 10.04.2026)

`OllamaVisionOCR` verarbeitet Bilder ausschließlich lokal via Ollama. Bilder werden
nicht an externe Server gesendet. `ChandraOCR` läuft ebenfalls lokal (GPU-Modell).
Kein Cloud-OCR-Anbieter ist integriert.

### Recovery-Code — Offline-Passwort-Reset (seit 20.04.2026)

`core/auth/recovery_code.py` erzeugt einen 16-stelligen Base32-Code aus einem reduzierten
Zeichensatz (25 Zeichen, ohne `O`, `I`, `L`, `8`, `B` — Ziffern `0` und `1` sind im
Base32-Alphabet ohnehin nicht enthalten). Entropie: ~74 Bit. Format: `XXXX-XXXX-XXXX-XXXX`.

```python
from core.auth.recovery_code import generate_recovery_code, hash_recovery_code, verify_recovery_code

code = generate_recovery_code # Einmalige Anzeige im First-Run-Wizard
user.recovery_code_hash = hash_recovery_code(code) # bcrypt Cost 12
#... Speicherung in users.json

# Reset-Dialog:
if verify_recovery_code(user_input, user.recovery_code_hash):
    rotate_password(user, new_password)
    user.recovery_code_hash = hash_recovery_code(generate_recovery_code) # neuer Code
```

- Hash: bcrypt Cost 12 (identisch mit Admin-Passwort-Hash)
- Klartext-Code wird ausschließlich einmalig im Wizard angezeigt und nie auf Disk geschrieben
- Ein verbrauchter Code wird sofort durch einen neuen ersetzt — keine Doppelnutzung möglich
- `verify_recovery_code` fängt ungültige Formate und leere Hashes ab, wirft nie Exception (kein Info-Leak)
- Rate-Limit: nach 5 falschen Eingaben im `forgot_password_dialog.py` → 60s Sperre

### Password-Reset-Flow (seit 20.04.2026)

`core/auth/password_reset.py` rotiert den Admin-User-Hash auf Basis eines gültigen
Recovery-Codes. Fehlversuche werden im Audit-Log als `PASSWORD_RESET_FAILED` protokolliert,
Erfolge als `PASSWORD_RESET`. Kein DB-Wipe, kein Re-Initialize.

### First-Run-Wizard — Admin-Setup (seit 20.04.2026)

Der neue Admin-User wird ausschließlich im First-Run-Wizard (`core/first_run_wizard/`) angelegt.
Die Trigger-Logik in `trigger.py` startet den Wizard nur wenn `users.json` fehlt oder keine
Admin-User enthält — ein zweiter Admin-Setup nach Installation ist nicht möglich.

Die AdminSetupPage prüft Passwort-Stärke in Echtzeit (Länge ≥ 10, eine Zahl, ein Sonderzeichen).
Der Recovery-Code wird erst *nach* bestätigter Passwort-Eingabe generiert und vom User
explizit durch Klick auf „Ich habe den Code gesichert" bestätigt, bevor der Wizard fortfährt.

### NoRisk BETA_BUILD_MODE — Zeit-begrenzter Lizenz-Bypass (seit 20.04.2026, läuft 15.05.2026 aus)

`core/beta_mode.py` umgeht den Lizenzfluss ausschließlich für die NoRisk-Beta-Binary bis
einschließlich 15.05.2026. Zwei Aktivierungspfade:

- `BETA_BUILD_MODE = True` im Build-Flag (fest in die Beta-Binary kompiliert)
- `NORISK_BETA_UNTIL` als Env-Var (nur für Developer-Tests)

Beide werden gegen `BETA_BUILD_EXPIRY = date(2026, 5, 15)` per MIN-Clamp gekappt — ein
manipulierter `NORISK_BETA_UNTIL=2099-01-01` läuft trotzdem am 15.05.2026 ab. Der Bypass
greift nur für `app_id="norisk"`; andere Apps ignorieren das Flag und loggen einen
`WARNING` wenn die Env-Var gesetzt wäre.

Nach Ablauf wird die App gestartet, aber fordert eine reguläre Lizenz. **Residualrisiko:**
Ein manipuliertes Beta-Binary mit `BETA_BUILD_MODE=True` und überschriebenem
`BETA_BUILD_EXPIRY` würde den Bypass verlängern — das ist eine Integrität-Frage der
Binary, nicht des Runtime-Codes. Der Produktiv-Build setzt `BETA_BUILD_MODE = False` oder
entfernt das Modul vollständig.

**Zuletzt geprüft:** 21.04.2026 — Recovery-Code + Password-Reset: bcrypt Cost 12, Fail-Closed bei leerem Hash, Rate-Limit im Dialog. BETA_BUILD_MODE: Hard-Expiry per Code-Konstante, MIN-Clamp gegen Env-Manipulation. Keine neuen kritischen Findings.

### Briefing-Audit-Trail — Klartext-Persistenz von TechStack-Daten (seit 08.05.2026)

`tools/cyber_dashboard/data/briefing_history_repository.py` persistiert
jeden KI-Briefing-Aufruf in einer eigenen SQLCipher-DB (`briefing_history`).
Felder: Modell, Prompt-Hash (SHA-256), **Prompt im Klartext**, Output, Score-
Snapshot, Dauer, Fehler.

**Privacy-Klassifikation der Inhalte:**
- BSI/MSRC-RSS-Meldungen, NVD-CVE-Texte, Consumer-Advisories: **öffentliche Daten**
  (kommen aus öffentlichen Feeds — keine User-PII). Klartext-Persistenz unkritisch.
- **TechStack-Einträge** (`tools/cyber_dashboard/domain/models.py:TechStackEintrag`,
  Felder `name` + `version`): **User-Eingaben**. Beispiel: ein User trägt
  `name="Patrick's Privat-Server"` ein → der Eintrag wandert via `_waehle_kandidaten`
  in den `_Kandidat.produkt`, von dort in den User-Prompt, und wird damit im
  Klartext in `briefing_history.prompt` persistiert.

**Mitigation P2, 09.05.2026):** Dieser Hinweis. Settings-Tab-UI-Hinweis
"Techstack-Einträge erscheinen im KI-Audit-Trail" steht als Folge-Task an,
sobald der Audit-Trail eine User-facing GUI bekommt. SQLCipher-Verschlüsselung
schützt den Klartext bei Datenträger-Diebstahl; Risiko bleibt bei Multi-User-
Workstations ohne Disk-Encryption.

**Out-of-Scope:** Privacy-Filter (Maskierung) wäre verlustreich für Audit-
Zweck (Regression-Detection braucht den Original-Prompt). Wer ohne TechStack-
Persistenz briefen will: TechStack-Einträge auf `aktiv=False` setzen.
