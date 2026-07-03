# system_tuner — Threat Model (Apply-Pfad, R5/R6/R7)

> Pflicht-Artefakt fuer den `/security-review`-Gate (Plan R7). Bewertet die
> NEUE Angriffsflaeche durch das erste arbitrary-write-Primitiv von NoRisk
> jenseits von winget. **Status: `APPLY_ENABLED=False` — echtes Schreiben ist
> gesperrt, bis dieses Threat Model + benannte Security/Legal/Produkt-Sign-offs
> + ein Windows-Admin-Smoke vorliegen.**

## Assets
- Integritaet der System-Konfiguration des Kundengeraets (Registry/Dienste).
- Verfuegbarkeit kritischer Windows-Funktionen (Update, Defender, BitLocker/TLS).
- Reversibilitaet (Snapshots) + Audit-Integritaet (Compliance-Nachweis).
- Dev-Signing-Private-Key (ausserhalb Repo, `~/.finlai/`).

## Trust Boundaries
1. **GUI (user) → elevated Prozess (Admin).** Die GUI ist NICHT vertrauenswuerdig
   (kann kompromittiert/manipuliert sein). Der elevated Prozess ist die
   Trust-Boundary.
2. **Repo/Bundle → Laufzeit.** Katalog + NEVER_DISABLE werden signiert ausgeliefert.
3. **Lokaler Admin/Insider** ist NICHT im Abwehrmodell (kann ohnehin alles).

## Bedrohungen & Mitigations
| # | Bedrohung | Mitigation | Status |
|---|---|---|---|
| T1 | Kompromittierte GUI laesst beliebige Registry/Dienst-Writes elevated ausfuehren | Elevated Prozess re-lädt **signierten** Katalog + NEVER_DISABLE selbst, re-resolved jede Op, lehnt jedes nicht-katalogisierte Ziel ab (`run_elevated_apply`) | ✅ Logik gebaut+getestet |
| T2 | Plan-Datei manipuliert (IDs/Ziele getauscht) | HMAC-SHA256-Bindung (`apply_plan`) ueber token+IDs+Katalog-Signatur; Mismatch → Reject | ✅ |
| T3 | Katalog/Signatur ausgetauscht | Ed25519-Verify gegen eingebetteten Public-Key (`catalog_signature`); fail-closed → ohne gueltige Signatur nur Scan | ✅ |
| T4 | Tweak zielt doch auf Defender/Update/Crypto | NEVER_DISABLE: Loader-Invariante **und** Engine-Recheck pro Op unmittelbar vor jedem Write | ✅ |
| T5 | Replay eines alten/gueltigen Plans | Single-Use-uuid4-Token; Plan-Datei nach Lesen loeschen; `used_tokens` | 🟡 Logik da; Datei-Loeschung im Entry-Adapter offen |
| T6 | Verify-Mismatch hinterlaesst Halbzustand | Pre-Write-Snapshot + Verify-Readback + Auto-Revert; `BatchResult` meldet `FAILED_ROLLED_BACK` | ✅ |
| T7 | Kein Rollback bei System-Breakage | System-Restore-Point fail-closed VOR Batch (R6); throttled → Abbruch/Override | 🟡 Gate in Orchestrator; `Checkpoint-Computer`-Adapter (Windows) offen |
| T8 | EoP via elevated Prozess (DLL-Hijack, schreibbarer Pfad) | `harden_dll_search_path()` als erste Anweisung; `assess_install_path_trust` vor elevated Exe (Muster collector) | 🔴 Entry-Adapter offen |
| T9 | Plan-HMAC-Secret nicht prozess-uebergreifend verfuegbar/leakt | Secret = DEK aus Key-Manager (nicht persistiert im Plan) | ✅ Gebaut 2026-06-17c — HMAC **und** Snapshot-DB-Key aus envelope-DEK; elevated bootet KeyManager aus DPAPI-DEK; `apply.key` eliminiert |
| T10 | Falscher Compliance-Erfolg auf verwaltetem Geraet (GPO/MDM ueberschreibt) | Managed-Mode-Erkennung + ehrliche Anzeige; kein unqualifizierter Erfolg | ✅ (Scan); Apply-Annotation offen |

## Restrisiken (vor Scharfschaltung zu klaeren)
- T5/T8 Entry-Adapter (Single-Use-Datei-Loeschung, DLL/Pfad-Haertung) sind
  Windows-only und noch nicht implementiert/gesmoked.
- Dev-Signing-Key: kein HSM/Rotation; nur fuer Vor-Release.
- AppX (T3-Tier) bewusst NICHT im Apply (nicht sauber reversibel).
- Restore-Point schuetzt nicht gegen alle Breakage-Klassen (z. B. Dienst-Abhaengigkeiten).

## Gate zum Scharfschalten (`APPLY_ENABLED=True`)
1. T5/T7/T8 Windows-Adapter implementiert + Admin-Smoke gegen gebautes Artefakt.
2. Persistente SQLCipher-Snapshots (prozess-uebergreifend) + Key-Manager-Wiring
   (T9) — ✅ GEBAUT (`data/encrypted_snapshot_repo.py`; DB-Key **und** Plan-HMAC
   aus dem envelope-DEK, `apply.key` eliminiert — s. Abschnitt „2026-06-17c").
3. EULA-Delta-Text final + anwaltlich gegengelesen (R7) — ✅ **B3 (2026-06-18):**
   `apply_terms.py` v1.1, ENTWURF-Marker entfernt; `CURRENT_EULA_VERSION` bleibt
   single-sourced aus `APPLY_TERMS_VERSION` → Bump erzwingt frische Einwilligung.
4. `/security-review`-Pass auf diesem Threat Model — ✅ **B4 (2026-06-18): PASS**
   (0 P0/P1, 0 confirmed criticals; s. Abschnitt „Security-Review 2026-06-18 (B4)").
   Anmerkung: Der Apply-Pfad selbst ist seit 2026-06-17c unveraendert; B4 fokussierte
   die neue B2/B3-Surface + Gate-Integritaet. Bei aenderndem Apply-Code: B4 erneuern.
5. Benannte Sign-offs: Security · Legal · Produkt/Haftung — s. **Sign-off-Matrix (B0)** unten.

## Security-Review 2026-06-17 (adversariales 5-Lens-Panel)

Befunde gegen den echten Code verifiziert. Trust-Boundary haelt (B9: Plan traegt
nur Tweak-IDs, HMAC `compare_digest`, Ed25519 fail-closed, Re-Resolve `by_id[i]`)
— **sofern die Gate-Items unten geschlossen sind.**

**SOFORT GEFIXT (dieser Stand):**
- **A1 (Teil)** `run_elevated_apply` verlangt jetzt die autoritative Modul-Konstante
  `APPLY_ENABLED` UND den Parameter (argv-`--allow-apply` allein genuegt nicht).
- **A2 (Teil)** `read_and_consume_plan` ist fail-closed: scheitert das Loeschen der
  Plan-Datei, wird NICHT angewandt (kein Replay ueber liegengebliebene Datei).
- **A6** Operanden-Whitelist im `catalog_loader` (hive HKLM/HKCU, service_name
  `^[A-Za-z0-9_.-]{1,256}$`, key ohne fuehrenden Slash/Steuerzeichen) — fail-closed.
- **A7** `apply.key`-Strip-Race gegenstandslos: `apply.key` ist in T9 (2026-06-17c)
  eliminiert (HMAC-Secret kommt aus dem envelope-DEK).
- **A8** `_coerce_value` wirft nie (ungueltiges `desired` → fail-ProbeResult).

**NACHGEZOGEN (2026-06-17, dev-fallback-Pfad live verifiziert; Admin-DACL-
Enforcement braucht den Admin-Smoke):**
- **A2 (voll)** persistenter Single-Use-Token-Ledger (`token_ledger` in der
  admin-only `secure_store`-Ablage) + `used_tokens` an `run_elevated_apply`
  verdrahtet (commit-then-act, mark_used VOR Apply). ✅
- **A3** `run_apply_entry` prueft `is_admin()` + `assess_install_path_trust`
  (Laufzeit-Image); Non-Admin/untrusted → fail-closed (Dev-Override-Flag). ✅
- **A4** `ConsentGate.has_consent()` als fail-closed Gate im elevated Pfad (R7). ✅
- **A5** Result-Marker + Snapshots in `%ProgramData%\NoRisk` (`secure_store`,
  admin-only DACL: SYSTEM/Admins full, Users read) + Result HMAC-signiert. ✅
- **A1 (voll)** Dev/Smoke-Flags (`--allow-apply`/`--skip-restore-point`/
  `--catalog`/`--allow-untrusted-path`) im Entry-Dispatch hart ignoriert ausser
  im non-frozen Dev-Build mit `NORISK_SYSTEM_TUNER_DEV=1`; in Produktion (frozen)
  Katalog auf Default festgenagelt. ✅

**OFFEN VOR `APPLY_ENABLED=True` (zusaetzlich zu 1–5 oben):**
- **Admin-Smoke** des vollen Happy-Path (echte HKLM-Writes + admin-only
  ProgramData-DACL-Enforcement + `Checkpoint-Computer`) auf einer Admin-Maschine —
  als Non-Admin nur dev-fallback + fail-closed verifizierbar.
- Prod-Signing-Key, echter UAC-relaunch. (Persistente SQLCipher-Snapshots statt
  JSON ✅ GEBAUT 2026-06-17 — s. Abschnitt „Security-Review 2026-06-17b".)

**Akzeptiertes Restrisiko / DiD (im T-Model gefuehrt):** B1/B2 (apply.key user-lesbar)
sind durch T9 (2026-06-17c) **eliminiert** — `apply.key` existiert nicht mehr, beide
Secrets kommen aus dem envelope-DEK. Re-Resolve bleibt die tragende Mitigation;
B4–B7/B11 optionale Haertungen niedriger Severity.

## Security-Review 2026-06-17b (Persistente SQLCipher-Snapshots, T6)

Die Klartext-JSON-Snapshot-Ablage (`file_snapshot_repo.py`) wurde durch eine
verschluesselte SQLCipher-DB (`data/encrypted_snapshot_repo.py`,
`EncryptedSnapshotRepository`) ersetzt: AES-256-CBC, HMAC-SHA512-Seitenintegritaet,
append-only (uuid4-id, `PRAGMA user_version`, latest-wins je `tweak_id` ueber die
monotone `rowid`). Liegt weiterhin in der admin-only `secure_store`-Ablage.

**Schluessel:** Der DB-Schluessel kommt aus dem zentralen KeyManager (envelope-DEK,
`derive_secondary_key("db:system_tuner_snapshots")`) — **scharfgeschaltet in T9
(2026-06-17c, s.u.).** (Zwischenstand am 2026-06-17b war eine Ableitung aus dem
user-lesbaren `apply_secret`; seit T9 ersetzt.) Snapshots tragen nur Konfig-Vorwerte
(keine Credentials); tragende Integritaets-Mitigation bleibt die admin-only DACL, die
Verschluesselung ist Defense-in-Depth (at-Rest + Tamper-Evidenz).

`core.database.EncryptedDatabase` wurde dafuer additiv + rueckwaerts-kompatibel um
einen optionalen `db_path`-Parameter erweitert (expliziter Pfad ausserhalb
`~/.finlai/db`). Der in 2026-06-17b zusaetzlich eingefuehrte explizite `key`-Param
wurde in T9 (2026-06-17c) wieder entfernt — der Schluessel kommt wieder NUR aus dem
KeyManager (Invariante „alle finLai-DBs nutzen KeyManager-Keys" wiederhergestellt).
Default-Verhalten aller bestehenden DBs unveraendert (volle Suite gruen).

**Adversariales Review (5 Lenses) → SOFORT GEFIXT:**
- **Fail-closed-Regression (high):** Die neue Repo-Konstruktion oeffnet sofort eine
  DB-Verbindung und kann werfen (fehlende sqlcipher3, Schluessel-Mismatch, IO/DACL) —
  anders als die frueher lazy, wurf-freie `FileSnapshotRepo`. `run_apply_entry` fing
  das nicht → unbehandelter Crash im elevated Prozess, kein Reject-Marker, GUI 90s im
  Timeout (Verletzung der „nie crashen"-Doktrin). Fix: DB-Init + Apply-Tail in
  try/except, schreibt fail-closed einen signierten Reject-Marker.
- **Token-Burn vor DB-Init (medium):** Der Wurf-Pfad lag NACH `ledger.mark_used` → ein
  **transienter** DB-Fehler verbrannte den Single-Use-Token dauerhaft (Plan
  unwiederholbar). Fix: DB-Init VOR den Token-Burn gezogen; ein DB-Init-Fehler laesst
  den Token unverbraucht (Retry moeglich). Token-Burn beim echten Apply bleibt
  (Replay-Schutz). Tests: `TestEntryFailClosed` (rc=0 + Reject-Marker + Token
  unverbraucht).
- Korrektheits-/Test-Haertung: rowid-basiertes latest-wins (statt Sekunden-`created_at`
  + uuid), Index auf den echten Zugriffspfad, echter WAL-Klartext-Test
  (offen gehaltene Verbindung), Engine×echtes-Repo-E2E (apply→Snapshot→Revert ueber
  frische Repo-Instanz, inkl. Re-Apply-latest-wins).

**Restschuld:** T9 (KeyManager-Schluessel) ✅ erledigt (2026-06-17c). Optional
`purge_older_than` beim Scharfschalten (bewusst weggelassen — endlicher Katalog,
seltene Applies, latest-wins macht Altzeilen irrelevant). `APPLY_ENABLED` bleibt False.

## Security-Review 2026-06-17c (T9 — KeyManager-Wiring scharfgeschaltet)

Snapshot-DB-Schluessel **und** Plan-/Result-HMAC-Geheimnis kommen jetzt aus dem
zentralen KeyManager (envelope-DEK, HKDF-Domain-Separation:
`db:system_tuner_snapshots` bzw. `system_tuner:apply_hmac`). Der app-bootlose
elevated Prozess bootet den KeyManager selbst aus dem DPAPI-gewrappten DEK
(`_resolve_key_manager`: aktiver KM ODER `KeyManager().load_master_key()`,
fail-closed bei fehlendem DEK -> rc=2). Die user-lesbare Klartext-Datei `apply.key`
(`apply_secret.py`) ist **eliminiert** -> B1/B2 geschlossen. Beide Prozesse (GUI +
elevated) leiten denselben Schluessel ab, weil UAC-Elevation derselbe Windows-User
ist (DPAPI-CurrentUser-Unwrap desselben `master.key.wrapped`).

**Neues akzeptiertes Restrisiko (T9-D1):** Der elevated (Admin-)Prozess entwrappt
jetzt den **vollen master-DEK** (statt nur eines 32-Byte-`apply_secret`). Damit
weitet sich der Blast-Radius einer Memory-Disclosure IM vertrauenswuerdigen elevated
Prozess von „ein Tool-Secret" auf „master-DEK / alle DB-Schluessel". **Akzeptiert:**
Ein Admin-on-same-user kann `master.key.wrapped` (CurrentUser-Scope) ohnehin selbst
entschluesseln, und „lokaler Admin/Insider" ist nicht im Abwehrmodell (Trust-Boundary
3) -> KEIN neuer Vorteil fuer einen in-scope Angreifer. Die DEK-Lebensdauer ist durch
den **kurzlebigen** Apply-Prozess (ein Apply -> `sys.exit`) bereits eng begrenzt;
darum bewusst KEIN `wipe()` wie im langlebigen Collector (`collector_main`) — der
Lifecycle-Unterschied rechtfertigt die Abweichung.

**Adversariales 5-Lens-Review (9/18 Befunde bestaetigt) → gefixt/behandelt:**
- **TOCTOU `signature_path.read_text()` (medium, pre-existing):** lag zwischen den
  beiden try-Bloecken NACH dem Token-Burn -> OSError haette unbehandelt gecrasht
  (kein Marker). Fix: in try/except OSError -> `signature_ok=False` -> fail-closed
  Reject-Marker.
- **GUI-Seite `request_elevated_apply` ungetestet (medium):** +2 Tests (Plan-Bindung
  mit KM-Secret cross-process-verifiziert; fail-closed ohne KM).
- **Snapshot-DB-Purpose ungepinnt (medium):** Charakterisierungstest nagelt
  `db:system_tuner_snapshots` fest (Rename wuerde sonst still DBs verwaisen).
- **Import-Order-Fragilitaet `_MASTER_KEY_FILE` (low, latent):** aktuell korrekt
  (empirisch: erster key_manager-Import liegt NACH `set_finlai_home`), aber an
  einen Import-Order-Constraint gebunden (in-code dokumentiert in
  `_resolve_key_manager`). **Durabler Fix (Restschuld):** `_MASTER_KEY_FILE` in
  `key_manager` lazy aufloesen (Helper statt Import-Zeit-Konstante).
- Test-Haertung: orphan-Plan-Cleanup im GUI-Timeout, Bootstrap-Idempotenz-Assert
  (aktiver State statt nur Objekt-Identitaet), echter cold-boot fail-closed
  (kein KM + fehlender master.key -> rc=2), wrong-KM-Isolations-Vorbedingung.

**OFFEN (Admin-Smoke):** echter elevated DPAPI-DEK-Round-Trip — verifizieren, dass
GUI und elevated unter dem TATSAECHLICHEN FINLAI_HOME denselben DEK lesen (das
Import-Order-Constraint haelt im Default-Install; non-default FINLAI_HOME im
Admin-Smoke pruefen). `APPLY_ENABLED` bleibt False.

## Security-Review 2026-06-18 (B4 — Gate-Item 4: PASS)

Formaler `/security-review`-Pass (adversariales 3-Lens-Panel + Verifikation,
Workflow wf_146a1d2f). Fokus: die NEUE Surface dieser Session (B2 Prod-Key-
Rotation + Signing-Helfer `sign_tuner_catalog.py`, B3 EULA-Finalisierung) sowie
die Gate-Integritaet. Der Apply-Pfad selbst ist seit 2026-06-17c unveraendert
(dort bereits 3x adversarial geprueft) und wurde nur auf Re-Bestaetigung gelesen.

**Verdikt: PASS** — 0 P0/P1, 0 confirmed criticals. Verifiziert: `APPLY_ENABLED`
bleibt `False`; das Doppelgate (Modul-Konstante UND Parameter) haelt; die neue
`.sig` verifiziert gegen den eingebetteten Prod-Public-Key; Re-Resolve lehnt
nicht-katalogisierte Ziele weiterhin ab (0/1 akzeptiert); der EULA-Bump 1.0->1.1
erzwingt frische Einwilligung (single-sourced).

**Befunde adressiert (kein Gate-Blocker, Schluessel-Hygiene gehaertet):**
- **P2** `sign_tuner_catalog.py keygen`: Privatkey wurde mit Default-Umask
  geschrieben, dann erst `chmod 0o600` (TOCTOU-Fenster auf POSIX; auf Windows ist
  `chmod` ein No-op -> Datei NICHT ACL-geschuetzt, Fehler still geschluckt). FIX:
  atomar restriktiv via `os.open(O_CREAT|O_EXCL|O_WRONLY, 0o600)`; auf Windows
  explizite WARNUNG (keine FS-ACL -> manuell einschraenken / verschluesselt
  offline). Zusaetzlich: keygen lehnt Out-Pfade IM Repo-Baum ab.
- **P3** `.gitignore`: `*signing_key*.b64` / `*_signing_key.b64` ergaenzt
  (zweite Bremse gegen versehentlichen Privatkey-Commit; `.sig` bleibt getrackt).
- **P3** Test-Docstring `test_system_tuner_signature.py`: „Dev-Public-Key" ->
  „Prod-Public-Key (seit B2 2026-06-18)" (Doku-Drift behoben).
- **P3** (Defense-in-Depth, NICHT umgesetzt, kein Gate-Bezug): `record_consent`
  koennte die Version explizit durchreichen; At-Rest-Verschluesselung des
  Privatkeys per Passphrase optional. Beide sind organisatorisch durch die
  B2-Empfehlung (offline/verschluesselt) abgedeckt.

## Sign-off-Matrix (B0, 2026-06-18)

Die drei vom Gate (Punkt 5) verlangten Unterschriften werden vom Firmeninhaber
**Patrick Riederich** wahrgenommen (B0-Entscheid 2026-06-18). Erst mit allen drei
Zeilen ✅ **und** Gate-Items 1–4 erfuellt darf `APPLY_ENABLED=True` (eine Zeile in
`application/elevated_apply.py:45`) gesetzt werden.

| Rolle | Kriterium (Gate-Item) | Name | Status / Datum |
|---|---|---|---|
| Security | Threat-Model abgenommen + `/security-review`-Pass (Gate 4 / B4) + Windows-Admin-Smoke gegen gebautes Artefakt (Gate 1 / B1) | Patrick Riederich | ⬜ offen — abhaengig von B1 + B4 |
| Legal | EULA-Delta final + anwaltlich gegengelesen (Gate 3 / B3) | Patrick Riederich | ✅ freigegeben 2026-06-18 (`apply_terms.py` v1.1) |
| Produkt/Haftung | Kundenhaftung getragen; Funktion nur Pro/Enterprise (`edition_gate`) | Patrick Riederich | ⬜ offen — zu zeichnen nach Security + Legal |

> Vorgehen: Legal ist mit B3 gezeichnet. Security wird gezeichnet, sobald B4
> (`/security-review`-Pass) **und** B1 (Admin-Smoke des Happy-Path: echte
> HKLM-Writes + admin-only ProgramData-DACL + `Checkpoint-Computer`) vorliegen.
> Produkt/Haftung folgt zuletzt. Datum + Commit-Referenz je Zeile beim Zeichnen
> nachtragen.
