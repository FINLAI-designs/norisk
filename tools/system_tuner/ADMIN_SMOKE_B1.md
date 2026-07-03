# B1 — Admin-Smoke-Checkliste (system_tuner Apply-Pfad)

> Gate-Item 1 zum Scharfschalten (`APPLY_ENABLED=True`). Validiert den vollen
> Happy-Path mit ECHTEN Systemeingriffen. Smoke-Tweak: **TW-TEL-001** (T1_safe,
> kein Reboot, reversibler HKLM-Write `…\DataCollection\AllowTelemetry=1`).
>
> **Warum nicht autonom durch Claude:** Der Apply braucht Elevation (UAC-Consent
> auf dem Secure Desktop — nicht per pywinauto/MCP klickbar) und — fuer den
> *vollstaendig* faithful Lauf — ein **frozen Build in `%ProgramFiles%`**
> (sonst `assess_install_path_trust`=False -> A3-Reject, ausser man umgeht es mit
> `--allow-untrusted-path`, was genau die DACL-/Trusted-Path-Pruefung entwertet,
> die dieser Smoke beweisen soll). Claude liefert die Checkliste; den einen
> UAC-Klick macht Patrick.

## Voraussetzung (einmalig, danach zuruecknehmen)
`APPLY_ENABLED` ist die autoritative Sperre. Fuer den Smoke EINE Zeile umlegen:

- Datei `tools/system_tuner/application/elevated_apply.py:45`
- `APPLY_ENABLED = False` -> `APPLY_ENABLED = True`
- **Nach dem Smoke zwingend zurueck auf `False`** (vor jedem Commit/Push).

## Zwei Varianten

### A) Dev-Mode-Funktionssmoke (jetzt machbar, 1 UAC-Klick)
Validiert: echte Elevation, echter HKLM-Write, `Checkpoint-Computer`,
admin-only `%ProgramData%\NoRisk`-DACL, Snapshot, Verify-Readback, Revert.
NICHT validiert: Trusted-Path-Enforcement des Laufzeit-Images (Dev-venv ist
user-schreibbar) — dafuer Variante B.

1. NoRisk im Dev-Mode als **Admin** starten (UAC-Prompt bestaetigen):
   `set NORISK_SYSTEM_TUNER_DEV=1` und die App elevated starten.
2. Login, Tool **„System optimieren"** oeffnen (Pro/Enterprise-Edition noetig).
3. Nutzungshinweis (EULA v1.1) **zustimmen** (ConsentGate).
4. **NUR** TW-TEL-001 auswaehlen -> **„Anwenden"**.
5. Vorher/Nachher pruefen (PowerShell, elevated) — s. „Verify-Befehle".
6. **„Meine Aenderungen zuruecknehmen"** -> Revert.
7. App schliessen, `APPLY_ENABLED` zurueck auf `False`.

### B) Faithful Release-Smoke (Gate-erfuellend)
Wie A, aber gegen den **frozen Build in `%ProgramFiles%\NoRisk`** und OHNE
`NORISK_SYSTEM_TUNER_DEV` / Override-Flags (A3 Trusted-Path greift dann echt).
Haengt am Release-Build (vgl. T-359). Das ist der Lauf, der die Security-Sign-off-
Zeile (B0) zeichnet.

## Verify-Befehle (je Gate-Punkt)

| Gate | Befehl (elevated PowerShell) | Erwartung |
|---|---|---|
| HKLM-Write gesetzt | `reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry` | `AllowTelemetry … 0x1` |
| Restore-Point | `Get-ComputerRestorePoint | Select-Object -Last 1` | frischer Punkt „NoRisk …" mit aktuellem Zeitstempel |
| Admin-only DACL | `icacls "%ProgramData%\NoRisk\secure_store"` | `SYSTEM:(…F)` + `Administratoren:(…F)`, Benutzer nur lesend (keine (W) fuer Users) |
| Snapshot persistiert | Datei `%ProgramData%\NoRisk\secure_store\…snapshots…db` existiert (SQLCipher) | vorhanden, > 0 Byte |
| Ergebnis-Marker (HMAC) | App zeigt „angewendet"; `result_<token>.json` kurz in der admin-only Ablage | GUI meldet Erfolg, kein Timeout |
| Revert | nach „Zuruecknehmen": `reg query … /v AllowTelemetry` | Wert **weg** (war vorher nicht gesetzt) bzw. auf Vorwert zurueck |

## Ergebnis-Protokoll (ausfuellen)
- [ ] UAC-Elevation ok (`is_admin` im elevated Prozess True)
- [ ] Restore-Point erstellt (Zeitstempel: __________)
- [ ] HKLM AllowTelemetry = 1 nach Apply
- [ ] `%ProgramData%\NoRisk` DACL: SYSTEM/Admins full, Users read-only
- [ ] Snapshot-DB geschrieben
- [ ] Ergebnis-Marker valid (kein 90s-Timeout)
- [ ] Revert: Wert sauber zurueckgenommen
- [ ] `APPLY_ENABLED` wieder `False`
- [ ] Variante (A Dev / B Frozen): __________  · Datum/Commit: __________
