# NoRisk by FINLAI

**Lokale Cybersecurity-Suite für KMU** — On-Premise, 100 % lokal, ohne Cloud-Zwang.

NoRisk bündelt Schwachstellen-Scan, NIS2-Reifegrad-Bewertung, Netzwerk-Monitoring,
Patch- und Zertifikats-Überwachung, Lieferketten-/AVV-Tracking und mehr in einer
einzigen Desktop-Anwendung. Alle Daten bleiben verschlüsselt auf dem Gerät; die
KI-Unterstützung läuft lokal über Ollama.

> **Open Source (AGPLv3).** Entwickelt von [FINLAI designs](https://financial-analytics.eu),
> Linz / Österreich. Single-Tenant-Desktop-Edition — keine Lizenz-Aktivierung, kein
> Telemetrie-Zwang, alle Funktionen enthalten.

## Funktionsumfang (Auszug)

- **Sicherheits-Assessment & Scoring** — System-Scan, Härtungs-Empfehlungen, Security-Score
- **NIS2** — Reifegrad-Bewertung, Vorfalls-Erfassung & Meldekette
- **Netzwerk** — Netzwerk-Scanner + kontinuierliches Netzwerk-Monitoring (ETW-Collector)
- **Patch- & Zertifikats-Monitor**, **Dependency-/CSAF-Advisory-Auditor**
- **Lieferketten-Monitor** inkl. AVV-/Art.-28-DSGVO-Tracking
- **Awareness-Tracker**, **Passwort-Leak-Check** (Have I Been Pwned, k-Anonymität)
- **Datei-Scanner** (E-Mail / PDF / Dokumente), **API-Security-Checks**
- **Kunden-Audit** & **Cyber-Lagebild** (öffentliche Bedrohungs-Feeds)

## Stack

- Python 3.12+ / PySide6 (Qt 6)
- SQLCipher — verschlüsselte lokale Datenbanken (`core.database.encrypted_db`)
- Ollama — lokaler KI-Assistent, 100 % on-device (kein Cloud-Schlüssel nötig)

## KI-Assistent lokal einrichten (Ollama)

Der eingebaute KI-Assistent läuft **vollständig lokal** über [Ollama](https://ollama.com) —
es verlässt kein Text das Gerät, und es ist kein Cloud-Schlüssel nötig.

1. **Ollama installieren:** [ollama.com/download](https://ollama.com/download) (Windows / macOS / Linux).
2. **Modell laden** (einmalig, in der Kommandozeile):
   ```bash
   ollama pull llama3.2
   ```
3. Ollama läuft danach im Hintergrund unter `http://localhost:11434`; NoRisk verbindet
   sich automatisch. Ein anderes Modell oder einen anderen Host stellen Sie über `.env`
   (`OLLAMA_DEFAULT_MODEL`, `OLLAMA_BASE_URL`) oder in den App-Einstellungen ein.

## Optionale API-Schlüssel

NoRisk funktioniert **ohne jeden Schlüssel**. Für einzelne Zusatz-Funktionen können Sie
kostenlose Schlüssel hinterlegen — in der App unter **Einstellungen → API-Schlüssel**
oder über `.env` (siehe [`.env.example`](.env.example)):

| Dienst | Wofür | Schlüssel (kostenlos) |
|---|---|---|
| **NVD** (National Vulnerability Database) | schnellere / häufigere CVE-Abfragen | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |
| **VirusTotal** | Datei-Hash-Abgleich im Datei-Scanner | [virustotal.com → API-Key](https://www.virustotal.com/gui/my-apikey) |
| **Have I Been Pwned** | Breach-Check im Passwort-Prüfer | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |

Ohne Schlüssel bleiben nur diese einzelnen Funktionen deaktiviert bzw. laufen mit
Standard-Rate-Limits — alle übrigen Funktionen sind uneingeschränkt nutzbar.

## Schnellstart (Entwicklung)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Windows (PowerShell)
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python apps\norisk_app.py           # App starten
```

## Build (Windows)

```powershell
.\.venv\Scripts\Activate.ps1
pyinstaller build_specs/build_norisk.spec --clean --noconfirm
```

Ausgabe: `dist/norisk/norisk.exe` (plus headless `norisk-collector.exe`).

## Tests

```powershell
pytest -q -m "not slow and not gui"     # schnelles Gate
pytest tests/ -q                        # vollständig
```

## Smoke-Test

```powershell
.\.venv\Scripts\python apps\norisk_app.py --smoke-test   # erwartet Exit 0
```

## Architektur

Hexagonal: `apps/` → `core/` → `tools/`, keine Cross-Tool-Importe.
Siehe [ARCHITECTURE.md](ARCHITECTURE.md).

## Mitwirken & Sicherheit

- Beiträge: [CONTRIBUTING.md](CONTRIBUTING.md)
- Sicherheitslücken vertraulich melden: [SECURITY.md](SECURITY.md)
- Drittanbieter-Lizenzen: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- Änderungshistorie: [CHANGELOG.md](CHANGELOG.md)

## Lizenz

**GNU Affero General Public License v3.0 (`AGPL-3.0-or-later`)** — siehe [LICENSE](LICENSE).

Copyright © 2026 Patrick Riederich / FINLAI designs (financial-analytics.eu).

NoRisk ist freie Software: Sie dürfen es unter den Bedingungen der AGPLv3 weitergeben
und/oder verändern. Es wird OHNE JEDE GEWÄHRLEISTUNG bereitgestellt, soweit gesetzlich
zulässig.
