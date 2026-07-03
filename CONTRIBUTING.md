# Contributing — NoRisk by FINLAI

Danke für dein Interesse an NoRisk! Beiträge sind willkommen — per Fork &
Pull Request. NoRisk steht unter der [GNU AGPL v3.0](LICENSE).

## Setup

**Wichtig:** Basis-Python muss **Standalone-Python von [python.org](https://www.python.org/downloads/)**
sein, **nicht Anaconda** — Anacondas `python.exe` lädt eine alte MSVC-Runtime
statisch, was beim PySide6-Import zu `WinError 127` (DLL-Konflikt) führt.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt

# Smoke-Test
.\.venv\Scripts\python apps\norisk_app.py --smoke-test
# Erwartung: Exit-Code 0, "[SMOKE-TEST OK] ..."
```

### Dev-Tools

`ruff` und `bandit` prüfen den Code. Empfohlen global via [`pipx`](https://pipx.pypa.io/):

```powershell
pipx install ruff
pipx install bandit
```

## Branch-Strategie

- `main` — produktiv, stabil.
- `feature/<thema>` — neue Features.
- `fix/<thema>` — Bugfixes.
- `refactor/<thema>` — Aufräumarbeiten ohne Feature-Änderung.
- `docs/<thema>` — reine Doku-Änderungen.

Vor dem Push:
- Tests grün: `pytest -x -q -m "not slow and not gui" --tb=short`
- Lint sauber: `ruff check .` und `bandit -r . -q`

## Commit-Stil

```
<typ>(<scope>): <kurze beschreibung>

Optionaler Body: Was/Warum, nicht Wie.
```

Typen: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `style`, `perf`, `security`.

Beispiele:
```
fix(password_checker): HIBP-Timeout von 5 s auf 10 s erhoeht
refactor(sidebar): Sidebar-Items aus deklarativer Config bauen
```

## Coding Rules

Die FINLAI-Regeln (R1–R12) gelten ausnahmslos:

- **R1** — Keine hardcodierten Konstanten (Farben, Modelle, URLs, Pfade, Magic Numbers/Strings).
- **R2** — Icons nur als Material Symbols.
- **R3** — Niemals stille Fehlerbehandlung (`except:` / `except Exception: pass`).
- **R4** — Datenbank nur über `EncryptedDatabase`, nie direkt `sqlite3`.
- **R5** — Hexagonale Schichten einhalten (siehe [ARCHITECTURE.md](ARCHITECTURE.md)).
- **R6** — Fonts nur Raleway / JetBrains Mono / Salaryman.
- **R7** — Secrets nie im Quellcode → `SecureStorage`.
- **R8** — Keine sensitiven Daten ins Logging.
- **R9** — Tests vor jedem Commit.
- **R10** — Keine versteckten `None`-Defaults für Dependencies.
- **R11** — White-Label-Konventionen (Akzentfarbe, Feature-Keys).
- **R12** — Keine hardcodierten UI-Inhalte (aus DB/Config laden).

## Tests

```powershell
pytest -x -q -m "not slow and not gui" --tb=short   # vor Push
pytest tests/ -q                                     # voll
```

## Fragen & Fehler

Bitte über GitHub Issues / Pull Requests. Für **Sicherheitslücken** gilt der
vertrauliche Meldeweg in [SECURITY.md](SECURITY.md).
