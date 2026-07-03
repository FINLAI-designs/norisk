# ARCHITECTURE.md — FINLAI Hexagonale Architektur

> **Rolle:** Single Source of Truth für das Architektur-Modell.
> Verbindliche Strukturregeln — wird zuerst gelesen, wenn man wissen will,
> wie FINLAI gebaut ist.
> **Lies vorher:** Keine Voraussetzung — kann als Erstes gelesen werden.

## Verbindliche Architektur
> Diese Datei beschreibt die verbindliche Architektur für FINLAI.
> Jeder neue Code MUSS diesen Prinzipien folgen.
> Bei Widersprüchen zwischen Komfort und Architektur: **Architektur gewinnt.**

---

## 1. Was ist Hexagonale Architektur?

Die hexagonale Architektur (auch "Ports & Adapters" genannt) trennt den
Geschäftskern einer Anwendung vollständig von der Außenwelt. Der Kern
kennt keine GUI, keine Datenbank, keine Frameworks — er enthält nur
reine Geschäftslogik.

```
╔══════════════════════════════════════════════════════════╗
║ ÄUSSERE WELT ║
║ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ ║
║ │ PySide6 │ │ SQLite │ │ CSV / Excel │ ║
║ │ GUI │ │ DB │ │ Dateisystem │ ║
║ └────┬─────┘ └────┬─────┘ └────────┬─────────┘ ║
║ │ │ │ ║
║ ╔════╧══════════════╧══════════════════╧════════════╗ ║
║ ║ ADAPTER-SCHICHT ║ ║
║ ║ gui/ data/ shared/ ║ ║
║ ║ (primär) (sekundär) (Hilfsmittel) ║ ║
║ ╚════╤══════════════╤══════════════════╤════════════╝ ║
║ │ │ │ ║
║ ╔════╧══════════════╧══════════════════╧════════════╗ ║
║ ║ PORT-SCHICHT ║ ║
║ ║ application/ ║ ║
║ ║ (Services / Use Cases) ║ ║
║ ╚════╤══════════════════════════════════════════════╝ ║
║ │ ║
║ ╔════╧══════════════════════════════════════════════╗ ║
║ ║ KERN / DOMAIN ║ ║
║ ║ domain/ ║ ║
║ ║ Models · Entities · Interfaces · Regeln ║ ║
║ ║ !! KEINE Abhängigkeiten nach außen !! ║ ║
║ ╚═══════════════════════════════════════════════════╝ ║
╚══════════════════════════════════════════════════════════╝
```

---

## 2. Die drei Schichten in FINLAI

### Schicht 1: DOMAIN (Kern)
**Ordner:** `tools/<tool>/domain/`

Der unveränderliche Kern. Enthält ausschließlich:
- Datenklassen (`@dataclass`) und Entitäten
- Geschäftsregeln und Validierungslogik
- Abstrakte Interfaces (Ports)
- Berechnungslogik ohne Seiteneffekte

**Erlaubte Imports:** nur Python-Standardbibliothek (`dataclasses`, `abc`, `typing`, `re`, `math`)

**Verboten:**
- PySide6, pandas, SQLite, openpyxl
- Imports aus `application/`, `data/`, `gui/`
- Dateioperationen, Netzwerk, Logging

```python
# ✅ KORREKT — domain/models.py
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class InvoiceRecord:
    date: str
    invoice: str
    gross: float
    tax: float
    lines: int
    accounts: dict = field(default_factory=dict)
    stc: set = field(default_factory=set)
    perc: set = field(default_factory=set)

# ❌ FALSCH — domain darf das NICHT
import pandas as pd # Externes Framework
from PySide6.QtWidgets import... # GUI
from data.repository import... # Adapter
```

---

### Schicht 2: APPLICATION (Ports / Use Cases)
**Ordner:** `tools/<tool>/application/`

Orchestriert den Ablauf. Enthält:
- Service-Klassen die Use Cases implementieren
- Koordination zwischen Domain-Objekten
- Keine GUI-Logik, keine direkten DB-Aufrufe
- Definiert Interfaces die von `data/` implementiert werden

**Erlaubte Imports:**
- `domain/` (immer erlaubt)
- Python-Standardbibliothek
- `core/logger.py` (für Logging)
- Abstrakte Interfaces aus `domain/`

**Verboten:**
- PySide6 (keine GUI-Abhängigkeit!)
- Direkte SQL-Aufrufe
- Direkte Dateioperationen (über Interfaces abstrahieren)

```python
# ✅ KORREKT — application/password_service.py
from tools.password_checker.domain.models import PasswordCheckResult
from core.logger import get_logger

class PasswordService:
    def __init__(self, hibp_client=None):
        self._log = get_logger(__name__)
        self._hibp = hibp_client

    def pruefen(self, passwort: str,
                mit_breach_check: bool = False) -> PasswordCheckResult:
        # Reine Logik — kein GUI, keine DB
...

# ❌ FALSCH — application darf das NICHT
from PySide6.QtWidgets import QMessageBox # GUI in Service!
import sqlite3 # Direkte DB in Service!
```

---

### Schicht 3: ADAPTER (Außenwelt)
**Ordner:** `tools/<tool>/gui/` und `tools/<tool>/data/`

Verbindet den Kern mit der Außenwelt. Zwei Typen:

#### Primäre Adapter: `gui/`
- PySide6 Widgets, Tabs, Dialoge
- Nimmt User-Input entgegen
- Ruft Application-Services auf
- Zeigt Ergebnisse an
- NIEMALS Geschäftslogik hier!

#### Sekundäre Adapter: `data/`
- Implementiert Interfaces aus `domain/`
- Datenbankzugriffe (SQLite)
- Datei-Imports (CSV, Excel)
- Datei-Exporte (PDF, Excel, ZIP)

```python
# ✅ KORREKT — gui/password_checker_widget.py
from tools.password_checker.application.password_service import PasswordService

class PasswordCheckerWidget(QWidget):
    def _on_check_clicked(self):
        # Adapter ruft Service auf — keine Logik hier
        service = PasswordService
        result = service.pruefen(self._input.text, mit_breach_check=True)
        self._result_panel.display(result)

# ❌ FALSCH — Geschäftslogik im GUI-Adapter
class PasswordCheckerWidget(QWidget):
    def _on_check_clicked(self):
        # Stärke-Berechnung direkt im Widget — VERBOTEN!
        passwort = self._input.text
        if len(passwort) < 8 or not any(c.isdigit for c in passwort):
            self._lbl.setText("Schwach")
...
```

---

## 3. Ordnerstruktur je Tool

Jedes Tool in `tools/<toolname>/` folgt exakt dieser Struktur:

```
tools/
└── <toolname>/
    ├── __init__.py
    ├── tool.py ← Tool-Registrierung (BaseTool)
    │
    ├── domain/ ← KERN (keine Außen-Abhängigkeiten)
    │ ├── __init__.py
    │ ├── models.py ← Dataclasses, Entitäten
    │ ├── interfaces.py ← Abstrakte Ports (ABC)
    │ └── <logik>.py ← Reine Berechnungslogik
    │
    ├── application/ ← USE CASES (orchestriert Domain)
    │ ├── __init__.py
    │ └── <name>_service.py ← Service-Klassen
    │
    ├── data/ ← SEKUNDÄRE ADAPTER (DB, Dateien)
    │ ├── __init__.py
    │ ├── <name>_repository.py ← DB-Zugriff
    │ └── <name>_importer.py ← Datei-Import/Export
    │
    └── gui/ ← PRIMÄRE ADAPTER (PySide6)
        ├── __init__.py
        ├── <tool>_widget.py ← Haupt-Widget mit Tabs
        ├── delegates/ ← QDelegate Implementierungen
        ├── models/ ← QAbstractTableModel
        └── pages/ ← Tab-Widgets (einzelne Seiten)
```

### Ausnahme: Tools mit headless-Einstiegspunkt (Collector) — Lazy Paket-Re-Export

Das Paket-`__init__.py` eines Tools re-exportiert normalerweise **eager** sein
`XTool` (`from.tool import XTool`). **Ausnahme:** Hat ein Tool einen eigenen
**GUI-losen Einstiegspunkt** (z. B. der ETW-Collector `apps/collector_main.py`
für `network_monitor`), MUSS sein `__init__.py` das `XTool` **lazy** via
PEP 562 `__getattr__` re-exportieren. Sonst zieht schon der Import eines
beliebigen `data`-/`application`-Submoduls über das eager Re-Export die ganze
Qt/PySide6-Kette herein (`.tool` → `core.base_tool` → `PySide6.QtWidgets`) — die
headless-Exe müsste dann ganz Qt bündeln (unnötig groß, größere Angriffsfläche).

> **Nicht zurück auf eager vereinheitlichen.** Ein „Aufräum"-Commit, der
> `network_monitor/__init__.py` auf das eager Muster zurücksetzt, bricht still
> den Qt-freien Collector-Build F-C). Regressionsschutz:
> `tests/test_network_monitor_qt_decoupling.py`.

---

## 4. Abhängigkeitsregeln (Dependency Rule)

> **Die goldene Regel:** Abhängigkeiten zeigen IMMER nach innen — niemals nach außen.

```
gui/ → darf importieren: application/, domain/, core/
data/ → darf importieren: domain/, core/
application/ → darf importieren: domain/, data/, core/
domain/ → darf importieren: NUR Python-Stdlib

VERBOTEN:
domain/ → application/, data/, gui/ ❌
application/ → gui/ ❌
data/ → gui/, application/ ❌
```

> **application → data ist ERLAUBT** (FINLAI-Konvention, erzwungen durch
> `import-linter`/pyproject; verbotene Pfeile sind nur `gui→data`, `application→gui`,
> `data→application/gui`, `domain→aussen`). Ein Service darf ein Repository
> konstruieren oder eine `data/`-Funktion aufrufen. **Aber:** Raw-SQL/`sqlite3`
> bleibt in `application/` verboten (→ Anti-Pattern 3) — das gehört in den
> `data/`-Adapter. Für Austauschbarkeit/Testbarkeit bleibt das **Ports-Muster**
> (Domain-Interface injizieren) empfohlen; der direkte `data/`-Import ist die
> pragmatisch erlaubte Abkürzung für die Default-Konstruktion.

### Abhängigkeitsmatrix

| Von \ Nach | domain | application | data | gui | core |
|--------------|--------|-------------|------|-----|------|
| **domain** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **application** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **data** | ✅ | ❌ | ✅ | ❌ | ✅ |
| **gui** | ✅ | ✅ | ❌ | ✅ | ✅ |
| **core** | ✅ | ❌ | ❌ | ❌ | ✅ |

> **Pädagogische Tiefe:** Eine ausführliche Erklärung der vier Schichten
> mit Bäckerei-Analogie, Schritt-für-Schritt-Szenario und vollständigem
> Beispiel-Tool findest du unter
> [docs/internal/architektur-leitfaden.md](docs/internal/architektur-leitfaden.md)
> Teil 1.3 (Schichten) und Teil 2 (`cert_monitor` als Muster).

---

## 5. core/ — Plattform-Kern

Der `core/` Ordner enthält plattformweite Infrastruktur:

```
core/
├── base_tool.py ← Abstrakte Basis für alle Tools
├── tool_registry.py ← Plugin-Registrierung
├── main_window.py ← Hauptfenster mit Sidebar
├── sidebar.py ← Sidebar mit Coming-Soon-Support
├── theme.py ← Dark-Only Theme, ThemeColors, DARK_ACCENT-Konstanten
├── fonts.py ← Font-Verwaltung
├── version.py ← __version__, __build_date__, get_version_info — einzige Quelle
├── updater.py ← Auto-Updater (kein PySide6 — testbar ohne GUI)
├── updater_dialog.py ← UpdateDialog + start_background_check — Qt-Wrapper
├── link_profile_loader.py ← JSON-basierte Link-Profile (dev + frozen Mode)
├── llm/ ← Multi-Provider LLM-System
│ ├── llm_base.py ← AbstractLLMProvider (Port)
│ ├── llm_config.py ← LLMProviderConfig
│ ├── llm_factory.py ← LLMFactory
│ ├── llm_result.py ← LLMResult + LLMMessage
│ ├── ollama_provider.py
│ ├── openai_provider.py
│ └── anthropic_provider.py
├── ocr/ ← Abstraktes OCR-System
│ ├── ocr_base.py ← AbstractOCR (Port)
│ ├── ocr_result.py ← OCRResult
│ ├── ocr_factory.py ← OCRFactory
│ ├── ollama_vision.py
│ └── chandra_ocr.py
├── logger.py ← Zentrales Logging (get_logger)
├── license_validator.py ← Lizenzprüfung
├── hardware_fingerprint.py← Hardware-ID
├── audit_log.py ← Audit-Logging
├── gdpr.py ← DSGVO-Einwilligung
├── beta_mode.py ← NoRisk-Beta-Bypass (befristet bis 15.05.2026)
├── auth/ ← Login, Session, User-Management
│ ├── models.py
│ ├── user_store.py
│ ├── session.py
│ ├── login_window.py
│ ├── admin_panel.py
│ ├── recovery_code.py ← 16-stelliger Code, bcrypt Cost 12 (ab 20.04.2026)
│ ├── password_reset.py ← Reset-Flow via Recovery-Code (ab 20.04.2026)
│ └── forgot_password_dialog.py ← GUI für Reset (ab 20.04.2026)
├── first_run_wizard/ ← Erstinstallations-Wizard (ab 20.04.2026)
│ ├── wizard.py ← QDialog + QStackedWidget
│ ├── trigger.py ← should_run_first_run_wizard
│ └── pages/
│ ├── base_page.py
│ ├── welcome_page.py
│ ├── company_info_page.py (Skelett)
│ ├── admin_setup_page.py
│ ├── backup_location_page.py (Skelett)
│ ├── two_factor_page.py (Skelett)
│ ├── recovery_code_page.py
│ └── completion_page.py
└── widgets/
    └── welcome_toast.py ← Nicht-modales Onboarding-Toast (ab 20.04.2026)
```

**Regel:** `core/` ist framework-agnostisch wo möglich.
`core/logger.py`, `core/audit_log.py`, `core/license_validator.py`, `core/updater.py`, `core/beta_mode.py`, `core/auth/recovery_code.py`, `core/auth/password_reset.py`
dürfen KEIN PySide6 importieren.

**Startup-Dialog-Kette:** `apps/__init__.py` orchestriert seit 20.04.2026 sequenziell:

```
GDPR-Dialog → First-Run-Wizard (wenn users.json fehlt) → LoginWindow → MainWindow
     (exec) (exec, optional) (exec) (show)
```

Der Wizard läuft mit `exec` statt `show`, damit Z-Order-Konflikte auf Windows 11 ausgeschlossen sind (3c0d522).

**Tool-DB ohne Legacy-Fallback:** `core/database/encrypted_db.py` akzeptiert keinen impliziten Fallback mehr über `DbContext.app_id` — jedes Tool übergibt den DB-Namen explizit (`EncryptedDatabase("mein_tool")`).

### Exception-Hierarchie (R-Exc-Sprint)

`core/exceptions.py` ist die zentrale Exception-Wurzel. Statt nackter
`raise RuntimeError` / `raise ValueError` muss Production-Code
Subklassen aus dieser Hierarchie nutzen, plus `raise X from err` (B904)
fuer Exception-Chaining.

```
FinLaiError — Wurzel, erbt von Exception
├── ConfigurationError — Settings, ENV-Vars
├── ValidationError — Input/Schema/Format
├── StorageError — DB- und FS-Operationen
│ ├── DatabaseError — SQLCipher-spezifisch
│ └── FileSystemError — IO ohne DB
├── NetworkError — HTTP/API/Timeout (NICHT Subprocess)
├── CryptoError — Keys/Signaturen/Encryption
├── LicenseError — License-Validierung/Activation
├── AuthError — Login/Session/Permissions
└── ExternalToolError — Subprocess (winget, wmic, PowerShell)
```

**Tool-spezifische Subklassen** leben in
`tools/<toolname>/domain/exceptions.py` und erben von der passenden
Kategorie (z. B. `class CertParseError(ValidationError)` in
`tools/cert_monitor/domain/exceptions.py`).

**Mehrfach-Vererbung mit Stdlib-Exceptions** Phase-1-Anpassung
2026-05-07): die Subklassen erben zusaetzlich von Stdlib-Klassen damit
existierender `except ValueError`-/`except RuntimeError`-/`except OSError`-
Code waehrend der Migration nicht bricht. Pattern bestaetigt durch
`requests.HTTPError` (extends both `IOError` und `RequestException`).
`FinLaiError` selbst bleibt sauber (nur `Exception`) — der semantische
Schnitt "FINLAI-Problem vs. Bug" lebt im `except FinLaiError`-Catchment.

| Subklasse | Stdlib-Mehrfach-Erbe |
|---|---|
| `ConfigurationError` | `RuntimeError` |
| `ValidationError` | `ValueError` |
| `StorageError` | `OSError` |
| `DatabaseError` / `FileSystemError` | `OSError` (transitiv via Storage) |
| `NetworkError` | `OSError` (Pattern wie `ConnectionError`) |
| `CryptoError` | `RuntimeError` |
| `LicenseError` | `RuntimeError` |
| `AuthError` | `RuntimeError` |
| `ExternalToolError` | `RuntimeError` |

**Migrations-Heuristik** fuer den R-Exc-Sprint:

| Pattern | Neue Klasse |
|---|---|
| `RuntimeError("X nicht verfuegbar")` (HTTP/API) | `NetworkError` |
| `RuntimeError("X nicht verfuegbar")` (Subprocess) | `ExternalToolError` |
| `RuntimeError("X nicht verfuegbar")` (Datei/DB) | `StorageError` |
| `RuntimeError("Settings X fehlt")` | `ConfigurationError` |
| `ValueError` aus User-Input-Pruefung | `ValidationError` |
| `RuntimeError` aus Crypto-Modul | `CryptoError` |

---

## 6. Konkretes Beispiel: Neues Feature implementieren

### Szenario: "Fuzzy-Matching Schwellwert konfigurierbar machen"

**Schritt 1 — Domain anpassen:**
```python
# domain/models.py
@dataclass
class BenchmarkConfig:
    tolerance: float = 0.01
    max_levenshtein: int = 2
    ignore_case: bool = True
```

**Schritt 2 — Application anpassen:**
```python
# application/benchmark_service.py
def compare_invoices(self, dict_real, dict_ocr,
                     label, config: BenchmarkConfig) ->...:
    # Config aus Domain verwenden
    if dist <= config.max_levenshtein:
...
```

**Schritt 3 — GUI anpassen:**
```python
# gui/pages/compare_tab.py
config = BenchmarkConfig(
    tolerance=self._tolerance_spin.value,
    max_levenshtein=self._lev_spin.value
)
lines, stats = self._service.compare_invoices(
    dict_real, dict_ocr, label, config
)
```

✅ GUI kennt Config-Dataclass aus Domain
✅ Service verwendet Config ohne GUI-Wissen
✅ Domain definiert Config ohne Außen-Abhängigkeiten

---

## 7. Anti-Patterns — Was NIEMALS getan werden darf

### ❌ Anti-Pattern 1: Fat GUI
```python
# VERBOTEN — Geschäftslogik im Widget
class ResultTab(QWidget):
    def calculate_error_rate(self, diffs):
        # Berechnung gehört in application/!
        base = sum(len(inv.accounts) + 3
                   for pid in diffs.values
                   for inv in pid.values)
        return len(diffs) / base * 100
```

### ❌ Anti-Pattern 2: Domain mit Framework-Abhängigkeit
```python
# VERBOTEN — pandas in domain/
import pandas as pd # ❌ Framework in Domain!

@dataclass
class InvoiceRecord:
    df: pd.DataFrame # ❌ Framework-Typ in Domain!
```

### ❌ Anti-Pattern 3: Direkte DB-Aufrufe in Services
```python
# VERBOTEN — SQL direkt in application/
class BenchmarkService:
    def save_result(self, stats):
        import sqlite3 # ❌ DB direkt in Service!
        conn = sqlite3.connect("results.db")
        conn.execute("INSERT INTO...")
```

### ❌ Anti-Pattern 4: Zirkuläre Imports
```python
# VERBOTEN — data/ importiert aus application/
# data/repository.py
from tools.password_checker.application.password_service import... # ❌
```

### ✅ Korrekte Alternative zu Anti-Pattern 3:
```python
# domain/interfaces.py — Interface definieren
from abc import ABC, abstractmethod

class IBenchmarkRepository(ABC):
    @abstractmethod
    def save_result(self, stats: DiffStat) -> None:...

# application/benchmark_service.py — Interface verwenden
class BenchmarkService:
    def __init__(self, repo: IBenchmarkRepository):
        self._repo = repo # ✅ Abhängigkeit injiziert

# data/benchmark_repository.py — Interface implementieren
class SQLiteBenchmarkRepository(IBenchmarkRepository):
    def save_result(self, stats: DiffStat) -> None:
        import sqlite3 # ✅ DB nur im Adapter
...
```

---

## 8. Checkliste bei neuem Code

Vor jedem Commit diese Fragen prüfen:

**Domain-Schicht:**
- [] Importiert `domain/` nur Python-Stdlib?
- [] Sind alle Datenklassen in `domain/models.py`?
- [] Enthält `domain/` keine Seiteneffekte?

**Application-Schicht:**
- [] Importiert `application/` kein PySide6?
- [] Enthält `application/` keine SQL-Aufrufe?
- [] Gibt jede Service-Methode einen Wert zurück (kein GUI-State)?

**GUI-Schicht:**
- [] Enthält `gui/` keine Berechnungslogik?
- [] Ruft `gui/` nur `application/`-Services auf?
- [] Sind Widgets zustandslos (State in Service, nicht Widget)?

**Allgemein:**
- [] Zeigen alle Imports nach innen (nie nach außen)?
- [] Gibt es keine zirkulären Imports?
- [] Hat jede neue Datei einen Docstring?
- [] Gibt es Tests für neue `domain/`- und `application/`-Logik?

---

## 9. Warum Hexagonale Architektur für FINLAI?

| Vorteil | Bedeutung für FINLAI |
|---------|----------------------|
| **Testbarkeit** | `domain/` und `application/` ohne GUI testbar → pytest funktioniert ohne PySide6 |
| **Austauschbarkeit** | GUI von PySide6 auf Web austauschbar ohne Domain-Änderungen |
| **Erweiterbarkeit** | Neues Tool = neuer Ordner, bestehende Tools unberührt |
| **Sicherheit** | Sensitive Logik in `domain/` ist von GUI-Vulnerabilities isoliert |
| **Wartbarkeit** | Klare Grenzen → man ändert nie versehentlich die falsche Schicht |

---

## 10. Projekt-Struktur

NoRisk ist eine eigenstaendige Desktop-App. `apps/norisk_app.py` ist der
Einstiegspunkt und ruft den generischen Launcher `launch_app`
(`apps/__init__.py`) mit `NORISK_CONFIG` (`apps/app_config.py`) auf. `AppConfig`
steuert die registrierten Tools, sichtbaren Sidebar-Gruppen, Fenstertitel und
Akzentfarbe.

```
apps/
  norisk_app.py — Entry Point
  app_config.py — AppConfig + NORISK_CONFIG
  __init__.py — launch_app + Smoke-Test
core/ — geteilte Plattform (DB, Theme, Auth, LLM, Widgets, Security)
tools/<tool>/ — je Tool: domain/ application/ data/ gui/
build_specs/
  build_norisk.spec — PyInstaller-Spec
```

### Smoke-Test

```bash
python apps/norisk_app.py --smoke-test
```

Importiert alle Tool-Module ohne GUI zu starten. Exit-Code 0 = OK, 1 = Fehler.

---

## 11. Auto-Updater-Architektur (ab Version 1.4)

> **Renumberiert:** Der ehemalige Abschnitt 11 (White-Label-Architektur) wurde am 2026-04-27 entfernt — White-Label ist im norisk-Einzelrepo nicht aktiv. Der frühere Abschnitt 12 (Auto-Updater) ist jetzt Abschnitt 11.

### Schichtenzugehörigkeit

```
core/updater.py ← Kein PySide6. Testbar ohne GUI. Enthält:
                            check_for_update(app_id, channel) → UpdateInfo | None
                            download_update(url, sha256, progress_cb) → Path
                            apply_update(exe_path) → None (startet neue EXE + sys.exit)

core/updater_dialog.py ← PySide6. Qt-Wrapper. Enthält:
                            start_background_check(window, config) → None
                            UpdateDialog (Modal-Dialog: Version, Release-Notes, Download)
```

### Server-Protokoll

**Check-Endpunkt (GET):**
```
https://api.financial-analytics.eu/updates/{app_id}/{channel}/latest.json
```

**Response-Format:**
```json
{
  "version": "1.1.0",
  "channel": "stable",
  "url": "https://api.financial-analytics.eu/releases/finlai/FINLAI_v1.1.0.exe",
  "sha256": "abc123...",
  "release_notes": "Bugfixes und Verbesserungen",
  "min_version": "1.0.0"
}
```

**SemVer-Vergleich:** Neue Version wird nur angeboten wenn `remote.version > local.__version__`.

### Sicherheitsgarantien (STRIDE)

| Bedrohung | Gegenmaßnahme |
|-----------|---------------|
| Spoofing | TLS mit CA-Verifikation (`verify=True`) |
| Tampering | SHA-256-Prüfsumme des Downloads |
| DoS | 5-Sekunden-Timeout für Check-Request |
| EoP | EXE wird als normaler User-Prozess gestartet |

### Deployment-Workflow

> **Hinweis:** Die `deploy/`-Server-Infrastruktur (publish_update.sh & co.) liegt **nicht** im norisk-Einzelrepo, sondern wird zentral im FINLAI-Monorepo gepflegt. Der folgende Workflow beschreibt den Monorepo-Stand:

```
Entwicklung
  → python build.py
  → dist/NORISK_v1.1.0.exe
  → bash deploy/publish_update.sh --channel staging... (Monorepo)
  → Test auf Staging-Kanal
  → bash deploy/publish_update.sh --channel stable... (mit Bestätigung "ja")
  → Git-Tag: git tag v1.1.0 && git push origin v1.1.0
```

---

## 12. Versionierung dieser Datei

| Version | Datum | Änderung |
|---------|------------|---------------------------------|
| 1.0 | 2026-03-19 | Initiale Architektur-Definition |
| 1.1 | 2026-04-01 | Zuletzt geprüft — keine Architektur-Änderungen; network_scanner folgt identischem Hexagonal-Pattern |
| 1.2 | 2026-04-02 | 3-App-Split dokumentiert (heute Abschnitt 10) |
| 1.3 | 2026-04-10 | 4-App-Split: TeachMe hinzugefügt; core/llm/ + core/ocr/ in Abschnitt 5 dokumentiert |
| 1.4 | 2026-04-12 | White-Label-Architektur, Auto-Updater, core/ um version.py / updater.py / link_profile_loader.py erweitert |
| 1.5 | 2026-04-21 | `core/first_run_wizard/`, `core/auth/recovery_code.py` + `password_reset.py` + `forgot_password_dialog.py`, `core/beta_mode.py`, `core/widgets/welcome_toast.py`; Startup-Dialog-Kette dokumentiert; `EncryptedDatabase`-Legacy-Fallback entfernt; Techstack als eigenständiges Tool (`tools/techstack/`, Repository verbleibt bei `cyber_dashboard/data/`) |
| 1.6 | 2026-04-25 | `shared/`-Abschnitt entfernt (nie realisiert); FINLAI-Schreibweise durchgängig; Rollen-Header + Cross-Refs zu Lehr-/Coding-/UI-Doku; Abschnitte 7–14 auf 6–13 renummeriert (Abschnitt 6 entfernt) |
| 1.7 | 2026-04-27 | norisk-Einzelrepo-Anpassung: ehemaliger Abschnitt 11 (White-Label) entfernt — White-Label nicht in norisk aktiv; `deploy/`-Server-Infrastruktur als monorepo-only markiert; Code-Beispiele auf `password_checker` umgestellt (statt `ocr_benchmark`, das nicht im norisk-Repo existiert); Smoke-Test auf nur `apps/norisk_app.py` reduziert |

**Autor:** Patrick Riederich
**Projekt:** FINLAI — Finance Analytics Artificial Intelligence
