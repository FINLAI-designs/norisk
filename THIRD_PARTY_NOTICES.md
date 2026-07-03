# Third-Party Notices — NoRisk by FINLAI

> **Zweck F-G).** Register der Dritt-Komponenten, die NoRisk bündelt oder
> als Bibliothek nutzt, mit ihrer Lizenz-Einordnung. Begleitet den fail-closed
> GPLv2-Sperrlisten-Build-Check (`license_compliance.py`), der verhindert, dass
> lizenz-inkompatible (GPLv2/Npcap) Komponenten in den kommerziellen Build geraten.
>
> **Rechtlicher Status:** Diese Übersicht ist eine technische Bestandsaufnahme,
> **keine** anwaltliche Lizenz-Freigabe. Die abschließende juristische Prüfung der
> Lizenzaussagen ist Teil des Release-Gates
> (siehe `NoRisk_WIRESHARK_STRATOSHARK_INTEGRATION.md`, „Anwaltliche Gesamt-Freigabe").
> Versionen: siehe `requirements.txt` (Single Source of Truth).

---

## 1. Qt / PySide6 — LGP.0 (wichtigster Fall)

NoRisk baut sein GUI auf **PySide6** („Qt for Python") auf. Die Qt-Bibliotheken und
PySide6 stehen unter der **GNU LGPL v3**. Die LGPL-Konformität des kommerziellen,
nicht quelloffenen NoRisk wird über folgende Maßnahmen gewahrt:

- **Dynamisches Linken / ersetzbare Bibliotheken.** Der Build ist ein
  **PyInstaller-Onedir-Bundle** (`dist/norisk/_internal/Qt6*.dll`,
  `PySide6/*.pyd`). Die Qt-DLLs liegen als **eigenständige, austauschbare**
  Dateien vor — der Endnutzer kann sie gegen eine eigene, kompatible Qt-Version
  derselben Major-Reihe ersetzen (LGPL-v3 §4). Es findet **kein statisches Linken**
  in die NoRisk-Exe statt.
- **Keine Modifikation** der Qt-/PySide6-Quellen.
- **Nur LGPL-Module.** Die GPL/kommerziellen Qt-Add-on-Module **Qt Charts** und
  **Qt Data Visualization** werden **nicht** genutzt und im Build **ausgeschlossen**
  (`build_norisk.spec`, `_COMMON_EXCLUDES`); das Live-Bandbreiten-Chart ist reiner
  `QPainter`-Code (`tools/network_monitor/gui/bandwidth_chart.py`). Ebenso
  ausgeschlossen: **QtWebEngine** (Chromium, ungenutzt).

Qt-Quelltext & LGPL-Lizenztext: <https://www.qt.io/licensing> ·
<https://doc.qt.io/qtforpython/licenses.html>

---

## 2. Gebündelte Laufzeit-Abhängigkeiten (permissive Lizenzen)

Alle folgenden Pakete stehen unter **permissiven** Lizenzen (MIT / BSD / Apache-2.0 /
ISC / PSF / Public Domain) und sind mit der kommerziellen Auslieferung vereinbar:

| Paket | Zweck | Lizenz (Einordnung) |
|---|---|---|
| qt-material-icons | Material-Symbols-Icons | Apache-2.0 |
| pyqtgraph | Plot-Widgets | MIT |
| numpy | numerische Basis | BSD-3-Clause |
| requests | HTTP-Client (gehärtet) | Apache-2.0 |
| httpx | HTTP-Client (Ollama/Web-Fetch) | BSD-3-Clause |
| ollama | lokaler LLM-Client | MIT |
| cryptography | Krypto-Primitive | Apache-2.0 / BSD |
| bcrypt | Passwort-Hashing | Apache-2.0 |
| sqlcipher3 / SQLCipher / SQLite | verschlüsselte DB | BSD-style / Public Domain |
| apsw | SQLCipher-Fallback-Bindung | OSI-permissiv (zlib-ähnlich) |
| packaging | Versions-/Marker-Logik | Apache-2.0 / BSD |
| psutil | Prozess-/Netz-Stats | BSD-3-Clause |
| pydantic / pydantic-settings | Validierung / Settings | MIT |
| pywin32 | Windows-DPAPI/COM | PSF |
| pywintrace | ETW-Subscriber (Windows) | Apache-2.0 |
| pypdf | PDF-Text-Extraktion | BSD-3-Clause |
| python-docx | DOCX-Reports | MIT |
| openpyxl | XLSX-Export | MIT |
| reportlab | PDF-Generierung | BSD-3-Clause |
| defusedxml | sichere XML-Parser | PSF |
| lxml | XSD-Parsing | BSD-3-Clause |
| magika | Dateityp-Erkennung | Apache-2.0 |
| oletools | Makro/DDE-Detection | BSD-2-Clause |
| yara-python / YARA | Pattern-Scanner | BSD-3-Clause / Apache-2.0 |
| dnspython | DNS-Lookup | ISC |
| jsonschema | JSON-Schema-Validierung | MIT |
| ijson | Streaming-JSON | BSD-3-Clause |
| ftfy | Unicode-Normalisierung | Apache-2.0 / MIT |
| extract-msg | Outlook-.msg-Parsing | BSD-3-Clause |
| feedparser | RSS/Atom | BSD-2-Clause |
| beautifulsoup4 | HTML-Parsing | MIT |
| ddgs | DuckDuckGo-Suche | MIT |
| scikit-learn | TF-IDF/Cosine | BSD-3-Clause |
| watchdog | Datei-Watcher | Apache-2.0 |

---

## 3. LGPL-Bibliotheken (dynamisch, ersetzbar)

| Paket | Zweck | Lizenz | Konformität |
|---|---|---|---|
| chardet | Zeichensatz-Erkennung | **LGP.1** | reines Python, unverändert, als eigenständiges Modul ersetzbar (LGPL §6 — dynamisch genutzt) |

> Hinweis: Für eine vollständig permissive Lieferkette ist `charset-normalizer`
> (MIT) ein drop-in-Kandidat als spätere Härtung — nicht release-blockierend.

---

## 4. PyInstaller-Bootloader

Die Exe enthält den **PyInstaller-Bootloader**. PyInstaller selbst steht unter
**GP.0 mit Ausnahme** (bootloader-exception): die mit dem Bootloader gebündelten
Anwendungen dürfen unter **beliebiger** Lizenz (auch proprietär) ausgeliefert werden.
PyInstaller ist ein **Build-Werkzeug** (in `requirements.txt`, nicht Teil des
NoRisk-Anwendungscodes).

---

## 5. Bewusst NICHT gebündelt (GPLv2/Npcap — fail-closed gesperrt)

Folgende Komponenten sind durch `license_compliance.py` **build-blockierend gesperrt**
und in keiner Form (Paket, Import, Spec, Bundle-DLL) enthalten:

- **Wireshark / tshark / libwireshark** (GPLv2)
- **pyshark** (GPLv2-Frontend zu tshark)
- **Stratoshark / libsinsp / Falco** (GPLv2)
- **Npcap / WinPcap** (proprietär/eingeschränkt, kein Redistribution-Recht im Default)
- **Qt Charts / Qt Data Visualization** (GPLv3/kommerziell)

NoRisk implementiert seine Netzwerk-Sicht **capture-frei** über die eigene
ETW-Pipeline (kein Paket-Capture, kein libpcap/Npcap) und vermeidet so jede
GPL-Kontamination — siehe `docs/THREAT_MODEL.md` und die Integrations-Roadmap.
