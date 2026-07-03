# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec für NoRisk by FINLAI — Weil Sicherheit kein Zufall ist.
#
# Aufruf (aus Repo-Root):
#   .venv\Scripts\pyinstaller.exe build_specs\build_norisk.spec --clean --noconfirm
#
# Ausgabe (Onedir, EIN geteilter Ordner mit ZWEI Exen, T-340 F-C-2):
#   dist/norisk/norisk.exe           — Haupt-App (PySide6-GUI)
#   dist/norisk/norisk-collector.exe — headless ETW-Collector (Qt-frei)
# Beide teilen sich das _internal/ (geteilte DLLs/PYZ-Binaries). Die geplante
# Aufgabe brennt norisk-collector.exe NEBEN norisk.exe ein (default_collector_action
# = Path(sys.executable).with_name("norisk-collector.exe")) → unter %ProgramFiles%
# installiert ist _MEIPASS damit admin-only (schließt Threat-Model R-25).

import glob
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(os.path.dirname(SPEC), ".."))

# ── GPLv2-Sperrlisten-Build-Check (T-340 F-G, FAIL-CLOSED) ───────────────────
# Bricht den Build ab, bevor PyInstaller etwas baut, falls eine GPL/Npcap-
# kontaminierende Komponente (pyshark/wireshark/tshark/stratoshark/Npcap/QtCharts)
# als installiertes Paket, Code-Import oder Spec-Bezug auftaucht. Schuetzt die
# Lizenz-Compliance des Builds (AGPLv3-Distribution). Der Bundle-Scan laeuft post-build
# (das _internal/ existiert hier noch nicht) ueber license_compliance.py --bundle.
sys.path.insert(0, ROOT)
from license_compliance import assert_build_compliant  # noqa: E402
assert_build_compliant(ROOT)

# qt_material_icons lädt Resource-Module dynamisch via importlib.
# Das Resource-Verzeichnis ist ein PEP-420-Namespace-Package (kein __init__.py),
# daher findet collect_submodules nur die Top-Level-Module. Wir enumerieren die
# Resource-Files explizit.
def _collect_qt_material_icons() -> list[str]:
    submodules = collect_submodules("qt_material_icons")
    import qt_material_icons
    resources_dir = os.path.join(os.path.dirname(qt_material_icons.__file__), "resources")
    for path in glob.glob(os.path.join(resources_dir, "icons_*.py")):
        name = os.path.splitext(os.path.basename(path))[0]
        submodules.append(f"qt_material_icons.resources.{name}")
    return submodules

_qt_material_icons_submodules = _collect_qt_material_icons()

# Excludes, die in BEIDEN Targets gelten (Schwester-App-Libs + QtWebEngine, das
# kein NoRisk-Tool nutzt). Zentral, damit Haupt-App und Collector nicht driften.
_COMMON_EXCLUDES = [
    # QtWebEngine — von keinem NoRisk-Tool genutzt
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PyQt6.QtWebEngineCore",
    "PyQt6.QtWebEngineWidgets",
    # Qt-Charts/DataVisualization — GPLv3/kommerziell (NICHT LGPL wie der Qt-Kern).
    # NoRisk nutzt sie nicht (bandwidth_chart = reiner QPainter); explizit
    # ausgeschlossen, damit ihre DLLs nie ins ausgelieferte Bundle geraten
    # (Belt-and-Suspenders zum license_compliance.py-Gate, T-340 F-G).
    "PySide6.QtCharts",
    "PySide6.QtDataVisualization",
    "PyQt6.QtCharts",
    "PyQt6.QtDataVisualization",
    # Finance (finLai)
    "neuralprophet",
    "openbb",
    # Robotic (AUTOMATE)
    "pyautogui",
    "pywinauto",
    "cv2",
    "mss",
    "pynput",
]

# Zusatz-Excludes NUR fuer den Collector: das gesamte Qt entfaellt (F-C-1 hat den
# network_monitor-Importgraphen Qt-entkoppelt; der headless Collector laedt kein
# PySide6 — siehe tests/test_network_monitor_qt_decoupling.py). Der explizite
# Voll-Ausschluss erzwingt das Decoupling: schliche sich je ein Qt-Import in den
# Collector-Pfad, bräche der unprivilegierte Exit-2-Smoke (ImportError statt 2).
_COLLECTOR_EXCLUDES = _COMMON_EXCLUDES + ["PySide6", "PyQt6", "shiboken6"]

# hiddenimports des Collectors (apps/collector_main.py). Sein network_monitor-
# Closure laeuft ueber das Lazy-PEP-562-__init__ (F-C-1) — ein __getattr__ kann
# PyInstaller statisch nicht folgen; die direkten Submodul-Importe findet die
# Bytecode-Analyse zwar selbst, die Liste ist bewusstes Belt-and-Suspenders.
# pywintrace exportiert sich als Paket ``etw`` (NICHT ``pywintrace``) — der
# Single-Point-of-Failure der ETW-Tiefe; alle Submodule explizit einsammeln.
_collector_hiddenimports = [
    "tools.network_monitor.data.dns_event_normalizer",
    "tools.network_monitor.data.etw_event_normalizer",
    "tools.network_monitor.data.process_path_tracker",
    "tools.network_monitor.data.etw_network_subscriber",
    "tools.network_monitor.data.dns_query_repository",
    "tools.network_monitor.data.process_traffic_repository",
    "tools.network_monitor.application.anomaly_detector",
    "tools.network_monitor.application.dns_query_aggregator",
    "tools.network_monitor.application.etw_traffic_aggregator",
    # DB/Crypto + Windows-Haertung (lazy in run_collector()/main() importiert).
    "core.database.encrypted_db",
    "core.database.key_manager",
    "core.win_security",
    "core.finlai_paths",
    "sqlcipher3",
    "argon2",
    "psutil",
] + collect_submodules("etw")

block_cipher = None

a = Analysis(
    [os.path.join(ROOT, "apps", "norisk_app.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        # Asset-Allowlist: nur Standard-Subfolder (fonts/icons/logo).
        # assets/customers/ wird bewusst NICHT inkludiert — Customer-Assets
        # gehören in Customer-Builds, nicht ins Standard-NoRisk-Bundle.
        (os.path.join(ROOT, "assets", "fonts"), "assets/fonts"),
        (os.path.join(ROOT, "assets", "icons"), "assets/icons"),
        (os.path.join(ROOT, "assets", "logo"), "assets/logo"),
        # Nur das Default-Link-Profil — keine Wildcard auf configs/, damit
        # Customer-spezifische Profile (kunde1.json, buchhaltung_free.json)
        # nicht ins NoRisk-Bundle leaken.
        (
            os.path.join(ROOT, "configs", "link_profiles", "default.json"),
            "configs/link_profiles",
        ),
        # Nur das NoRisk-Icon — automate.ico/finlai.ico/finlai_old.ico haben
        # keine Funktion im NoRisk-Bundle (~630 KB unnötig). resources/ enthält
        # heute ausschließlich App-Icons; keine NoRisk-Tool-Code-Pfade lesen
        # andere Subdirs aus resources/.
        (os.path.join(ROOT, "resources", "icons", "norisk.ico"), "resources/icons"),
        # c2 (2026-06-26): kuratierte Marketing-Leitfaden-PDFs (Backup-Strategie,
        # Verschluesselung, Grundschutz, …), die das Cockpit aus der "FINLAI
        # empfiehlt"-Anleitung oeffnet. resource_path-Aufloesung in
        # core/guide_registry.py.
        (os.path.join(ROOT, "resources", "guides"), "resources/guides"),
        # HandbuchService lädt docs/*.md relativ zu parents[3]. NoRisk-spezifisch:
        # nur ANWENDERHANDBUCH_NORISK.md bündeln (FINLAI/AUTOMATE/TeachMe-Handbücher
        # sind für diesen Build irrelevant, Denylist-Dokumente werden ohnehin gefiltert).
        (os.path.join(ROOT, "docs", "ANWENDERHANDBUCH_NORISK.md"), "docs"),
        # T-453: Handbuch-Screenshots für den In-App-Handbuch-Reiter, der die .md
        # direkt rendert (inkl. Bilder). Ohne diese fehlen die Screenshots im Build.
        (os.path.join(ROOT, "docs", "images"), "docs/images"),
        # T-068: endoflife.date Vendor:Product → Slug Mapping. _load_product_map
        # liest aus sys._MEIPASS im Bundle, repo-root im Dev-Modus.
        (
            os.path.join(ROOT, "core", "data", "endoflife_product_map.json"),
            "core/data",
        ),
    ],
    hiddenimports=[
        # ── Core (Plattform) ─────────────────────────────────────────────
        "core.version",
        "core.main_window",
        "core.sidebar",
        "core.tool_registry",
        "core.base_tool",
        "core.audit_log",
        "core.gdpr",
        "core.fonts",
        "core.theme",
        "core.ui_settings",
        "core.logger",
        "core.constants",
        "core.config",
        "core.prompts",
        "core.ollama_utils",
        "core.hardware_fingerprint",
        "core.security.encryption",
        "core.updater",
        "core.updater_dialog",
        "core.link_profile_loader",
        "core.auth.login_window",
        "core.auth.session",
        "core.auth.user_store",
        "core.database.encrypted_db",
        "core.database.db_check",
        # ── Core LLM (Ollama-only, 100% lokal — T-242r/T-244r) ───────────
        "core.llm.llm_base",
        "core.llm.llm_config",
        "core.llm.llm_factory",
        "core.llm.llm_result",
        "core.llm.ollama_provider",
        # ── Apps ─────────────────────────────────────────────────────────
        "apps.app_config",
        # ── NoRisk Tools (NORISK_CONFIG.tool_modules, T-359-Sync) ────────
        "tools.mainpage.tool",
        "tools.norisk_dashboard.tool",
        "tools.cyber_dashboard.tool",
        "tools.system_scanner.tool",
        "tools.system_tuner.tool",
        "tools.security_scoring.tool",
        "tools.techstack.tool",
        "tools.network_scanner.tool",
        "tools.network_monitor.tool",
        "tools.api_security.tool",
        "tools.cert_monitor.tool",
        "tools.password_checker.tool",
        "tools.customer_audit.tool",
        "tools.awareness_tracker.tool",
        # T-446: Bewerten-Container + sein lazy (PLC0415) geladenes NIS2-Sub-Tool
        # (customer_audit/security_scoring/awareness_tracker stehen bereits oben).
        "tools.security_assessment.tool",
        "tools.nis2_incidents.tool",
        "tools.dependency_auditor.tool",
        "tools.csaf_advisor.tool",
        "tools.patch_monitor.tool",
        "tools.supply_chain_monitor.tool",
        "tools.file_scanner.tool",
        "tools.handbuch_assistent.application.handbuch_service",
        "tools.einstellungen.tool",
        # file_scanner laedt seine drei Sub-Tools lazy (PLC0415). PyInstallers
        # Bytecode-Analyse findet literale Funktions-Imports zwar i.d.R. selbst,
        # die expliziten Eintraege sind bewusstes Belt-and-Suspenders.
        "tools.email_scanner.tool",
        "tools.pdf_risk_scanner.tool",
        "tools.document_scanner.tool",
        # ── Externe Libs, die PyInstaller gern übersieht ─────────────────
        "sqlcipher3",
        "argon2",
    ] + _qt_material_icons_submodules,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=_COMMON_EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# ── Collector: 2. EXE-Target (Qt-frei, headless ETW-Collector, T-340 F-C-2) ──
# Eigene Analysis mit eigenem Importgraphen ab apps/collector_main.py und vollem
# Qt-Ausschluss. KEIN MERGE(): MERGE setzt Cross-Bundle-Referenzen mit relativen
# Pfaden zwischen GETRENNTEN Bundle-Ordnern — hier liegen aber beide Exen im
# SELBEN COLLECT-Ordner und teilen ein _internal/. Der robuste, dokumentierte
# Onedir-Mehrfach-Exe-Weg ist deshalb: zwei Analysen → zwei PYZ/EXE → EIN COLLECT,
# das beide Exen plus die (von COLLECT deduplizierte) Vereinigung der Binaries
# auslegt. Jede Exe traegt ihr eigenes PYZ (reines Python), die Binaries/DLLs
# liegen geteilt im _internal/.
c = Analysis(
    [os.path.join(ROOT, "apps", "collector_main.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=_collector_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=_COLLECTOR_EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# DLLs herausfiltern die mit Qt's Loader kollidieren (UCRT/ICU + OpenSSL-
# Kopien aus site-packages). CPythons eigene libcrypto/libssl aus
# <python>/DLLs/ bleiben im Bundle — _ssl.pyd braucht sie (T-359-Review F1).
# Gilt fuer BEIDE Analysen (auch der Collector braucht funktionierendes Python-
# TLS, falls Lazy-Importe es ziehen). Zentral in build.py — siehe Docstring dort.
import sys as _sys
_sys.path.insert(0, ROOT)
from build import is_qt_conflicting_dll


def _filter_qt_conflicting(binaries: list) -> list:
    """Entfernt Qt-kollidierende/site-packages-DLLs aus einer Binaries-TOC."""
    return [
        b for b in binaries
        if not is_qt_conflicting_dll(b[0].lower(), str(b[1]).lower())
    ]


a.binaries = _filter_qt_conflicting(a.binaries)
c.binaries = _filter_qt_conflicting(c.binaries)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
pyz_collector = PYZ(c.pure, c.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="norisk",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, "resources", "icons", "norisk.ico"),
)

exe_collector = EXE(
    pyz_collector,
    c.scripts,
    [],
    exclude_binaries=True,
    name="norisk-collector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    # Headless: kein Konsolenfenster (analog pythonw.exe im Dev-Modus) — sonst
    # blitzt beim Logon-Trigger der geplanten Aufgabe eine Konsole auf. Der
    # Exit-Code (z. B. 2 = kein Admin) bleibt fuer den Smoke trotzdem lesbar.
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    # Signing-Readiness (T-340 F-C): Hook bewusst None, bis das OV-Zertifikat da
    # ist; die Signatur kommt dann hier UND fuer ``exe`` (Haupt-App) rein.
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, "resources", "icons", "norisk.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    exe_collector,
    c.binaries,
    c.zipfiles,
    c.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="norisk",
)

# ── Post-Build Bundle-Gate (T-340 F-G, FAIL-CLOSED) ──────────────────────────
# COLLECT() hat das Bundle bereits nach dist/norisk/ geschrieben. Jetzt der
# Binär-Scan: eine TRANSITIV gezogene GPL/Npcap-DLL (die der Pre-Build-Code-Scan
# nicht sehen kann, weil sie in keinem eigenen Import auftaucht) bricht den Build
# hier hart ab. check_installed=False — die installierten Dists wurden oben bereits
# geprueft.
assert_build_compliant(
    ROOT,
    bundle_dir=os.path.join(ROOT, "dist", "norisk"),
    check_installed=False,
)
