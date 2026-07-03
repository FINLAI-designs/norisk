"""
patch_console_widget — UI fuer den Patch-Monitor.

PM-1.7. Zeigt das Inventar einer Patch-Pipeline-Ausfuehrung:

* Toolbar mit Scan/Cancel/Filter
* QProgressBar (eingeblendet waehrend Scan)
* QTableWidget mit 7 Spalten (Status / App / Version / Kanal / CVEs /
  CVSS / Empfehlung)
* Detail-Panel (collapsible) zur ausgewaehlten Zeile
* Statuszeile unten

Threading:
  Der:class:`core.scan_worker.ScanWorker` laeuft via
  ``moveToThread`` in einem Hintergrund-Thread, das Widget ist
  reine UI-Schicht ohne Business-Logik. Alle Updates kommen ueber
  Qt-Signals.

Schicht: ``gui/`` — keine direkten ``application/``-Importe ausser
ueber den Worker; keine ``data/``-Importe. Theme-Farben aus
:mod:`core.theme`.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QSize, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.icons import ICON_SIZE_MD, Icons, get_icon
from core.logger import get_logger
from core.patch_collector import ModuleStatus, get_winget_module_status
from core.patch_id_utils import is_synthetic_id
from core.patch_result import PatchScanResult
from core.patch_strategy import PatchStrategy
from core.patch_upgrade import UpgradeRequest, UpgradeResult, UpgradeStatus
from core.scan_worker import ScanWorker
from core.widgets.button_styles import outline_button_qss
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.patch_monitor.application.batch_upgrade_service import BatchSummary
from tools.patch_monitor.application.patch_inventory_service import (
    PatchInventoryService,
)
from tools.patch_monitor.gui.custom_source_dialog import CustomSourceDialog
from tools.patch_monitor.gui.onboarding_dialog import (
    WingetModuleOnboardingDialog,
)
from tools.patch_monitor.gui.upgrade_confirm_dialog import UpgradeConfirmDialog
from tools.patch_monitor.gui.upgrade_worker import UpgradeWorker
from tools.patch_monitor.onboarding_marker import load_marker
from tools.patch_monitor.onboarding_orchestrator import should_show_onboarding

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Styling-Mappings — Theme-zentrale Farben + Material-Status-Farben
# ---------------------------------------------------------------------------

# FE-1 (Code-Review 2026-05-19): Recommendation → Material Symbol.
# Vorher Mixed-Dict aus ASCII/Unicode-Glyphs + Emojis. Skill
# 'frontend-design' verlangt durchgaengig Google Material Symbols.
# Die Status-Spalte ist explizit nicht sortierbar (
# ``setSortingEnabled(False)`` weiter unten), also keine
# Text-Sort-Anforderung. Faerbung jetzt ueber ``get_icon(name, color=...)``
# statt ``setForeground(QColor)``.
_REC_ICON: dict[str, str] = {
    "update_urgent": Icons.PRIORITY_HIGH,
    "update": Icons.ARROW_UP,
    "update_available": Icons.CIRCLE,
    "up_to_date": Icons.DONE,
    "notify_only": Icons.HELP,
    "pinned": Icons.ANCHOR,
    # erweiterte Empfehlungs-Klassen aus
    # ``core.patch_recommendation_engine``. Workaround → BUILD (CSAF
    # kennt Mitigation), EOL → DANGEROUS (Vendor-Support endgueltig
    # weg), patch_available_with_csaf_context → SHIELD (CSAF + Patch).
    "workaround_available": Icons.BUILD,
    "eol_no_patch": Icons.DANGEROUS,
    "patch_available_with_csaf_context": Icons.SHIELD,
    # User hat die App vom Patchen ausgenommen (PatchStrategy.NONE).
    "skipped_by_user": Icons.BLOCK,
}

# User-lesbare Labels fuer das Strategie-Dropdown (Sie-Form, deutsch).
# Reihenfolge = Anzeige-Reihenfolge im QComboBox.
_STRATEGY_LABELS: dict[PatchStrategy, str] = {
    PatchStrategy.STABLE: "Stabil",
    PatchStrategy.LATEST: "Neueste",
    PatchStrategy.NONE: "Nicht patchen",
}


def _strategy_label(strategy: PatchStrategy) -> str:
    """User-lesbares Label einer:class:`PatchStrategy` (Fallback: Wert)."""
    return _STRATEGY_LABELS.get(strategy, strategy.value)


# User-lesbare Labels fuer den Channel-Selektor (Sie-Form, deutsch).
# Reihenfolge = Anzeige-Reihenfolge im QComboBox (Task-Vorgabe). Schluessel =
# core.patch_policy.USER_OVERRIDE_CHANNELS-Werte.
_CHANNEL_LABELS: dict[str, str] = {
    "notify_only": "Nur melden",
    "patch_only": "Nur Patches",
    "stable": "Stabil",
    "latest": "Neueste",
    "pinned": "Eingefroren",
}

# FE-2 (Code-Review 2026-05-19): vorher 11 hartcodierte Hex-Farben in
# _REC_COLOR/_CHANNEL_COLOR/_cvss_color — eigene Palette ausserhalb des
# Theme-Systems, die bei White-Label-Akzent-Wechsel nicht mit-migrierte.
# Jetzt funktions-basiert mit theme.get-Tokens, semantisch eindeutig.
# Eine Custom-Konstante bleibt (Channel 'patch_only' = lila) — kein
# semantisch passendes FINLAI-Theme-Token, lokal als Modul-Konstante
# mit klarem Kommentar.

#: Patch-Only-Channel = Material Purple 600. Im FINLAI-Theme nicht
#: vorgesehen (Theme ist Teal-zentriert). Lokale Modul-Konstante; bei
#: Theme-Erweiterung um Channel-Token in core/theme.py heben.
_CHANNEL_COLOR_PATCH_ONLY: str = "#8E44AD"


def _rec_color(rec: str | None) -> str:
    """Recommendation -> Vordergrund-Farbe (Statuszeichen). Theme-aware.

    Workaround = orange (deutlich aber nicht panic-rot),
    EOL = dunkelrot (terminal), patch+CSAF = blau (kontextualisiert).
    """
    c = theme.get()
    if rec in ("update_urgent", "eol_no_patch"):
        return c.DANGER
    if rec in ("update", "workaround_available"):
        return c.WARNING
    if rec in ("update_available", "patch_available_with_csaf_context"):
        return c.STATUS_INFO
    if rec == "up_to_date":
        return c.SUCCESS
    if rec in ("notify_only", "pinned", "skipped_by_user"):
        return c.TEXT_DIM
    return c.TEXT_DIM  # Fallback


def _channel_color(channel: str | None) -> str:
    """Channel -> Badge-Hintergrundfarbe. Theme-aware (User-Spec)."""
    c = theme.get()
    if channel == "latest":
        return c.ACCENT
    if channel == "stable":
        return c.STATUS_INFO
    if channel == "patch_only":
        return _CHANNEL_COLOR_PATCH_ONLY
    if channel in ("pinned", "notify_only"):
        return c.TEXT_DIM
    return c.TEXT_DIM  # Fallback


def _cvss_color(cvss: float | None) -> str:
    """Ampel-Farbe fuer CVSS-Score laut User-Spec. Theme-aware (SEVERITY_SIGNAL_*)."""
    if cvss is None:
        return theme.SEVERITY_SIGNAL_INFO
    if cvss >= 9.0:
        return theme.SEVERITY_SIGNAL_CRITICAL
    if cvss >= 7.0:
        return theme.SEVERITY_SIGNAL_HIGH
    if cvss >= 4.0:
        return theme.SEVERITY_SIGNAL_MEDIUM
    return theme.SEVERITY_SIGNAL_OK


# Filter-Dropdown-Werte (interner Schluessel → Anzeigetext).
_FILTERS: tuple[tuple[str, str], ...] = (
    ("all", "Alle"),
    ("critical", "Nur kritisch (urgent)"),
    ("needs_update", "Updates verfuegbar"),
    ("up_to_date", "Up-to-date"),
    ("notify_only", "Notify-only"),
)


# Banner-Texte (Privacy-Filter-konform — keine stderr-Excerpts).
# Bug-Fix-Sprint C-5: Mapping reason-Klasse → User-lesbarer Banner-Text.
_BANNER_TEXT: dict[str, str] = {
    "module-not-found": (
        "WinGet-PowerShell-Modul nicht installiert — "
        "Patch-Erkennung läuft im Fallback-Modus."
    ),
    "execution-policy-restricted": (
        "PowerShell-Execution-Policy ist Restricted — "
        "WinGet-Modul-Install nicht möglich."
    ),
    "execution-policy-allsigned": (
        "PowerShell-Execution-Policy ist AllSigned — "
        "WinGet-Modul-Install nicht möglich."
    ),
    "get-module-failed": (
        "WinGet-Modul-Erkennung fehlgeschlagen — "
        "Patch-Erkennung läuft im Fallback-Modus."
    ),
    "probe-failed": (
        "WinGet-Modul installiert, aber Aufruf fehlgeschlagen — "
        "Patch-Erkennung läuft im Fallback-Modus."
    ),
    "powershell-subprocess-unavailable": (
        "PowerShell nicht erreichbar — Patch-Erkennung eingeschränkt."
    ),
    "non-windows-platform": ("Patch-Monitor unterstützt aktuell nur Windows."),
}


def _should_show_banner(module_status: ModuleStatus) -> bool:
    """True wenn der Status-Banner sichtbar sein soll.

    Banner zeigen bei NEEDS_INSTALL und BLOCKED. Bei AVAILABLE: Modul ist
    da, kein Hinweis nötig.
    """
    return module_status is not ModuleStatus.AVAILABLE


def _banner_text_for_reason(reason: str) -> str:
    """User-lesbarer Banner-Text fuer eine ``reason``-Klasse.

    Privacy-Filter-konform: niemals stderr-Excerpts oder Pfad-/User-Daten.
    Bei unbekannter Klasse: generischer Fallback-Text.
    """
    return _BANNER_TEXT.get(
        reason,
        "WinGet-PowerShell-Modul nicht verfügbar — Fallback aktiv.",
    )


def _passes_filter(result: PatchScanResult, filter_key: str) -> bool:
    """Gibt True zurueck, wenn das Result die aktuelle Filter-Auswahl
    durchlaeuft. Modul-Funktion → testbar ohne QApplication."""
    if filter_key == "all":
        return True
    if filter_key == "critical":
        return result.recommendation == "update_urgent"
    if filter_key == "needs_update":
        # „Updates verfuegbar" = ein Update EXISTIERT (roh, is_update_available),
        # UNABHAENGIG vom Kanal — auch notify_only-Apps mit Update erscheinen hier
        # (Quick-Check-Konsistenz: Toast/Zaehlung/Popup zeigen dasselbe). Ob eine
        # Zeile direkt patchbar ist, entscheidet separat `_is_upgradeable`
        # (Install-Checkbox); notify_only wird erst nach Kanalwechsel patchbar.
        return result.is_update_available
    if filter_key == "up_to_date":
        return result.recommendation == "up_to_date"
    if filter_key == "notify_only":
        return result.recommendation == "notify_only"
    return True


def _passes_search(result: PatchScanResult, query: str) -> bool:
    """True wenn der App-Name den Suchbegriff enthaelt (Substring, case-insensitiv).

    Leerer Query matcht alles. Modul-Funktion → testbar ohne QApplication
    (analog:func:`_passes_filter`). ``query`` wird bereits normalisiert
    (``casefold``) uebergeben.
    """
    if not query:
        return True
    return query in result.name.casefold()


# ---------------------------------------------------------------------------
# PM-2.x Upgrade-Hilfen — Auswahl, Request-Konstruktion, Live-Status
# ---------------------------------------------------------------------------

# Empfehlungs-Werte, fuer die der User ein Upgrade ausloesen darf.
# ``patch_available_with_csaf_context`` ist selektierbar — es gibt
# einen Patch, plus CSAF-Kontext (Severity + Action). ``workaround_available``
# und ``eol_no_patch`` sind NICHT selektierbar: kein Patch verfuegbar
# (Workaround) bzw. kein Patch in Sicht (EOL).
_UPGRADEABLE_RECOMMENDATIONS: frozenset[str] = frozenset(
    {
        "update_urgent",
        "update",
        "update_available",
        "patch_available_with_csaf_context",
    }
)


#: Herkunft-Anzeige je Quelle (Patrick 2026-06-30: sichtbar machen, woher eine
#: Zeile kommt — vor allem die neuen Windows-Update-Eintraege, die winget nicht
#: kennt).
_SOURCE_LABEL: dict[str, str] = {
    "winget": "winget",
    "registry": "Registry",
    "msix": "Store/MSIX",
    "custom": "Eigene Quelle",
    "windows_update": "Windows-Update",
    "dotnet": ".NET",
    "driver": "Treiber",
}

_SOURCE_TOOLTIP: dict[str, str] = {
    "winget": "Aus dem winget-Katalog — automatisch installierbar.",
    "registry": (
        "Aus der Windows-Registry erkannt (keine winget-Quelle) — "
        "manuell beim Hersteller aktualisieren."
    ),
    "msix": "Microsoft-Store-/MSIX-App.",
    "custom": "Manuell gepflegte Quelle (nur Hinweis).",
    "windows_update": (
        "Über Windows-Update geliefert (OS/Treiber/.NET) — Installation in "
        "den Windows-Einstellungen, nicht im Patch-Monitor."
    ),
    "dotnet": (
        "Installierte .NET-Laufzeit — Updates kommen über Windows-Update."
    ),
    "driver": (
        "Gerätetreiber (GPU/Netzwerk/Storage) — Updates kommen über "
        "Windows-Update."
    ),
}


def _source_label(source: str) -> str:
    """Anzeigename der Quelle (Herkunft) einer Inventar-Zeile."""
    return _SOURCE_LABEL.get(source, source)


def _source_tooltip(source: str) -> str:
    """Erklärungs-Tooltip zur Quelle (warum ggf. nicht im Tool installierbar)."""
    return _SOURCE_TOOLTIP.get(source, "")


def _is_upgradeable(result: PatchScanResult) -> bool:
    """``True`` wenn eine Zeile fuer den Batch-Upgrade selektierbar ist.

    Zwei Bedingungen: ``recommendation`` muss eine Update-Klasse sein
    (nicht ``up_to_date`` / ``notify_only`` / ``pinned``) **und** ein
    Package-Identifier muss vorhanden sein.: seit
    msstore-Support qualifizieren sowohl ``winget_id`` (Catalog) als
    auch ``store_id`` (Microsoft Store). Registry-Apps ohne beide
    bleiben weiterhin nicht-selektierbar.

    Synthetische Ids (Registry-/MSIX-Apps, ``regid:``/``msix:``) sind
    NIE selektierbar — winget kann sie nicht installieren. Diese Apps
    werden nur angezeigt (notify_only-aehnlich), nicht batch-upgradet.
    """
    if is_synthetic_id(result.winget_id):
        return False
    if result.winget_id is None and result.store_id is None:
        return False
    return result.recommendation in _UPGRADEABLE_RECOMMENDATIONS


def _to_upgrade_request(result: PatchScanResult) -> UpgradeRequest:
    """Konstruiert einen:class:`UpgradeRequest` aus einer Tabellenzeile.

    Voraussetzung::func:`_is_upgradeable` ist ``True`` — sonst ist
    weder ``winget_id`` noch ``store_id`` gesetzt.

    Dispatch-Konvention: exact one of ``winget_id`` / ``store_id``
    ist auf der Request gesetzt. Bei Mixed-Items (theoretisch beide
    befuellt) gewinnt ``winget_id`` — Catalog-Pfad ist robuster und
    deterministischer. In der Praxis liefert ``collect_winget_module``
    genau eines der beiden, je nach ``source_raw``.

    Raises:
        ValueError: Wenn ``winget_id`` eine synthetische Id ist
            (Registry-/MSIX-App). Defense-in-depth — der Aufrufer muss
            via:func:`_is_upgradeable` vorab filtern; eine synthetische
            Id darf nie in einen:class:`UpgradeRequest` und damit nie an
            ein winget-Kommando gelangen.
    """
    if is_synthetic_id(result.winget_id):
        raise ValueError(
            "Synthetische Id (Registry-/MSIX-App) ist nicht upgradebar — "
            "darf nie in einen UpgradeRequest gelangen"
        )
    if result.winget_id is not None:
        return UpgradeRequest(
            winget_id=result.winget_id,
            version_from=result.installed_version or None,
            version_to=result.available_version,
            display_name=result.name,
        )
    # store_id ist garantiert nicht-None weil _is_upgradeable bereits prueft
    return UpgradeRequest(
        winget_id=None,
        store_id=result.store_id,
        version_from=result.installed_version or None,
        version_to=result.available_version,
        display_name=result.name,
    )


def _format_select_count(n: int) -> str:
    """Footer-Badge-Text wie ``"3 Updates ausgewaehlt"``."""
    if n == 0:
        return "Keine Updates ausgewaehlt"
    if n == 1:
        return "1 Update ausgewaehlt"
    return f"{n} Updates ausgewaehlt"


# FE-1: Material Symbols statt Text-Glyphs. ueberlagert die
# ``recommendation``-Icon waehrend / nach einer Batch.
_UPGRADE_LIVE_ICON: dict[UpgradeStatus, str] = {
    UpgradeStatus.SUCCESS: Icons.DONE,
    UpgradeStatus.FAILED: Icons.CLOSE,
    UpgradeStatus.TIMEOUT: Icons.TIMER,
    UpgradeStatus.SKIPPED: Icons.BLOCK,
}

_UPGRADE_LIVE_COLOR: dict[UpgradeStatus, str] = {
    UpgradeStatus.SUCCESS: "#27AE60",
    UpgradeStatus.FAILED: "#C0392B",
    UpgradeStatus.TIMEOUT: "#E67E22",
    UpgradeStatus.SKIPPED: "#7F8C8D",
}

#: Material Symbol waehrend ein Upgrade fuer eine Zeile aktiv laeuft.
_UPGRADE_RUNNING_ICON = Icons.HOURGLASS
_UPGRADE_RUNNING_COLOR = "#2980B9"


def _format_log_line_started(index: int, total: int, req: UpgradeRequest) -> str:
    """Formatiert eine Log-Zeile beim Start eines Items."""
    return f"[{index}/{total}] starte {req.display_name} ({req.winget_id})"


def _format_log_line_finished(
    index: int, total: int, req: UpgradeRequest, result: UpgradeResult
) -> str:
    """Formatiert eine Log-Zeile nach Item-Ende mit Status + Dauer.

    Bei FAILED nutzt sie ``result.error`` — das traegt den User-lesbaren
    Hinweis aus:func:`core.patch_upgrade._format_exit_code_error`
-Smoke 2026-05-12). Fallback auf Exit-Code wenn ``error`` leer.
    """
    sec = result.duration_ms / 1000
    if result.status is UpgradeStatus.SUCCESS:
        return f"[{index}/{total}] OK: {req.display_name} in {sec:.1f}s"
    if result.status is UpgradeStatus.SKIPPED:
        return f"[{index}/{total}] {req.display_name} uebersprungen"
    if result.status is UpgradeStatus.TIMEOUT:
        return f"[{index}/{total}] Timeout: {req.display_name} nach {sec:.1f}s"
    detail = result.error or f"exit={result.exit_code}"
    return (
        f"[{index}/{total}] Fehler: {req.display_name} ({detail}, {sec:.1f}s)"
    )


def _format_scan_freshness(
    last_full: datetime | None,
    last_daily: datetime | None,
    *,
    now: datetime | None = None,
) -> str:
    """Banner-Text fuer den Patch-Persistence-Stand Stop-Step D).

    Drei Faelle:
    * Keine Persistenz (last_full=None): "Patch-Inventar noch nicht
      aufgebaut — Erst-Scan empfohlen."
    * Vollscan vorhanden, Daily=None: "Letzter Vollscan: vor N Tagen.
      Daily-Refresh ausstehend."
    * Beides vorhanden: "Letzter Vollscan: vor N Tagen · Daily-Refresh:
      vor M Stunden."

    Args:
        last_full: Aus:meth:`PatchInventoryService.get_last_full_scan_at`.
        last_daily: Aus:meth:`PatchInventoryService.get_last_daily_refresh_at`.
        now: Test-Override.
    """
    if last_full is None:
        return (
            "Patch-Inventar noch nicht aufgebaut — 'Scan starten' erfasst alle "
            "installierten Programme, findet verfuegbare Sicherheitsupdates und "
            "gleicht sie gegen bekannte Schwachstellen (CVE) ab "
            "(Erst-Vollscan ca. 15-20 Min)."
        )
    if now is None:
        from datetime import datetime as _dt  # noqa: PLC0415

        now = _dt.now(tz=last_full.tzinfo)
    full_age = now - last_full
    full_text = _format_age(full_age)
    if last_daily is None:
        return f"Letzter Vollscan: vor {full_text}. Daily-Refresh ausstehend."
    daily_age = now - last_daily
    daily_text = _format_age(daily_age)
    return f"Letzter Vollscan: vor {full_text} · Daily-Refresh: vor {daily_text}."


def _format_age(delta) -> str:  # noqa: ANN001 - timedelta
    """Menschenlesbare Altersangabe fuer den Banner-Text.

    Auswahl der Einheit nach Faustregel:
    * < 1 h → "wenigen Minuten" / "X Minuten"
    * < 24 h → "X Stunden"
    * < 30 d → "X Tagen"
    * sonst → "X Monaten" (round-down)
    """
    seconds = delta.total_seconds()
    if seconds < 60:
        return "wenigen Sekunden"
    minutes = seconds / 60
    if minutes < 60:
        n = int(minutes)
        return f"{n} Minute" if n == 1 else f"{n} Minuten"
    hours = minutes / 60
    if hours < 24:
        n = int(hours)
        return f"{n} Stunde" if n == 1 else f"{n} Stunden"
    days = hours / 24
    if days < 30:
        n = int(days)
        return f"{n} Tag" if n == 1 else f"{n} Tagen"
    months = days / 30
    n = int(months)
    return f"{n} Monat" if n == 1 else f"{n} Monaten"


def _format_batch_summary(summary: BatchSummary) -> str:
    """Statuszeilen-Text fuer das Batch-Ende."""
    parts: list[str] = [f"{summary.total} Aktionen"]
    if summary.succeeded:
        parts.append(f"{summary.succeeded} erfolgreich")
    if summary.failed:
        parts.append(f"{summary.failed} fehlgeschlagen")
    if summary.timed_out:
        parts.append(f"{summary.timed_out} Timeout")
    if summary.skipped:
        parts.append(f"{summary.skipped} uebersprungen")
    return "Batch fertig: " + ", ".join(parts)


def _format_status_line(results: list[PatchScanResult]) -> str:
    """Statuszeile fuer eine fertige Ergebnisliste (Modul-Funktion fuer Tests)."""
    total = len(results)
    urgent = sum(1 for r in results if r.recommendation == "update_urgent")
    # „Updates verfuegbar" = ein Update EXISTIERT (roh, is_update_available),
    # unabhaengig vom Kanal — konsistent mit Filter, Popup und Hintergrund-Toast
    # (`items_with_updates`). notify_only-Apps mit Update zaehlen mit; ob sie DIREKT
    # patchbar sind, zeigt separat die „installierbar"-Teilmenge unten.
    update_rows = [r for r in results if r.is_update_available]
    updates = len(update_rows)
    # Transparenz (Patrick 2026-06-29): „X Updates verfuegbar" zaehlt ALLE Apps mit
    # verfuegbarem Update — auch Registry-/MSIX-Apps OHNE winget-/Store-Eintrag, die
    # nicht per Batch („Updates durchfuehren") installierbar und damit nicht
    # ankreuzbar sind. Sonst wirkt es wie „11 Updates, aber nur 3 auswaehlbar".
    # Darum die ankreuzbare (installierbare) Teilmenge der Update-Zeilen ausweisen.
    installierbar = sum(
        1
        for r in update_rows
        if r.winget_id is not None or r.store_id is not None
    )
    updates_text = f"{updates} Updates verfuegbar"
    if updates and installierbar < updates:
        updates_text += f" (davon {installierbar} automatisch installierbar)"
    now = datetime.now().strftime("%H:%M:%S")
    return (
        f"{total} Apps | {urgent} kritisch | {updates_text}"
        f" | Letzter Scan: {now}"
    )


# ---------------------------------------------------------------------------
# Widget
# ---------------------------------------------------------------------------


class PatchConsoleWidget(QWidget):
    """Patch-Monitor-Konsole — Tabelle + Detail-Panel.

    Signals:
        request_scan: wird vom Scan-Button gefeuert.
            Externer Code oder die internen Slots koennen darauf
            reagieren (Tests pruefen Worker-Trigger ueber Mocks).
        request_quick_check: wird vom Button "Schnell nach Updates suchen"
            gefeuert. Das MainWindow verbindet das Signal duck-typed
            (``core/dock_mixin.py``) mit dem Daily-Refresh-Worker
            (``_inv_worker.run_daily_refresh``) — ein leichter
            Versions-Abgleich (~30-60 s) statt des Vollscans (~20 Min).
    """

    request_scan = Signal()
    request_quick_check = Signal()

    # PM-2.x: Erste Spalte ist die Multi-Select-Checkbox.
    # Bestehende Spaltenindexe sind um +1 verschoben.
    _COL_CHECKBOX = 0
    _COL_STATUS = 1
    _COL_NAME = 2
    _COL_VERSION = 3
    _COL_SOURCE = 4  # Herkunft: winget / Registry / Windows-Update / Store
    _COL_CHANNEL = 5
    _COL_CVES = 6
    _COL_CVSS = 7
    _COL_RECOMMEND = 8
    _COL_STRATEGY = 9  # user-eigene Patch-Strategie (Dropdown)
    _COL_COUNT = 10

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        upgrade_history_repo_factory=None,  # type: ignore[no-untyped-def]
    ) -> None:
        """Initialisiert das Widget.

        Worker + Thread werden lazy bei:meth:`_start_scan` angelegt
        — Widget-Konstruktion wirft also keine NVD/DB-Konstruktion
        an (relevant fuer Tab-Wechsel-Performance).

        Args:
            parent: Eltern-Widget.
            upgrade_history_repo_factory: Parameterlose Factory, die ein
                ``UpgradeHistoryRepository`` liefert (aus der Composition-Root
                ``tool.py`` gereicht — die GUI haengt nicht direkt am data-Layer,
                Hex-Vertrag gui!->data). ``None`` -> der Upgrade-Verlauf bleibt leer.
        """
        super().__init__(parent)
        self._upgrade_history_repo_factory = upgrade_history_repo_factory
        self._results: list[PatchScanResult] = []
        self._filter_key: str = "all"
        # D (Live-Test 2026-07-01): Freitext-Filter ueber den App-Namen,
        # UND-verknuepft mit dem Kategorie-Filter. Single-Source: ``_results``.
        self._search_text: str = ""
        # C (Live-Test 2026-07-01): merkt sich, dass der naechste
        # reload_after_refresh von einem ON-DEMAND-Quick-Check ausgeloest wurde
        # (nicht vom automatischen 24-h-Scheduler) — nur dann springen wir in
        # den Update-Filter und weisen aufs Markieren hin.
        self._quick_check_pending: bool = False
        self._scan_thread: QThread | None = None
        self._scan_worker: ScanWorker | None = None
        # Bug-Fix-Sprint C-3 Option D — Onboarding-Dialog wird genau einmal
        # pro Widget-Instanz beim ersten Sichtbar-Werden geprueft. Das Flag
        # verhindert Mehrfach-Anzeige bei Tab-Wechseln (showEvent feuert auch
        # bei Re-Show nach Hide).
        self._onboarding_checked: bool = False
        # PM-2.x: Upgrade-Worker + Live-Status-Overlay.
        self._upgrade_thread: QThread | None = None
        self._upgrade_worker: UpgradeWorker | None = None
        # winget_id → UpgradeStatus | "running"; ueberlagert die
        # Recommendation-Glyph in der Status-Spalte waehrend / nach Batch.
        self._upgrade_status_by_id: dict[str, UpgradeStatus | str] = {}
        # Stop-Step D: Persistence-Service fuer load_from_db beim
        # Open + Persistenz nach jedem on_scan_complete. Lazy init beim
        # ersten Zugriff, damit Tests die Konstruktion via
        # ``patch_console_widget._INVENTORY_SERVICE`` faken koennen ohne
        # echte EncryptedDB-Anlage.
        self._inventory_service: PatchInventoryService | None = None
        self._inventory_loaded_from_db: bool = False
        # Phase E2: Host-OS-Eckdaten (Edition/Version/Build) fuer die
        # rechtsbuendige Kopfzeilen-Anzeige. Einmalig + fail-soft erhoben — der
        # Detektor in core/os_info.py wirft nie, hier zusaetzlich abgeschirmt,
        # damit ein ungeahnter Importfehler den Patch-Monitor nicht blockiert.
        self._host_os_text: str = ""
        try:
            from core.os_info import detect_host_os_info

            self._host_os_text = detect_host_os_info().anzeige
        except Exception as exc:  # noqa: BLE001 — Kopfzeile ist rein dekorativ
            log.debug("Host-OS-Anzeige nicht verfuegbar: %s", exc)
        self._build_ui()
        self._apply_styles()

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        root.addWidget(self._build_module_banner())  # C-5: Status-Banner
        root.addWidget(self._build_freshness_banner())  # D: Cache-Stand
        root.addWidget(self._build_eol_banner())  # ID.AM EOL-Banner
        root.addLayout(self._build_toolbar())
        root.addWidget(self._build_progress())
        root.addWidget(self._build_table(), stretch=7)
        # PM-2.x: Footer-Bar zwischen Tabelle und Detail-Panel.
        root.addWidget(self._build_footer_bar())
        root.addWidget(self._build_log_panel())
        root.addWidget(self._build_detail_panel(), stretch=3)
        root.addWidget(self._build_status_bar())

    def _build_module_banner(self) -> QFrame:
        """Status-Banner fuer ModuleStatus != AVAILABLE (Bug-Fix-Sprint C-5).

        Sichtbarkeit + Inhalt werden in:meth:`_refresh_module_banner`
        gesetzt — diese Methode baut nur das UI-Skelett.
        """
        banner = QFrame()
        banner.setObjectName("ModuleStatusBanner")
        banner.setFrameShape(QFrame.Shape.StyledPanel)
        banner.setStyleSheet(
            "QFrame#ModuleStatusBanner {"
            "  background: #FFF8E1;"  # warm yellow tint
            "  border: 1px solid #E67E22;"
            "  border-radius: 4px;"
            "}"
        )
        layout = QVBoxLayout(banner)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)

        top_row = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(
            get_icon(Icons.WARNING, color="#E67E22").pixmap(QSize(ICON_SIZE_MD, ICON_SIZE_MD))
        )
        top_row.addWidget(icon)

        self._banner_text = QLabel("")
        self._banner_text.setWordWrap(True)
        top_row.addWidget(self._banner_text, stretch=1)

        self._banner_install_btn = QPushButton("Modul installieren")
        self._banner_install_btn.clicked.connect(self._on_banner_install_clicked)
        top_row.addWidget(self._banner_install_btn)

        self._banner_diagnose_btn = QPushButton("Diagnose")
        self._banner_diagnose_btn.setCheckable(True)
        self._banner_diagnose_btn.toggled.connect(self._on_diagnose_toggled)
        top_row.addWidget(self._banner_diagnose_btn)

        layout.addLayout(top_row)

        # Diagnose-Section: standardmaessig versteckt (Opt-in fuer Admin).
        # reason_detail kann stderr-Excerpts mit Pfad-/User-Daten enthalten,
        # daher nicht sichtbar in der Default-Ansicht.
        self._banner_diagnose_label = QLabel("")
        self._banner_diagnose_label.setWordWrap(True)
        self._banner_diagnose_label.setVisible(False)
        self._banner_diagnose_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._banner_diagnose_label.setStyleSheet(
            "font-family: monospace; padding: 8px;"
            "background: #FAFAFA; border: 1px solid #DDD; border-radius: 3px;"
        )
        layout.addWidget(self._banner_diagnose_label)

        self._module_banner = banner
        banner.setVisible(False)
        return banner

    def _build_freshness_banner(self) -> QFrame:
        """Status-Banner mit Cache-Stand Stop-Step D).

        Zeigt "Letzter Vollscan vor X Tagen · Daily-Refresh vor Y
        Stunden". Wird beim Open ueber:meth:`_refresh_freshness_banner`
        gesetzt — diese Methode baut nur das UI-Skelett.
        """
        banner = QFrame()
        banner.setObjectName("ScanFreshnessBanner")
        banner.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(banner)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(8)
        self._freshness_icon = QLabel("ℹ")
        self._freshness_icon.setObjectName("ScanFreshnessIcon")
        layout.addWidget(self._freshness_icon)
        self._freshness_label = QLabel("")
        self._freshness_label.setObjectName("ScanFreshnessLabel")
        self._freshness_label.setWordWrap(True)
        layout.addWidget(self._freshness_label, stretch=1)
        self._freshness_banner = banner
        banner.setVisible(False)  # erst nach _refresh_freshness_banner
        return banner

    def _refresh_freshness_banner(self) -> None:
        """Liest aktuelle scan_history-Daten und aktualisiert den Banner."""
        service = self._get_inventory_service()
        if service is None:
            self._freshness_banner.setVisible(False)
            return
        try:
            last_full = service.get_last_full_scan_at()
            last_daily = service.get_last_daily_refresh_at()
        except Exception as exc:  # noqa: BLE001 — Banner darf App nicht crashen
            log.exception("freshness banner refresh: %s", exc)
            self._freshness_banner.setVisible(False)
            return
        self._freshness_label.setText(_format_scan_freshness(last_full, last_daily))
        self._freshness_banner.setVisible(True)

    def _get_inventory_service(self) -> PatchInventoryService | None:
        """Lazy-Init des Persistence-Service. ``None`` wenn DB-Init
        fehlschlaegt (Tests / Greenfield) — Widget bleibt funktional
        ohne Persistenz."""
        if self._inventory_service is not None:
            return self._inventory_service
        try:
            self._inventory_service = PatchInventoryService()
        except Exception as exc:  # noqa: BLE001 — DB-Init darf App nicht crashen
            log.warning(
                "PatchInventoryService-Init fehlgeschlagen (%s) — "
                "Patch-Console laeuft ohne Persistenz.",
                type(exc).__name__,
            )
            return None
        return self._inventory_service

    def _load_from_db_if_first_show(self) -> None:
        """Beim ersten Show: lade persistierten Stand in die Tabelle.

        Vermeidet leere Tabelle nach App-Restart — User sieht den letzten
        Scan-Stand sofort, ohne 20 min auf einen Live-Scan zu warten.
        """
        if self._inventory_loaded_from_db:
            return
        self._inventory_loaded_from_db = True
        service = self._get_inventory_service()
        if service is None:
            return
        try:
            results = service.load_from_db()
        except Exception as exc:  # noqa: BLE001
            log.exception("load_from_db beim Open fehlgeschlagen: %s", exc)
            return
        if not results:
            # Leere DB → Status-Bar-Hinweis statt leerer Tabelle
            self._status_label.setText(
                "Patch-Inventar leer — klick 'Scan starten' fuer Erst-Scan."
            )
            return
        self._results = results
        self._populate_table()
        self._status_label.setText(f"Aus Cache geladen: {_format_status_line(results)}")

    def _persist_scan_results(self, results: list[PatchScanResult]) -> None:
        """Persistiert ein vom ScanWorker geliefertes Result-Set in der
        PatchInventoryService-DB. Wird in on_scan_complete getriggert.

        scan_type ist 'manual' weil der User den Scan-Button geklickt
        hat. Initial/Monthly werden vom Scheduler getriggert (Stop-Step E).
        """
        service = self._get_inventory_service()
        if service is None:
            return
        try:
            # Wir haben die Results schon — wir bauen einen Mini-Wrapper-
            # PatchService der die existing Results zurueckliefert. So nutzt
            # die service.full_scan-Pipeline (inkl. scan_history-Audit +
            # delete_inventory_not_in) ohne nochmal NVD/winget aufzurufen.
            from types import SimpleNamespace  # noqa: PLC0415

            cached_scanner = SimpleNamespace(scan=lambda progress_cb=None: results)
            service._patch_service = cached_scanner  # type: ignore[assignment] # noqa: SLF001
            summary = service.full_scan(scan_type="manual")
            log.info(
                "scan persisted: total=%d, with_updates=%d, with_cves=%d (scan_id=%s)",
                summary.items_total,
                summary.items_with_updates,
                summary.items_with_cves,
                summary.scan_id,
            )
        except Exception as exc:  # noqa: BLE001 — Persistenz darf UI nicht crashen
            log.exception(
                "scan persistence fehlgeschlagen (%s) — Tabelle bleibt aktuell, "
                "DB-Cache nicht aktualisiert.",
                type(exc).__name__,
            )
        # Banner aktualisieren — neues last_full_scan_at
        self._refresh_freshness_banner()

    def _build_eol_banner(self) -> QFrame:
        """ID.AM-EOL-Banner (Iter 2f).

        Zeigt eine Warnung, wenn das aktuelle Inventory >=1 App enthaelt,
        deren ``recommendation`` ``"eol_no_patch"`` ist. Banner ist beim
        Bau hidden; wird in:meth:`_refresh_eol_banner` befuellt.
        """
        banner = QFrame()
        banner.setObjectName("EolBanner")
        banner.setFrameShape(QFrame.Shape.StyledPanel)
        banner.setStyleSheet(
            "QFrame#EolBanner {"
            "  background: #FFEBEE;"  # rot-pastell
            "  border: 1px solid #C62828;"
            "  border-radius: 4px;"
            "}"
        )
        layout = QHBoxLayout(banner)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)

        # EOL-Banner: kritische Severity → Material Symbol "dangerous"
        # in der DANGER-Farbe (statt Skull-Emoji).
        icon = QLabel()
        icon.setPixmap(
            get_icon("dangerous", color=theme.DANGER).pixmap(QSize(ICON_SIZE_MD, ICON_SIZE_MD))
        )
        layout.addWidget(icon)

        self._eol_banner_text = QLabel("")
        self._eol_banner_text.setWordWrap(True)
        self._eol_banner_text.setStyleSheet("color: #5D1A1A; font-weight: 600;")
        layout.addWidget(self._eol_banner_text, stretch=1)

        self._eol_filter_btn = QPushButton("Nur EOL anzeigen")
        self._eol_filter_btn.clicked.connect(self._on_eol_filter_clicked)
        layout.addWidget(self._eol_filter_btn)

        self._eol_banner = banner
        banner.setVisible(False)
        return banner

    def _refresh_eol_banner(self) -> None:
        """Aktualisiert den EOL-Banner anhand der aktuellen ``self._results``."""
        eol_count = sum(
            1
            for r in self._results
            if getattr(r, "recommendation", "") == "eol_no_patch"
        )
        if eol_count == 0:
            self._eol_banner.setVisible(False)
            return
        self._eol_banner_text.setText(
            f"<b>{eol_count}</b> installierte Anwendung(en) sind End-of-Life — "
            "Hersteller liefert keine Sicherheits-Patches mehr. Migration auf "
            "Nachfolge-Version planen."
        )
        self._eol_banner.setVisible(True)

    def _on_eol_filter_clicked(self) -> None:
        """Setzt den Tabellen-Filter auf ``eol_no_patch``-Empfehlungen.

        Filter-Key existiert seit in der Filter-Liste; wir setzen
        ihn direkt + triggern ein Repopulate.
        """
        self._filter_key = "eol_no_patch"
        if hasattr(self, "_filter_combo") and self._filter_combo is not None:
            idx = self._filter_combo.findData("eol_no_patch")
            if idx >= 0:
                self._filter_combo.setCurrentIndex(idx)
        self._populate_table()

    def apply_navigation(self, *, focus: str | None = None, **_kwargs) -> None:
        """Deeplink-Ziel (Cockpit-Inc-2): ``focus='outdated'`` zeigt die Patches
        mit verfuegbaren Updates (Filter ``needs_update``)."""
        if focus == "outdated":
            self._filter_key = "needs_update"
            if getattr(self, "_filter_combo", None) is not None:
                idx = self._filter_combo.findData("needs_update")
                if idx >= 0:
                    self._filter_combo.setCurrentIndex(idx)
            self._populate_table()

    def _refresh_module_banner(self) -> None:
        """Liest den aktuellen Modul-Status und aktualisiert den Banner.

        Wird beim ersten Show und nach jedem Onboarding-Dialog gerufen.
        """
        try:
            detail = get_winget_module_status()
        except Exception as exc:  # noqa: BLE001 — Banner darf App nicht crashen
            log.exception("module banner refresh crash: %s", exc)
            return
        if not _should_show_banner(detail.status):
            self._module_banner.setVisible(False)
            return
        self._banner_text.setText(_banner_text_for_reason(detail.reason))
        self._banner_install_btn.setEnabled(detail.can_attempt_install)
        # Diagnose-Section: Inhalt + Verfuegbarkeit
        if detail.reason_detail:
            self._banner_diagnose_label.setText(detail.reason_detail)
            self._banner_diagnose_btn.setEnabled(True)
        else:
            self._banner_diagnose_label.setText(
                f"Kein zusätzlicher Diagnose-Text. Klasse: {detail.reason}"
            )
            # Button bleibt aktiv damit User die Klasse einsehen kann.
            self._banner_diagnose_btn.setEnabled(True)
        self._module_banner.setVisible(True)

    @Slot(bool)
    def _on_diagnose_toggled(self, checked: bool) -> None:
        self._banner_diagnose_label.setVisible(checked)

    @Slot()
    def _on_banner_install_clicked(self) -> None:
        dialog = WingetModuleOnboardingDialog(parent=self)
        dialog.exec()
        self._refresh_module_banner()

    def _on_show_upgrade_history(self) -> None:
        """Oeffnet den Patch-Upgrade-Verlauf in einem Dialog (read-only Tabelle).

        Reaktiviert das Lost-Feature ``upgrade_history``: der Writer
        (``batch_upgrade_service``) persistierte laengst, es fehlte nur der
        Reader. Fail-safe: DB-Fehler blenden die History leer aus.
        """
        from tools.patch_monitor.gui.upgrade_history_view import (  # noqa: PLC0415
            UpgradeHistoryView,
        )

        repo = None
        if self._upgrade_history_repo_factory is not None:
            try:
                repo = self._upgrade_history_repo_factory()
            except Exception as exc:  # noqa: BLE001 — DB-Fehler darf den Dialog nicht crashen
                log.warning("Upgrade-History-Repo nicht verfuegbar: %s", exc)
                repo = None

        dlg = QDialog(self)
        dlg.setWindowTitle("Upgrade-Verlauf")
        dlg.resize(860, 500)
        dlg.setStyleSheet(f"QDialog {{ background: {theme.get().BG_MAIN}; }}")
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.addWidget(UpgradeHistoryView(repository=repo))
        dlg.exec()

    def _build_toolbar(self) -> QHBoxLayout:
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self._scan_btn = QPushButton("Scan starten")
        self._scan_btn.setObjectName("PrimaryButton")
        self._scan_btn.clicked.connect(self._start_scan)
        toolbar.addWidget(self._scan_btn)

        # Leichter On-Demand-Update-Check (Daily-Refresh ~30-60 s) als
        # Alternative zum Vollscan (~20 Min). Eigenes Widget-Stylesheet
        # (Outline-Factory) — der Button liegt unter dem Tool-Container,
        # der eine eigene Kaskade traegt (R23/R26).
        self._quick_check_btn = QPushButton("Schnell nach Updates suchen")
        self._quick_check_btn.setObjectName("QuickCheckButton")
        self._quick_check_btn.setStyleSheet(outline_button_qss())
        self._quick_check_btn.setToolTip(
            "Prueft nur, ob fuer bereits bekannte Produkte neue Versionen "
            "verfuegbar sind (~30-60 s) — ohne den vollstaendigen Scan."
        )
        self._quick_check_btn.clicked.connect(self._on_quick_check_clicked)
        toolbar.addWidget(self._quick_check_btn)

        # C (Live-Test 2026-07-01): Ein-Klick-Auswahl aller sichtbaren,
        # installierbaren Update-Zeilen — der Nutzer muss nach dem Quick-Check
        # nicht jede Zeile einzeln ankreuzen.
        self._select_all_btn = QPushButton("Alle Updates markieren")
        self._select_all_btn.setToolTip(
            "Kreuzt alle aktuell sichtbaren, installierbaren Updates an."
        )
        self._select_all_btn.clicked.connect(self._select_all_updates)
        toolbar.addWidget(self._select_all_btn)

        self._cancel_btn = QPushButton("Abbrechen")
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.clicked.connect(self._cancel_scan)
        toolbar.addWidget(self._cancel_btn)

        # Custom-Sources manuell anlegen — im OSS-Build für alle frei
        # (kein Pro-Tier-Gate mehr).
        self._add_source_btn = QPushButton("App hinzufuegen")
        self._add_source_btn.clicked.connect(self._on_add_custom_source)
        toolbar.addWidget(self._add_source_btn)

        self._history_btn = QPushButton("Upgrade-Verlauf")
        self._history_btn.setToolTip(
            "Zeigt die bisherigen Patch-Upgrade-Versuche (Zeit, App, Version, "
            "Status, Dauer)."
        )
        self._history_btn.clicked.connect(self._on_show_upgrade_history)
        toolbar.addWidget(self._history_btn)

        toolbar.addStretch(1)

        # Phase E2: rechtsbuendige, gedimmte Host-OS-Kopfzeile
        # (Edition/Version/Build). Bei leerer/fehlgeschlagener Erhebung bleibt
        # der Label leer und ist optisch unsichtbar (kein Crash, kein Platz).
        if self._host_os_text:
            os_label = QLabel(self._host_os_text)
            os_label.setObjectName("HostOsLabel")
            os_label.setStyleSheet(f"color: {theme.get().TEXT_DIM};")
            os_label.setToolTip("Betriebssystem dieses Geraets")
            toolbar.addWidget(os_label)
            toolbar.addSpacing(12)

        # D (Live-Test 2026-07-01): Freitext-Suche zum Einschraenken der
        # angezeigten Apps. Erbt das globale QLineEdit-Theme-QSS (core.theme,
        # Theme-Tokens, kein Inline-Hex); der ObjectName ist gesetzt, damit spaeter
        # bei Bedarf gezielt nachformatiert werden kann.
        self._search_input = QLineEdit()
        self._search_input.setObjectName("PatchSearchInput")
        self._search_input.setPlaceholderText("App suchen …")
        self._search_input.setClearButtonEnabled(True)
        self._search_input.setMaximumWidth(220)
        self._search_input.textChanged.connect(self._on_search_changed)
        toolbar.addWidget(self._search_input)
        toolbar.addSpacing(12)

        toolbar.addWidget(QLabel("Filter:"))
        self._filter_combo = QComboBox()
        for key, label in _FILTERS:
            self._filter_combo.addItem(label, userData=key)
        self._filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self._filter_combo)

        return toolbar

    def _build_progress(self) -> QWidget:
        # kanonische 8-px-Bar + separater Zaehler-Label rechts daneben.
        # 2026-05-12: In-Bar-Text war auf 8 px nicht lesbar (Patrick-Smoke).
        # Pattern analog cert_monitor / dependency_auditor.
        container = QFrame()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._progress = FinlaiProgressBar(total=100)
        self._progress.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        layout.addWidget(self._progress, stretch=1)

        self._progress_label = QLabel("")
        self._progress_label.setMinimumWidth(120)
        self._progress_label.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        self._progress_label.setStyleSheet("font-size: 12px;")
        layout.addWidget(self._progress_label)

        container.setVisible(False)
        # Aliase: alte Tests benutzen _progress.isVisibleTo(w) und setRange.
        # Wir lassen self._progress weiter den Bar-Pointer behalten und
        # haengen das Container-Visibility-Toggle an die Slots.
        self._progress_container = container
        return container

    def _build_table(self) -> QTableWidget:
        self._table = QTableWidget(0, self._COL_COUNT)
        self._table.setHorizontalHeaderLabels(
            ["", "", "App", "Version", "Quelle", "Kanal", "CVEs", "CVSS",
             "Empfehlung", "Strategie"]
        )
        h = self._table.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        h.setStretchLastSection(False)
        self._table.setColumnWidth(self._COL_CHECKBOX, 30)
        self._table.setColumnWidth(self._COL_STATUS, 40)
        self._table.setColumnWidth(self._COL_NAME, 320)
        self._table.setColumnWidth(self._COL_VERSION, 100)
        self._table.setColumnWidth(self._COL_SOURCE, 120)
        self._table.setColumnWidth(self._COL_CHANNEL, 100)
        self._table.setColumnWidth(self._COL_CVES, 60)
        self._table.setColumnWidth(self._COL_CVSS, 80)
        self._table.setColumnWidth(self._COL_RECOMMEND, 140)
        self._table.setColumnWidth(self._COL_STRATEGY, 150)
        h.setSectionResizeMode(self._COL_NAME, QHeaderView.ResizeMode.Stretch)

        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        # PM-2.x: Sortierung deaktiviert — Sortierung wuerde die
        # checkbox-Spalte mit Mixed-States kollidieren lassen
        # (User-Erwartung: ausgewaehlte Zeilen bleiben ausgewaehlt).
        self._table.setSortingEnabled(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        # PM-2.x: Checkbox-Toggle → Footer-Aktualisierung.
        self._table.itemChanged.connect(self._on_table_item_changed)
        return self._table

    def _build_footer_bar(self) -> QFrame:
        """Footer-Bar mit Selektionszaehler + Install-/Cancel-Button.

        Wird unter der Tabelle eingeblendet sobald >=1 Update selektiert
        ist. Der Cancel-Button erscheint erst waehrend einer laufenden
        Batch.
        """
        bar = QFrame()
        bar.setObjectName("UpgradeFooterBar")

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(8)

        self._select_count_label = QLabel(_format_select_count(0))
        layout.addWidget(self._select_count_label)
        layout.addStretch(1)

        self._install_btn = QPushButton("Updates installieren")
        self._install_btn.setObjectName("UpgradeInstallButton")
        self._install_btn.setEnabled(False)
        self._install_btn.clicked.connect(self._on_install_clicked)
        layout.addWidget(self._install_btn)

        self._upgrade_cancel_btn = QPushButton("Batch abbrechen")
        self._upgrade_cancel_btn.setVisible(False)
        self._upgrade_cancel_btn.clicked.connect(self._cancel_upgrade)
        layout.addWidget(self._upgrade_cancel_btn)

        return bar

    def _build_log_panel(self) -> QFrame:
        """Collapsible Live-Log-Panel fuer Batch-Output."""
        frame = QFrame()
        frame.setObjectName("UpgradeLogPanel")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        header_row = QHBoxLayout()
        header_row.setSpacing(6)
        self._log_toggle_btn = QPushButton("▸ Upgrade-Log")
        self._log_toggle_btn.setCheckable(True)
        self._log_toggle_btn.setChecked(False)
        self._log_toggle_btn.setFlat(True)
        self._log_toggle_btn.toggled.connect(self._on_log_toggled)
        header_row.addWidget(self._log_toggle_btn)
        header_row.addStretch(1)
        layout.addLayout(header_row)

        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setVisible(False)
        self._log_text.setMaximumHeight(180)
        self._log_text.setStyleSheet(
            "QTextEdit { font-family: 'JetBrains Mono'; font-size: 12px; }"
        )
        layout.addWidget(self._log_text)

        return frame

    def _build_detail_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("DetailPanel")
        panel.setFrameShape(QFrame.Shape.StyledPanel)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setPlaceholderText(
            "Eine Zeile in der Tabelle waehlen, um Details zu sehen."
        )
        self._detail_text.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        layout.addWidget(self._detail_text)
        return panel

    def _build_status_bar(self) -> QLabel:
        self._status_label = QLabel("Bereit. Klick 'Scan starten' fuer Inventar-Scan.")
        self._status_label.setObjectName("StatusBar")
        return self._status_label

    def _apply_styles(self) -> None:
        t = theme.get()
        self._scan_btn.setStyleSheet(
            f"QPushButton#PrimaryButton {{"
            f"  background: {t.ACCENT};"
            f"  color: {theme.TEXT_ON_ACCENT_DEEP};"
            f"  border: 1px solid {t.ACCENT};"
            f"  border-radius: 4px;"
            f"  padding: 6px 14px;"
            f"  font-weight: 600;"
            f"}}"
            f"QPushButton#PrimaryButton:hover {{"
            f"  background: {theme.ACCENT_HOVER_BRIGHT};"
            f"}}"
            f"QPushButton#PrimaryButton:disabled {{"
            f"  background: {t.BORDER};"
            f"  color: {t.TEXT_DIM};"
            f"  border-color: {t.BORDER};"
            f"}}"
        )
        # D: Freshness-Banner an Dark-Theme angepasst (Patrick-
        # Smoke 2026-05-12: vorher hellblauer Material-Design-Block,
        # passte nicht zum Dark-Neon-Look). CARD_BG + STATUS_INFO-Border.
        self._freshness_banner.setStyleSheet(
            f"QFrame#ScanFreshnessBanner {{"
            f"  background: {t.CARD_BG};"
            f"  border: 1px solid {t.STATUS_INFO};"
            f"  border-radius: 4px;"
            f"}}"
            f"QLabel#ScanFreshnessIcon {{"
            f"  font-size: 14px;"
            f"  color: {t.STATUS_INFO};"
            f"  background: transparent;"
            f"  border: none;"
            f"}}"
            f"QLabel#ScanFreshnessLabel {{"
            f"  color: {t.TEXT_MAIN};"
            f"  background: transparent;"
            f"  border: none;"
            f"}}"
        )

    # ------------------------------------------------------------------
    # Worker-Lifecycle
    # ------------------------------------------------------------------

    def start_initial_scan(self) -> None:
        """Loest den Erst-Vollscan aus (von MainWindow nach "Ja" im Erst-Scan-Dialog).

        Public Einstiegspunkt fuer den automatischen Start nach dem Onboarding-
        Erst-Scan-Dialog — nutzt denselben beobachtbaren ScanWorker-Pfad wie der
        "Scan starten"-Button. Laeuft bereits ein Scan, ist der Aufruf dank des
        ``_start_scan``-Guards ein No-op.
        """
        self._start_scan()

    def _start_scan(self) -> None:
        """Started den Scan-Worker in einem QThread."""
        if self._scan_thread is not None:
            log.debug("Scan laeuft bereits — Klick ignoriert.")
            return

        self._scan_thread = QThread(self)
        self._scan_worker = ScanWorker()
        self._scan_worker.moveToThread(self._scan_thread)

        # Signals: Worker → UI (alle laufen via Qt::AutoConnection,
        # also bei Cross-Thread automatisch QueuedConnection).
        self._scan_worker.scan_started.connect(self._on_scan_started)
        self._scan_worker.scan_progress.connect(self._on_scan_progress)
        self._scan_worker.scan_complete_with_results.connect(self._on_scan_complete)
        self._scan_worker.scan_failed.connect(self._on_scan_failed)
        self._scan_worker.scan_complete.connect(self._scan_thread.quit)
        self._scan_worker.scan_failed.connect(
            lambda _msg: self._scan_thread.quit() if self._scan_thread else None
        )
        # Wenn der Thread fertig ist, raeumen wir ihn auf.
        self._scan_thread.finished.connect(self._cleanup_thread)
        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_thread.start(QThread.Priority.LowPriority)
        self.request_scan.emit()

    def _cancel_scan(self) -> None:
        if self._scan_worker is not None:
            self._scan_worker.cancel()
        self._cancel_btn.setEnabled(False)

    def _cleanup_thread(self) -> None:
        if self._scan_worker is not None:
            self._scan_worker.deleteLater()
            self._scan_worker = None
        if self._scan_thread is not None:
            self._scan_thread.deleteLater()
            self._scan_thread = None

    # ------------------------------------------------------------------
    # Slots — Worker → UI (alle public + @Slot fuer Qt-Bind-Sicherheit)
    # ------------------------------------------------------------------

    @Slot()
    def on_scan_started(self) -> None:
        """Reagiert auf ScanWorker.scan_started.

        Setzt UI in den Lauf-Zustand: Buttons toggeln, Progressbar
        einblenden, Tabelle leeren.
        """
        self._scan_btn.setEnabled(False)
        self._quick_check_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress_container.setVisible(True)
        self._progress.setRange(0, 0)  # indeterminate bis erstes Tick
        self._progress.setValue(0)
        self._progress_label.setText("Scan laeuft …")
        self._table.setRowCount(0)
        self._status_label.setText("Scan laeuft …")
        # PM-2.x: alte Live-Status-Overlays + Selektions-Zaehler resetten
        self._upgrade_status_by_id.clear()
        self._update_footer_state()

    @Slot(int, int)
    def on_scan_progress(self, current: int, total: int) -> None:
        """Reagiert auf ScanWorker.scan_progress.

        Schaltet Progressbar von indeterminate auf determinate, sobald
        ``total`` bekannt ist.
        """
        if total > 0:
            self._progress.setRange(0, total)
            self._progress.setValue(current)
            pct = int(current * 100 / total) if total else 0
            self._progress_label.setText(f"{current} / {total}  ({pct} %)")

    @Slot(list)
    def on_scan_complete(self, results: list[PatchScanResult]) -> None:
        """Reagiert auf ScanWorker.scan_complete_with_results.

        Befuellt Tabelle, aktualisiert Statuszeile, Buttons und
        Progressbar zuruecksetzen.
        """
        self._results = list(results)
        self._populate_table()
        self._status_label.setText(_format_status_line(self._results))
        self._scan_btn.setEnabled(True)
        self._quick_check_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress_container.setVisible(False)
        self._progress.setValue(0)
        self._progress_label.setText("")
        # PM-2.x: nach frischer Tabelle ist nichts ausgewaehlt → Footer-State
        self._update_footer_state()
        # Stop-Step D: Persistiere den Scan-Stand fuer Tier-Modell
        # (load_from_db beim naechsten Open, daily_refresh kennt CPE-Set).
        self._persist_scan_results(self._results)

    @Slot(str)
    def on_scan_failed(self, error: str) -> None:
        """Reagiert auf ScanWorker.scan_failed."""
        self._status_label.setText(f"Scan fehlgeschlagen: {error}")
        self._scan_btn.setEnabled(True)
        self._quick_check_btn.setEnabled(True)
        self._cancel_btn.setEnabled(False)
        self._progress_container.setVisible(False)
        self._progress_label.setText("")

    # Aliase mit underscore — interne Convention; Worker connect
    # nutzt diese.
    _on_scan_started = on_scan_started
    _on_scan_progress = on_scan_progress
    _on_scan_complete = on_scan_complete
    _on_scan_failed = on_scan_failed

    # ------------------------------------------------------------------
    # Tabelle befuellen + Filter
    # ------------------------------------------------------------------

    @Slot()
    def _on_filter_changed(self) -> None:
        self._filter_key = self._filter_combo.currentData() or "all"
        self._populate_table()

    @Slot(str)
    def _on_search_changed(self, text: str) -> None:
        """Freitext-Filter (D): normalisiert den Suchbegriff und repopuliert."""
        self._search_text = text.strip().casefold()
        self._populate_table()

    def _populate_table(self) -> None:
        # PM-2.x: Sortierung bleibt aus (Checkbox-Spalte wuerde springen),
        # itemChanged-Signals waehrend Bulk-Fuellen blocken.
        self._table.blockSignals(True)
        self._table.setRowCount(0)
        for result in self._results:
            # Kategorie-Filter UND Freitext-Suche muessen beide durchlaufen (D).
            if not _passes_filter(result, self._filter_key):
                continue
            if not _passes_search(result, self._search_text):
                continue
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._fill_row(row, result)
        self._table.blockSignals(False)
        self._update_footer_state()
        # Iter 2f: EOL-Banner nach jedem Table-Refresh aktualisieren.
        self._refresh_eol_banner()

    @Slot()
    def _select_all_updates(self) -> None:
        """Hakt alle aktuell sichtbaren, installierbaren Update-Zeilen an (C).

        Nur Zeilen mit aktiver Checkbox (``_is_upgradeable`` → ItemIsUserCheckable
        in:meth:`_fill_row`) werden gesetzt; Registry-/MSIX-/Windows-Update-
        Zeilen ohne Checkbox bleiben unberuehrt. Signals werden waehrend des
        Bulk-Setzens geblockt, der Footer danach genau einmal aktualisiert.
        """
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            check_item = self._table.item(row, self._COL_CHECKBOX)
            if check_item is None:
                continue
            if not (check_item.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                continue
            if check_item.checkState() is not Qt.CheckState.Checked:
                check_item.setCheckState(Qt.CheckState.Checked)
        self._table.blockSignals(False)
        self._update_footer_state()

    def _fill_row(self, row: int, result: PatchScanResult) -> None:
        # 0 — Checkbox (PM-2.x). Nur aktiviert wenn upgradeable.
        check_item = QTableWidgetItem("")
        if _is_upgradeable(result):
            check_item.setFlags(
                Qt.ItemFlag.ItemIsUserCheckable
                | Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
            )
            check_item.setCheckState(Qt.CheckState.Unchecked)
        else:
            # Greyed-out: kein CheckState → keine Checkbox sichtbar.
            check_item.setFlags(Qt.ItemFlag.ItemIsSelectable)
        # PatchScanResult auch hier als UserRole hinterlegen, damit
        # _collect_selected_requests die Zeile sauber rueckabwickeln kann.
        check_item.setData(Qt.ItemDataRole.UserRole, result)
        self._table.setItem(row, self._COL_CHECKBOX, check_item)

        # 1 — Status-Icon (mit ggf. Upgrade-Live-Overlay)
        live_status = self._upgrade_status_by_id.get(result.winget_id or "")
        if live_status == "running":
            icon_name = _UPGRADE_RUNNING_ICON
            color = _UPGRADE_RUNNING_COLOR
        elif isinstance(live_status, UpgradeStatus):
            icon_name = _UPGRADE_LIVE_ICON[live_status]
            color = _UPGRADE_LIVE_COLOR[live_status]
        else:
            icon_name = _REC_ICON.get(result.recommendation, Icons.HELP)
            color = _rec_color(result.recommendation)
        item = QTableWidgetItem()
        item.setIcon(get_icon(icon_name, color=color))
        item.setData(Qt.ItemDataRole.UserRole, result)
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        # action_text aus dem Recommendation-Engine-Pass als
        # Tooltip — User sieht beim Hover die Begruendung der erweiterten
        # Empfehlung (z. B. EOL-Datum + Migrations-Vorschlag, CSAF-
        # Workaround-Hinweis). Quelle bleibt im Audit-Trail.
        if result.action_text:
            item.setToolTip(result.action_text)
        self._table.setItem(row, self._COL_STATUS, item)

        # 2 — App-Name
        self._table.setItem(row, self._COL_NAME, QTableWidgetItem(result.name))

        # 3 — Version
        self._table.setItem(
            row,
            self._COL_VERSION,
            QTableWidgetItem(result.installed_version),
        )

        # 4 — Quelle (Herkunft der Erkennung: winget / Registry / Windows-Update …)
        src_item = QTableWidgetItem(_source_label(result.source))
        src_item.setToolTip(_source_tooltip(result.source))
        self._table.setItem(row, self._COL_SOURCE, src_item)

        # 4 — Kanal: editierbarer Selektor fuer winget-Apps, sonst Badge.
        self._fill_channel_cell(row, result)

        # 5 — CVE-Anzahl
        cves_item = QTableWidgetItem(str(len(result.cve_ids)))
        cves_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, self._COL_CVES, cves_item)

        # 6 — CVSS max (Ampel)
        cvss_text = f"{result.cvss_max:.1f}" if result.cvss_max is not None else "-"
        cvss_item = QTableWidgetItem(cvss_text)
        cvss_item.setForeground(QColor(_cvss_color(result.cvss_max)))
        cvss_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self._table.setItem(row, self._COL_CVSS, cvss_item)

        # 7 — Empfehlung (mit-Tooltip)
        rec_item = QTableWidgetItem(result.recommendation)
        if result.action_text:
            rec_item.setToolTip(result.action_text)
        self._table.setItem(row, self._COL_RECOMMEND, rec_item)

        # 8 — Strategie-Dropdown. Nur fuer Catalog-Apps mit winget_id;
        # Items ohne winget_id (Registry/MSIX/notify_only) haben keine
        # Strategie und bekommen einen gedimmten Platzhalter.
        self._fill_strategy_cell(row, result)

    def _fill_channel_cell(self, row: int, result: PatchScanResult) -> None:
        """Setzt den Channel-Selektor bzw. einen read-only Badge.

        Fuer winget-Apps ein QComboBox (notify_only/patch_only/stable/latest/
        pinned) -> der User kann eine ``notify_only``-App auf einen patchbaren
        Kanal stellen (behebt das Dead-End: notify_only-Apps waren nie batch-
        upgradebar). Items ohne ``winget_id`` (Registry/Custom) sind ohnehin
        nicht upgradebar -> read-only Badge wie bisher.
        """
        if not result.winget_id:
            ch_item = QTableWidgetItem(result.channel)
            ch_item.setBackground(QColor(_channel_color(result.channel)))
            ch_item.setForeground(QColor("#ffffff"))
            ch_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, self._COL_CHANNEL, ch_item)
            return
        combo = QComboBox()
        for ch, label in _CHANNEL_LABELS.items():
            combo.addItem(label, ch)
        idx = combo.findData(result.channel)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        name = result.name
        winget_id = result.winget_id
        # ``activated`` feuert NUR bei User-Auswahl (nicht bei setCurrentIndex) —
        # kein Re-Entry beim Aufbau. name/winget_id per Default-Arg gebunden.
        combo.activated.connect(
            lambda _idx, c=combo, n=name, w=winget_id: self._on_channel_changed(
                n, w, c.currentData()
            )
        )
        self._table.setCellWidget(row, self._COL_CHANNEL, combo)

    def _fill_strategy_cell(self, row: int, result: PatchScanResult) -> None:
        """Setzt das Strategie-Dropdown bzw. einen Platzhalter."""
        if not result.winget_id:
            placeholder = QTableWidgetItem("—")  # em-dash
            placeholder.setForeground(QColor(theme.get().TEXT_DIM))
            placeholder.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, self._COL_STRATEGY, placeholder)
            return
        combo = QComboBox()
        for strat, label in _STRATEGY_LABELS.items():
            combo.addItem(label, strat)
        idx = combo.findData(result.patch_strategy)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        winget_id = result.winget_id
        # ``activated`` feuert NUR bei User-Auswahl (nicht bei setCurrentIndex
        # oben), darum kein Re-Entry beim Aufbau. winget_id per Default-Arg
        # gebunden (kein Late-Binding ueber die Schleife).
        # Qt castet StrEnum-userData zu plain str — der rohe Wert wird
        # bewusst durchgereicht; set_strategy normalisiert via Value-Lookup
        # INNERHALB des try/except von _on_strategy_changed.
        combo.activated.connect(
            lambda _idx, c=combo, w=winget_id: self._on_strategy_changed(
                w, c.currentData()
            )
        )
        self._table.setCellWidget(row, self._COL_STRATEGY, combo)

    # ------------------------------------------------------------------
    # Detail-Panel
    # ------------------------------------------------------------------

    @Slot()
    def _on_selection_changed(self) -> None:
        items = self._table.selectedItems()
        if not items:
            self._detail_text.clear()
            return
        # PM-2.x: Status-Spalte (Col 1) enthaelt UserRole-PatchScanResult
        # — Checkbox (Col 0) traegt es zwar auch, aber die Status-Spalte
        # ist der historische Anchor (Detail-Panel) und bleibt es.
        first_in_row = self._table.item(items[0].row(), self._COL_STATUS)
        if first_in_row is None:
            return
        result = first_in_row.data(Qt.ItemDataRole.UserRole)
        if isinstance(result, PatchScanResult):
            self._detail_text.setHtml(_render_detail_html(result))

    # ------------------------------------------------------------------
    # PM-2.x — Selektion, Confirm-Dialog, Batch-Worker
    # ------------------------------------------------------------------

    @Slot("QTableWidgetItem*")
    def _on_table_item_changed(self, item: QTableWidgetItem) -> None:
        """Reagiert auf Checkbox-Toggle in der Checkbox-Spalte.

        Wird auch bei anderen Item-Modifikationen gefeuert — wir
        filtern auf die Checkbox-Spalte. Aktualisiert Footer-Label +
        Install-Button-State.
        """
        if item.column() != self._COL_CHECKBOX:
            return
        self._update_footer_state()

    def _on_strategy_changed(
        self, winget_id: str, strategy: PatchStrategy | str
    ) -> None:
        """Persistiert die neu gewaehlte Patch-Strategie.

        ``strategy`` kommt aus Qt-userData und ist daher meist ein plain
        ``str`` (Qt unwrappt StrEnum) — ``set_strategy`` normalisiert
        via Value-Lookup; eine ValueError landet im except unten.

        NONE aendert die Empfehlung auf ``skipped_by_user`` und deaktiviert
        die Upgrade-Checkbox — darum wird die Tabelle nach dem Persistieren
        aus der DB neu geladen. Der Reload wird via ``QTimer.singleShot(0)``
        verzoegert, damit das ausloesende QComboBox nicht mitten in seiner
        eigenen ``activated``-Signalverarbeitung zerstoert wird.
        """
        service = self._get_inventory_service()
        if service is None:
            return
        try:
            service.set_strategy(winget_id, strategy)
        except Exception as exc:  # noqa: BLE001 — Persistenz darf UI nicht crashen
            log.exception("set_strategy(%s) fehlgeschlagen: %s", winget_id, exc)
            return
        QTimer.singleShot(0, self._reload_results_from_db)

    def _on_channel_changed(
        self, name: str, winget_id: str, channel: str
    ) -> None:
        """Persistiert den User-Channel-Override + Tabelle neu ableiten.

        Setzt den dauerhaften Override (PolicyDB) + das Sofort-Update der
        Inventar-Zeile (``set_channel_override``) und laedt danach aus der DB neu
        — die Empfehlung wird mit dem neuen Kanal frisch abgeleitet (eine zuvor
        ``notify_only``-App wird so upgradebar). Reload via ``QTimer.singleShot(0)``,
        damit das ausloesende QComboBox nicht mitten in seiner ``activated``-
        Signalverarbeitung zerstoert wird (wie beim Strategie-Dropdown).
        """
        service = self._get_inventory_service()
        if service is None:
            return
        try:
            service.set_channel_override(name, winget_id, channel)
        except Exception as exc:  # noqa: BLE001 — Persistenz darf UI nicht crashen
            log.exception(
                "set_channel_override(%s) fehlgeschlagen: %s", name, exc
            )
            return
        QTimer.singleShot(0, self._reload_results_from_db)

    def _reload_results_from_db(self) -> None:
        """Laedt den Stand aus der DB neu und rendert die Tabelle.

        Konsistenz-Refresh nach User-Aktionen (Strategie-Aenderung,
        Custom-Source-Anlage): Empfehlung, Status-Icon, Checkbox-State
        und Custom-Source-Zeilen spiegeln den persistierten Stand.
        """
        service = self._get_inventory_service()
        if service is None:
            return
        try:
            self._results = service.load_from_db()
        except Exception as exc:  # noqa: BLE001 — Reload darf UI nicht crashen
            log.exception("Reload nach Strategie-Aenderung fehlgeschlagen: %s", exc)
            return
        self._populate_table()

    # ------------------------------------------------------------------
    # On-Demand-Quick-Check (leichter Daily-Refresh statt Vollscan)
    # ------------------------------------------------------------------

    @Slot()
    def _on_quick_check_clicked(self) -> None:
        """Loest den leichten Update-Check on-demand aus.

        Anders als "Scan starten" (Vollscan ~20 Min inkl. CVE-Abfrage pro
        Paket) prueft dieser Pfad nur, ob fuer die bereits bekannten
        Produkte neue Versionen verfuegbar sind (~30-60 s). Der eigentliche
        Refresh laeuft im MainWindow-Worker (eigener Thread); das Widget
        signalisiert nur den Wunsch und wartet auf
:meth:`reload_after_refresh` bzw.:meth:`quick_check_failed`.
        """
        if self._scan_thread is not None:
            # Ein laufender Vollscan deckt den Update-Check bereits ab.
            self._status_label.setText("Es laeuft bereits ein Scan.")
            return
        if not self._results:
            # Ohne Inventar gibt es nichts abzugleichen — Erst-Scan noetig.
            self._status_label.setText(
                "Noch kein Inventar vorhanden — starte zuerst einen Scan."
            )
            return
        self._quick_check_btn.setEnabled(False)
        # C: Dieser Reload kommt vom Nutzer — danach die gefundenen Updates
        # sichtbar machen (Filter-Sprung), im Gegensatz zum Scheduler-Refresh.
        self._quick_check_pending = True
        self._status_label.setText("Suche nach neuen Updates …")
        self.request_quick_check.emit()

    @Slot()
    def reload_after_refresh(self) -> None:
        """Aktualisiert die Ansicht nach einem Daily-Refresh.

        Wird vom MainWindow nach ``daily_refresh_finished`` duck-typed
        aufgerufen — sowohl beim on-demand ausgeloesten Quick-Check als
        auch beim automatischen 24-h-Refresh des Schedulers. Laedt die
        Tabelle aus der DB neu, aktualisiert das Freshness-Banner und gibt
        den Quick-Check-Button wieder frei.
        """
        self._quick_check_btn.setEnabled(True)
        self._reload_results_from_db()
        self._refresh_freshness_banner()
        # C (Live-Test 2026-07-01): War der Reload durch einen ON-DEMAND-
        # Quick-Check ausgeloest, die gefundenen Updates direkt zeigen.
        if self._quick_check_pending:
            self._quick_check_pending = False
            self._show_found_updates()
        else:
            self._status_label.setText(_format_status_line(self._results))

    def _show_found_updates(self) -> None:
        """Bringt nach einem Quick-Check die gefundenen Updates vor Augen (C).

        Schaltet auf den Filter „Updates verfuegbar" (nur Update-Zeilen sichtbar),
        weist in der Statuszeile aufs Markieren + Installieren hin UND oeffnet ein
        Popup mit den patchbaren Apps + Konfig + Direkt-Installation (Live-Test
        2026-07-02). Ohne gefundene Updates bleibt die normale Statuszeile stehen.
        """
        updates = self._current_update_results()
        if not updates:
            self._status_label.setText(_format_status_line(self._results))
            return
        # Bestehenden Deeplink-Pfad wiederverwenden: setzt Filter-Key +
        # Combo-Index auf „needs_update" und repopuliert die Tabelle — der
        # Haupt-Monitor zeigt danach dieselben Updates wie das Popup.
        self.apply_navigation(focus="outdated")
        self._status_label.setText(
            f"{len(updates)} Update(s) gefunden — markieren Sie die gewuenschten "
            "(oder 'Alle Updates markieren') und klicken Sie 'Updates installieren'."
        )
        self._open_quick_updates_dialog(updates)

    def _current_update_results(self) -> list[PatchScanResult]:
        """Die aktuell aktualisierbaren Zeilen (Filter „needs_update")."""
        return [r for r in self._results if _passes_filter(r, "needs_update")]

    def _reload_updates_for_dialog(self) -> list[PatchScanResult]:
        """Reload nach Konfig-Aenderung im Popup: Haupt-Monitor + frische Liste.

        Laedt den Stand aus der DB neu (aktualisiert ``_results`` + Haupttabelle,
        damit Kanal-/Strategie-Aenderungen aus dem Popup im Haupt-Monitor sichtbar
        werden) und gibt die frische Update-Teilmenge fuer das Popup zurueck.
        """
        self._reload_results_from_db()
        return self._current_update_results()

    def _install_results_from_dialog(
        self, results: list[PatchScanResult]
    ) -> None:
        """Startet die Installations-Pipeline fuer die im Popup gewaehlten Zeilen."""
        requests = [_to_upgrade_request(r) for r in results if _is_upgradeable(r)]
        self._confirm_and_start_upgrade(requests)

    def _open_quick_updates_dialog(
        self, updates: list[PatchScanResult]
    ) -> None:
        """Oeffnet das Quick-Update-Popup (Live-Test 2026-07-02).

        Lazy-Import vermeidet einen Import-Zyklus: das Popup bekommt die
        Modul-Helfer dieses Widgets ueber Konstruktor-Parameter, importiert sie
        also nicht selbst.
        """
        service = self._get_inventory_service()
        if service is None:
            return
        from tools.patch_monitor.gui.quick_updates_dialog import QuickUpdatesDialog

        # Non-blocking oeffnen (show statt exec): das ausloesende
        # _show_found_updates darf nicht in einem nested Event-Loop haengen
        # bleiben (Testbarkeit + Qt-Freeze-Vermeidung). Referenz halten, damit
        # der Dialog nicht sofort vom Garbage Collector eingesammelt wird.
        self._quick_updates_dialog = QuickUpdatesDialog(
            updates=updates,
            channel_labels=_CHANNEL_LABELS,
            strategy_labels=_STRATEGY_LABELS,
            is_upgradeable=_is_upgradeable,
            source_label=_source_label,
            service=service,
            on_reload=self._reload_updates_for_dialog,
            on_install=self._install_results_from_dialog,
            parent=self,
        )
        self._quick_updates_dialog.show()

    @Slot(str)
    def quick_check_failed(self, message: str) -> None:
        """Reaktiviert den Quick-Check-Button nach Fehler/Busy.

        Wird vom MainWindow aufgerufen, wenn der Daily-Refresh fehlschlug
        oder der Worker bereits beschaeftigt war.

        Args:
            message: Anzuzeigender Hinweis (Sie-Form). Leer → kein Update
                der Statuszeile.
        """
        self._quick_check_btn.setEnabled(True)
        if message:
            self._status_label.setText(message)

    @Slot()
    def _on_add_custom_source(self) -> None:
        """Oeffnet den Custom-Source-Dialog und legt die Quelle an.

        Custom-Sources sind seit für alle frei — kein
        Pro-Tier-Gate mehr in Button oder Service.
        """
        dialog = CustomSourceDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        service = self._get_inventory_service()
        if service is None:
            return
        try:
            source = service.add_custom_source(**dialog.form_values())
        except Exception as exc:  # noqa: BLE001 — UI darf nicht crashen
            log.exception("add_custom_source fehlgeschlagen: %s", exc)
            self._status_label.setText("Custom-Source konnte nicht angelegt werden.")
            return
        self._status_label.setText(f"Custom-Source hinzugefuegt: {source.name}")
        # Neu laden, damit die Custom-Source als notify_only-Zeile erscheint
        # (available_version wird erst beim naechsten Refresh-Check befuellt).
        self._reload_results_from_db()

    def _update_footer_state(self) -> None:
        """Aktualisiert Footer-Label + Install-Button nach Selektions-
        oder Worker-Status-Aenderung."""
        selected = self._collect_selected_requests()
        n = len(selected)
        self._select_count_label.setText(_format_select_count(n))
        # Install-Button nur enabled wenn N>0 UND kein Batch laeuft.
        running = self._upgrade_thread is not None
        self._install_btn.setEnabled(n > 0 and not running)

    def _collect_selected_requests(self) -> list[UpgradeRequest]:
        """Liest die aktuell angekreuzten Zeilen und baut Requests."""
        requests: list[UpgradeRequest] = []
        for row in range(self._table.rowCount()):
            check_item = self._table.item(row, self._COL_CHECKBOX)
            if check_item is None:
                continue
            if check_item.checkState() != Qt.CheckState.Checked:
                continue
            result = check_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(result, PatchScanResult) and _is_upgradeable(result):
                requests.append(_to_upgrade_request(result))
        return requests

    @Slot(bool)
    def _on_log_toggled(self, checked: bool) -> None:
        """Klappt das Live-Log-Panel auf/zu."""
        self._log_text.setVisible(checked)
        self._log_toggle_btn.setText("▾ Upgrade-Log" if checked else "▸ Upgrade-Log")

    @Slot()
    def _on_install_clicked(self) -> None:
        """Oeffnet den Confirm-Dialog und startet bei Accept den Worker."""
        requests = self._collect_selected_requests()
        if not requests:
            return
        self._confirm_and_start_upgrade(requests)

    def _confirm_and_start_upgrade(self, requests: list[UpgradeRequest]) -> None:
        """Bestaetigt (UpgradeConfirmDialog) und startet bei Accept den Batch-Worker.

        Gemeinsamer Pfad fuer den Install-Button der Haupttabelle UND das
        Quick-Update-Popup (Live-Test 2026-07-02): baut auf denselben
:class:`UpgradeConfirmDialog` +:meth:`_start_upgrade`, damit die
        Batch-Pipeline nicht dupliziert wird.
        """
        if not requests:
            return
        dialog = UpgradeConfirmDialog(requests=requests, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._start_upgrade(requests)

    def _start_upgrade(self, requests: list[UpgradeRequest]) -> None:
        """Startet den:class:`UpgradeWorker` in einem neuen QThread."""
        if self._upgrade_thread is not None:
            log.debug("Upgrade-Batch laeuft bereits — Klick ignoriert.")
            return

        self._upgrade_thread = QThread(self)
        self._upgrade_worker = UpgradeWorker(requests=requests)
        self._upgrade_worker.moveToThread(self._upgrade_thread)

        self._upgrade_worker.batch_started.connect(self._on_batch_started)
        self._upgrade_worker.item_started.connect(self._on_upgrade_item_started)
        self._upgrade_worker.item_finished.connect(self._on_upgrade_item_finished)
        self._upgrade_worker.batch_done.connect(self._on_batch_done)
        self._upgrade_worker.batch_failed.connect(self._on_batch_failed)

        # Thread-Lifecycle: nach batch_done / batch_failed → thread.quit
        self._upgrade_worker.batch_done.connect(
            lambda _s: self._upgrade_thread.quit() if self._upgrade_thread else None
        )
        self._upgrade_worker.batch_failed.connect(
            lambda _m: self._upgrade_thread.quit() if self._upgrade_thread else None
        )
        self._upgrade_thread.finished.connect(self._cleanup_upgrade_thread)
        self._upgrade_thread.started.connect(self._upgrade_worker.run)

        # UI in Lauf-Zustand setzen
        self._install_btn.setEnabled(False)
        self._upgrade_cancel_btn.setVisible(True)
        self._scan_btn.setEnabled(False)
        # Log-Panel aufklappen damit User Verlauf sieht
        if not self._log_toggle_btn.isChecked():
            self._log_toggle_btn.setChecked(True)
        self._log_text.append(f"--- Batch gestartet ({len(requests)} Aktionen) ---")

        self._upgrade_thread.start(QThread.Priority.LowPriority)

    @Slot()
    def _cancel_upgrade(self) -> None:
        if self._upgrade_worker is not None:
            self._upgrade_worker.cancel()
        self._upgrade_cancel_btn.setEnabled(False)
        self._log_text.append("--- Abbruch angefordert ---")

    def _cleanup_upgrade_thread(self) -> None:
        if self._upgrade_worker is not None:
            self._upgrade_worker.deleteLater()
            self._upgrade_worker = None
        if self._upgrade_thread is not None:
            self._upgrade_thread.deleteLater()
            self._upgrade_thread = None
        # UI-State zuruecksetzen
        self._upgrade_cancel_btn.setVisible(False)
        self._upgrade_cancel_btn.setEnabled(True)
        self._scan_btn.setEnabled(True)
        self._update_footer_state()

    # ----- Upgrade-Worker-Signals → UI -----

    @Slot(int)
    def _on_batch_started(self, total: int) -> None:
        self._status_label.setText(f"Upgrade-Batch laeuft ({total} Aktionen)…")

    @Slot(int, int, object)
    def _on_upgrade_item_started(
        self, index: int, total: int, req: UpgradeRequest
    ) -> None:
        self._upgrade_status_by_id[req.winget_id] = "running"
        self._refresh_row_status(req.winget_id)
        self._log_text.append(_format_log_line_started(index, total, req))

    @Slot(int, int, object, object)
    def _on_upgrade_item_finished(
        self,
        index: int,
        total: int,
        req: UpgradeRequest,
        result: UpgradeResult,
    ) -> None:
        self._upgrade_status_by_id[req.winget_id] = result.status
        self._refresh_row_status(req.winget_id)
        self._log_text.append(_format_log_line_finished(index, total, req, result))

    @Slot(object)
    def _on_batch_done(self, summary: BatchSummary) -> None:
        self._status_label.setText(_format_batch_summary(summary))
        self._log_text.append(f"--- {_format_batch_summary(summary)} ---")

    @Slot(str)
    def _on_batch_failed(self, error: str) -> None:
        self._status_label.setText(f"Batch fehlgeschlagen: {error}")
        self._log_text.append(f"!!! Batch fehlgeschlagen: {error}")

    def _refresh_row_status(self, winget_id: str) -> None:
        """Aktualisiert die Status-Glyph einer Zeile mit dem Live-Overlay."""
        for row in range(self._table.rowCount()):
            status_item = self._table.item(row, self._COL_STATUS)
            if status_item is None:
                continue
            result = status_item.data(Qt.ItemDataRole.UserRole)
            if not isinstance(result, PatchScanResult):
                continue
            if result.winget_id != winget_id:
                continue
            live = self._upgrade_status_by_id.get(winget_id)
            if live == "running":
                icon_name = _UPGRADE_RUNNING_ICON
                color = _UPGRADE_RUNNING_COLOR
            elif isinstance(live, UpgradeStatus):
                icon_name = _UPGRADE_LIVE_ICON[live]
                color = _UPGRADE_LIVE_COLOR[live]
            else:
                icon_name = _REC_ICON.get(result.recommendation, Icons.HELP)
                color = _rec_color(result.recommendation)
            status_item.setIcon(get_icon(icon_name, color=color))

    # ------------------------------------------------------------------
    # Onboarding (Bug-Fix-Sprint C-3 Option D)
    # ------------------------------------------------------------------

    def showEvent(self, event) -> None:  # noqa: ANN001 - Qt-Signatur
        """Triggert Onboarding-Check, Banner-Refresh und DB-Load beim Show.

        Onboarding-Dialog laeuft genau einmal pro Widget-Instanz
        (``_onboarding_checked``-Flag). Banner-Refresh laeuft bei jedem
        Show — damit Status-Aenderungen (z.B. Modul nachtraeglich via
        Settings-Tab installiert) sofort sichtbar werden.

 Stop-Step D: beim ersten Show wird der persistierte
        Patch-Stand aus der DB geladen (``load_from_db``). Das ersetzt
        den frueheren "leere Tabelle bis User Scan klickt"-Pfad —
        statt 20 min auf einen Vollscan zu warten sieht der User sofort
        den letzten bekannten Stand. Plus: Freshness-Banner mit
        "Letzter Vollscan vor N Tagen".
        """
        super().showEvent(event)
        if not self._onboarding_checked:
            self._onboarding_checked = True
            self._maybe_show_onboarding()
        self._refresh_module_banner()
        self._load_from_db_if_first_show()
        self._refresh_freshness_banner()

    def _maybe_show_onboarding(self) -> None:
        """Prueft Marker + Detection-Status und zeigt ggf. den Dialog.

        Fail-open: jede Exception aus Detection oder Marker-Read wird
        geloggt, der User bekommt keinen Dialog (Patch-Monitor laeuft
        im Fallback-Pfad). Der naechste Open versucht's wieder.
        """
        try:
            module_status = get_winget_module_status().status
            marker = load_marker()
        except Exception as exc:  # noqa: BLE001
            log.exception("onboarding precheck crash: %s", exc)
            return
        if not should_show_onboarding(module_status, marker):
            return
        dialog = WingetModuleOnboardingDialog(parent=self)
        dialog.exec()
        # Banner sofort an neuen Status anpassen (Refresh in showEvent
        # passiert nur einmalig bevor der Dialog laeuft).
        self._refresh_module_banner()


# ---------------------------------------------------------------------------
# Detail-Rendering — modul-funktion, testbar ohne Widget
# ---------------------------------------------------------------------------


def _render_detail_html(result: PatchScanResult) -> str:
    """HTML-Repraesentation fuer das Detail-Panel."""
    lines: list[str] = []

    def row(label: str, value: str) -> None:
        lines.append(
            f'<tr><td style="padding-right:14px;color:#80CBC4;">'
            f"{label}</td><td>{value}</td></tr>"
        )

    cvss_text = f"{result.cvss_max:.1f}" if result.cvss_max is not None else "—"
    vendor = result.vendor or "—"
    # PatchScanResult haelt keine cpe direkt — wir leiten ueber
    # winget_id oder vendor ab (CPE selbst lebt in der vorgelagerten
    # ChannelDecision; ein P2-Enhancement koennte sie hier mitfuehren).
    cpe_repr = result.winget_id or vendor

    lines.append("<table cellspacing='0' cellpadding='2'>")
    row("App", f"<b>{result.name}</b> {result.installed_version}")
    row("Kanal", result.channel)
    row("Policy", f"{result.policy_source} (confidence={result.confidence_score:.2f})")
    row("Quelle", result.source)
    row("Vendor", vendor)
    row("CPE-Hinweis", cpe_repr)
    row("Empfehlung", f"<b>{result.recommendation}</b>")
    row("CVSS max", cvss_text)
    row("Exploit", "JA" if result.exploit_available else "—")
    row("EOL", "JA" if result.eol else "—")
    lines.append("</table>")

    if result.cve_ids:
        lines.append(f"<p><b>CVEs ({len(result.cve_ids)}):</b></p><ul>")
        for cve_id in result.cve_ids[:20]:
            lines.append(f"<li>{cve_id}</li>")
        if len(result.cve_ids) > 20:
            lines.append(f"<li>… und {len(result.cve_ids) - 20} weitere</li>")
        lines.append("</ul>")
    else:
        lines.append("<p><i>Keine CVEs gefunden / kein CPE — manuell pruefen.</i></p>")

    return "\n".join(lines)
