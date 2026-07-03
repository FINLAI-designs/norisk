"""
briefing_tab — KI-Briefing Tab für das Cyberrisiko-Dashboard.

Zeigt zwei Spalten: links techstack-bezogene Meldungen, rechts allgemeine.
Einträge sind kompakte Zeilen (Produkt-Badge + CVE-ID + 1 Satz) — kein
klassischer Chatbot-Output.

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.feed_settings import load_feed_settings, save_feed_settings
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.ollama_utils import ensure_ollama_running, is_ollama_running
from core.widgets.finlai_progress import FinlaiProgressBar
from core.widgets.ki_disclaimer import KiDisclaimerWidget
from tools.cyber_dashboard.application.briefing_service import (
    FEHLER_HTTP_PREFIX,
    FEHLER_LEERER_STREAM,
    FEHLER_MODELL_FEHLT,
    FEHLER_TIMEOUT,
    BriefingService,
)
from tools.cyber_dashboard.application.dashboard_service import DashboardService
from tools.cyber_dashboard.application.phishing_briefing import (
    waehle_phishing_kandidaten,
)

log = get_logger(__name__)

_TECHSTACK_LEER_HINT = (
    "Kein Techstack eingetragen. Füge deine Systeme im Techstack-Tool "
    "hinzu, um personalisierte Warnungen zu bekommen."
)
_KEINE_TREFFER_HINT = "Keine techstack-bezogenen Meldungen im aktuellen Datensatz."
_KEINE_PHISHING_HINT = "Keine aktuellen Phishing-Warnungen im Datensatz."
_KEINE_CONSUMER_HINT = (
    "Keine Consumer-Software-Advisories erreichbar. Prüfe Internet-Verbindung "
    "oder Feed-Konfiguration in den Einstellungen."
)

# noqa: domain-source-badges — Quellen-Badge-Farben sind bewusste Marken-/Domain-
# Farben (BSI=Blau, MSRC=Microsoft-Blau, Chrome=Google-Grün, Mozilla=Firefox-Orange).
# NICHT in core/theme.py — eigene semantische Achse pro Consumer-Source.
_QUELLE_FARBEN: dict[str, str] = {
    "BSI": "#2a4a6e",  # noqa: domain-source-badge-bsi
    "MSRC": "#0a5c8a",  # noqa: domain-source-badge-msrc-microsoft
    "Chrome": "#3b6e2a",  # noqa: domain-source-badge-chrome-google
    "Mozilla": "#8a4a0a",  # noqa: domain-source-badge-mozilla-firefox
}


def _abfrage_installierte_modelle() -> list[str]:
    """Fragt Ollama /api/tags ab und gibt installierte Modellnamen zurück.

    Returns:
        Liste der installierten Modellnamen oder leere Liste bei Fehler.
    """
    try:
        import requests as req  # noqa: PLC0415

        from core.ollama_utils import get_default_ollama_tags_url  # noqa: PLC0415

        resp = req.get(get_default_ollama_tags_url(), timeout=5)
        if resp.status_code == 200:
            return [
                m.get("name", "")
                for m in resp.json().get("models", [])
                if m.get("name")
            ]
    except Exception:  # noqa: BLE001 -- Ollama-HTTP/JSON kann unspezifizierte Errors werfen, fail-safe leere Liste
        pass
    return []


def _briefing_fehler_texte(grund: str | None) -> tuple[str, str]:
    """Macht einen generiere_briefing-Fehlergrund zu (Titelzeile, Spalten-Hinweis).

    unterscheidet ein Modell-Versagen (leerer Stream / Timeout / Modell
    fehlt) von "Ollama nicht erreichbar", damit ein schlechtes Modell nicht wie
    ein nicht laufendes Ollama aussieht.

    Args:
        grund: Fehlergrund aus ``BriefingService._letzter_fehler`` oder None.

    Returns:
        Tuple ``(titel, hinweis)`` in Sie-Form.
    """
    if grund == FEHLER_LEERER_STREAM:
        return (
            "Modell lieferte keine Antwort — wähle ein anderes Modell",
            "Das gewählte Modell hat keinen Text geliefert. Reasoning-Modelle "
            "liefern unter JSON oft nichts — wähle ein Instruct-Modell und "
            "klicke auf 'Neu generieren'.",
        )
    if grund == FEHLER_TIMEOUT:
        return (
            "Modell-Timeout — wähle ein schnelleres Modell",
            "Das Modell hat nicht rechtzeitig geantwortet. Wähle ein "
            "kleineres, schnelleres Modell und klicke auf 'Neu generieren'.",
        )
    if grund == FEHLER_MODELL_FEHLT:
        return (
            "Modell nicht installiert",
            "Das gewählte Modell ist in Ollama nicht installiert. Wähle ein "
            "installiertes Modell und klicke auf 'Neu generieren'.",
        )
    if grund and grund.startswith(FEHLER_HTTP_PREFIX):
        return (
            "Ollama-Fehler bei der Generierung",
            "Ollama hat die Generierung mit einem Fehler abgebrochen. Prüfe "
            "das gewählte Modell und klicke auf 'Neu generieren'.",
        )
    if grund is None:
        return (
            "Ollama nicht erreichbar — starte Ollama für KI-Briefings",
            "Kein Briefing verfügbar. Starte Ollama lokal und klicke "
            "auf 'Neu generieren'.",
        )
    # ARCH-3: nicht-None, nicht-kategorisierter Grund = unerwarteter Fehler.
    # NICHT als "Ollama nicht erreichbar" maskieren (fail-loud-Ziel von).
    return (
        "Briefing fehlgeschlagen — bitte erneut versuchen",
        "Die Generierung wurde mit einem unerwarteten Fehler abgebrochen. "
        "Versuche es erneut; bleibt es bestehen, prüfe das Modell.",
    )


class _ModelleladenThread(QThread):
    """Fragt Ollama nach installierten Modellen.

    Signals:
        modelle: Liste installierter Modellnamen (leer bei Fehler).
    """

    modelle: Signal = Signal(list)

    def run(self) -> None:
        """Fragt /api/tags ab und emittiert die Modellliste."""
        self.modelle.emit(_abfrage_installierte_modelle())


class _OllamaCheckThread(QThread):
    """Nicht-blockierender Health-Check für Ollama (/api/tags).

    Ersetzt den synchronen ``is_ollama_running``-Call im ``__init__`` der
    Briefing-Tab. Emittiert das Ergebnis asynchron, damit das Tab-Öffnen
    auch bei hängendem Ollama-Prozess < 50ms dauert.

    Signals:
        checked: True wenn Ollama erreichbar ist.
    """

    checked: Signal = Signal(bool)

    def run(self) -> None:
        """Prüft Ollama via kurzem HTTP-Request, ohne den UI-Thread zu blocken."""
        self.checked.emit(is_ollama_running())


class _OllamaStartThread(QThread):
    """Startet Ollama im Hintergrund und wartet auf Bereitschaft.

    Signals:
        bereit: True wenn Ollama bereit ist, False wenn fehlgeschlagen.
    """

    bereit: Signal = Signal(bool)

    def run(self) -> None:
        """Ruft ensure_ollama_running im Hintergrund auf."""
        ok = ensure_ollama_running(timeout=30.0)
        self.bereit.emit(ok)


class _BriefingThread(QThread):
    """Generiert KI-Briefing im Hintergrund — streaming und abbrechbar.

    Der Thread prüft zwischen jedem Verarbeitungsschritt sowie zwischen
    Ollama-Streaming-Chunks ein Stop-Flag. Nach ``cancel`` beendet sich
    die Generierung spätestens beim nächsten Chunk (typ. < 500ms) ohne den
    Thread mit ``terminate`` zu killen.

    Signals:
        ergebnis: Generiertes Briefing-Dict ({} bei Fehler/Cancel).
        abgebrochen: Emittiert wenn der Benutzer ``cancel`` gerufen hat —
            die UI kann darauf reagieren ohne ``ergebnis`` als Fehler zu
            interpretieren.
    """

    ergebnis: Signal = Signal(dict)
    abgebrochen: Signal = Signal()
    # Stage-Wechsel an die GUI signalisieren (idx 1..3, label).
    stage_changed: Signal = Signal(int, str)

    # Stages laut TASKS.md.
    _STAGE_TOTAL = 3

    def __init__(
        self,
        service: DashboardService,
        modell: str,
    ) -> None:
        """Initialisiert den Briefing-Thread.

        Args:
            service: DashboardService-Instanz für Meldungen und CVEs.
            modell: Ollama-Modellname.
        """
        super().__init__()
        self._service = service
        self._modell = modell
        self._cancelled = False

    def cancel(self) -> None:
        """Setzt das Stop-Flag. BriefingService bricht beim nächsten Chunk ab."""
        self._cancelled = True

    def _is_cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:
        """Lädt Kontext und generiert Briefing via Ollama — streaming + cancel."""
        try:
            self.stage_changed.emit(1, "Daten sammeln")
            meldungen = self._service.lade_meldungen()
            if self._cancelled:
                self.abgebrochen.emit()
                return

            cves = self._service.lade_cves_briefing_pool(limit=40)
            if self._cancelled:
                self.abgebrochen.emit()
                return

            techstack = self._service.lade_techstack()
            if self._cancelled:
                self.abgebrochen.emit()
                return

            self.stage_changed.emit(2, "Modell anfragen")
            # c1: CVE- und Phishing-Briefing in ZWEI Sessions, nebenlaeufig
            # gestartet (ThreadPoolExecutor). Das lokale Ollama serialisiert
            # ggf. (kein OLLAMA_NUM_PARALLEL gesetzt) -> degradiert sauber auf
            # seriell; das Modell ist nach der 1. Session warm (keep_alive). Die
            # Phishing-Kandidaten stecken bereits in ``meldungen`` (RSS) -> kein
            # zusaetzlicher Abruf. Getrennte Service-Instanzen = keine geteilte
            # Cache-/Fehler-State-Race.
            kmu, consumer = waehle_phishing_kandidaten(meldungen)
            briefing_svc = BriefingService()
            phishing_svc = BriefingService()
            with ThreadPoolExecutor(max_workers=2) as pool:
                cve_future = pool.submit(
                    briefing_svc.generiere_briefing,
                    meldungen=meldungen,
                    cves=cves,
                    techstack=techstack,
                    modell=self._modell,
                    cancel_flag=self._is_cancelled,
                )
                phishing_future = pool.submit(
                    phishing_svc.generiere_phishing_briefing,
                    kmu,
                    consumer,
                    self._modell,
                    self._is_cancelled,
                )
                result = cve_future.result()
                phishing = phishing_future.result()
            if self._cancelled:
                self.abgebrochen.emit()
                return
            self.stage_changed.emit(3, "Antwort verarbeiten")
            if result is None:
                # Fehlergrund mitschicken, damit die GUI Modell-Versagen
                # von "Ollama nicht erreichbar" unterscheiden kann.
                grund = getattr(briefing_svc, "_letzter_fehler", None)
                payload: dict = {"_fehler": grund} if grund else {}
                # c1 (Review P2): die Phishing-Session ist unabhaengig — auch
                # wenn das CVE-Briefing scheitert, die (ggf. roh-)Phishing-
                # Warnungen trotzdem mitschicken, statt den bewusst gebauten
                # Fallback zu verwerfen.
                if phishing and (
                    phishing.get("phishing_kmu") or phishing.get("phishing_consumer")
                ):
                    payload["phishing_kmu"] = phishing.get("phishing_kmu", [])
                    payload["phishing_consumer"] = phishing.get(
                        "phishing_consumer", []
                    )
                self.ergebnis.emit(payload)
            else:
                if phishing:
                    # Phishing-Sektion in das CVE-Briefing mergen + das
                    # Gesamtergebnis persistieren (sonst fehlt es beim
                    # Cache-Reload, lade_briefing).
                    result["phishing_kmu"] = phishing.get("phishing_kmu", [])
                    result["phishing_consumer"] = phishing.get(
                        "phishing_consumer", []
                    )
                    briefing_svc.speichere_briefing(result)
                self.ergebnis.emit(result)
        except Exception as exc:  # noqa: BLE001 -- Worker-Thread muss fail-safe leeres Resultat liefern statt Thread sterben zu lassen
            log.error("Briefing-Thread fehlgeschlagen: %s", exc)
            self.ergebnis.emit({})


class _ConsumerZeile(QFrame):
    """Zeile in der "Verbreitete Software"-Sektion.

    Anordnung: Quelle-Badge + Produkt-Badge + (optional CVE/Datum rechts)
    + 1 Satz Beschreibung.

    Args:
        produkt: Produktname (z.B. "Chrome (Desktop)", "Windows 11").
        quelle: ``"BSI"`` / ``"MSRC"`` / ``"Chrome"`` / ``"Mozilla"``.
        beschreibung: Sachlicher Ein-Satz-Text.
        datum: ISO-Datum als String (``""`` = nicht anzeigen).
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        produkt: str,
        quelle: str,
        beschreibung: str,
        datum: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._produkt = produkt
        self._quelle = quelle
        self._beschreibung = beschreibung
        self._datum = datum
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        kopf = QHBoxLayout()
        kopf.setSpacing(6)

        self._lbl_quelle = QLabel(self._quelle or "—")
        self._lbl_quelle.setObjectName("quelle_badge")
        kopf.addWidget(self._lbl_quelle)

        self._lbl_produkt = QLabel(self._produkt or "—")
        self._lbl_produkt.setObjectName("produkt_badge")
        self._lbl_produkt.setTextFormat(Qt.TextFormat.PlainText)
        kopf.addWidget(self._lbl_produkt)

        kopf.addStretch()

        if self._datum:
            self._lbl_datum = QLabel(self._datum)
            self._lbl_datum.setObjectName("datum")
            kopf.addWidget(self._lbl_datum)

        layout.addLayout(kopf)

        self._lbl_text = QLabel(self._beschreibung)
        self._lbl_text.setWordWrap(True)
        self._lbl_text.setObjectName("meldungs_text")
        self._lbl_text.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._lbl_text)

    def apply_theme(self) -> None:
        c = theme.get()
        quelle_bg = _QUELLE_FARBEN.get(self._quelle, c.ACCENT_DIM)
        self.setStyleSheet(
            f"QFrame {{ background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; }}"
            f"QLabel#quelle_badge {{ background-color: {quelle_bg};"
            f" color: {c.TEXT_ON_LIGHT}; padding: 2px 8px; border-radius: 8px;"
            f" font-size: {theme.FONT_SIZE_CAPTION_XS}px; font-weight: 700; border: none;"
            f" letter-spacing: 0.4px; }}"
            f"QLabel#produkt_badge {{ background-color: {c.ACCENT_DIM};"
            f" color: {c.BG_DARK}; padding: 2px 8px; border-radius: 8px;"
            f" font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: 600; border: none; }}"
            f"QLabel#datum {{ color: {c.TEXT_DIM}; font-family: 'JetBrains Mono',"
            f" Consolas, monospace; font-size: {theme.FONT_SIZE_CAPTION}px; background: transparent;"
            f" border: none; }}"
            f"QLabel#meldungs_text {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px;"
            f" background: transparent; border: none; }}"
        )


class _MeldungsZeile(QFrame):
    """Kompakte Meldungszeile: Produkt-Badge + CVE-ID + 1 Satz Text.

    Args:
        produkt: Produktname für das Badge.
        cve_id: CVE-Identifikator (leer wenn RSS-Meldung).
        beschreibung: Ein Satz Sachtext.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        produkt: str,
        cve_id: str,
        beschreibung: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._produkt = produkt
        self._cve_id = cve_id
        self._beschreibung = beschreibung
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        """Erstellt die Zeile: Kopf (Badge + CVE) + Body (Beschreibung)."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        kopf = QHBoxLayout()
        kopf.setSpacing(6)

        self._lbl_badge = QLabel(self._produkt or "—")
        self._lbl_badge.setObjectName("produkt_badge")
        self._lbl_badge.setTextFormat(Qt.TextFormat.PlainText)
        kopf.addWidget(self._lbl_badge)

        if self._cve_id:
            self._lbl_cve = QLabel(self._cve_id)
            self._lbl_cve.setObjectName("cve_id")
            kopf.addWidget(self._lbl_cve)

        kopf.addStretch()
        layout.addLayout(kopf)

        self._lbl_text = QLabel(self._beschreibung)
        self._lbl_text.setWordWrap(True)
        self._lbl_text.setObjectName("meldungs_text")
        self._lbl_text.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._lbl_text)

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QFrame {{ background-color: {c.CARD_BG};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; }}"
            f"QLabel#produkt_badge {{ background-color: {c.ACCENT_DIM};"
            f" color: {c.BG_DARK}; padding: 2px 8px; border-radius: 8px;"
            f" font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: 600; border: none; }}"
            f"QLabel#cve_id {{ color: {c.TEXT_DIM}; font-family: 'JetBrains Mono',"
            f" Consolas, monospace; font-size: {theme.FONT_SIZE_CAPTION}px; background: transparent;"
            f" border: none; }}"
            f"QLabel#meldungs_text {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px;"
            f" background: transparent; border: none; }}"
        )


class _Spalte(QWidget):
    """Eine der beiden Briefing-Spalten (Titel + Liste oder Hinweistext).

    Args:
        titel: Spaltenüberschrift.
        parent: Optionales Eltern-Widget.
    """

    def __init__(self, titel: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._titel = titel
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        """Erstellt den Spalten-Rahmen."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._lbl_titel = QLabel(self._titel)
        self._lbl_titel.setObjectName("spalten_titel")
        layout.addWidget(self._lbl_titel)

        self._liste_container = QWidget()
        self._liste_layout = QVBoxLayout(self._liste_container)
        self._liste_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._liste_layout.setContentsMargins(0, 0, 0, 0)
        self._liste_layout.setSpacing(6)

        layout.addWidget(self._liste_container)
        layout.addStretch()

    def zeige_eintraege(self, eintraege: list[dict]) -> None:
        """Befüllt die Liste mit Meldungszeilen.

        Args:
            eintraege: Liste von Dicts mit ``produkt``, ``cve_id``, ``beschreibung``.
        """
        self._leeren()
        for eintrag in eintraege:
            self._liste_layout.addWidget(
                _MeldungsZeile(
                    produkt=eintrag.get("produkt", ""),
                    cve_id=eintrag.get("cve_id", ""),
                    beschreibung=eintrag.get("beschreibung", ""),
                )
            )

    def zeige_hinweis(self, text: str) -> None:
        """Zeigt statt Meldungen einen Hinweistext an.

        Args:
            text: Hinweistext (Empty-State).
        """
        self._leeren()
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setObjectName("hinweis")
        self._liste_layout.addWidget(lbl)

    def _leeren(self) -> None:
        """Entfernt alle Kinder aus der Liste."""
        while self._liste_layout.count():
            item = self._liste_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QLabel#spalten_titel {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;"
            f" background: transparent; border: none; padding: 0 0 2px 0; }}"
            f"QLabel#hinweis {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_BODY_SM}px;"
            f" font-style: italic; background: transparent; border: none;"
            f" padding: 4px 8px; }}"
        )


class _ConsumerSektion(_Spalte):
    """Untere Sektion "Verbreitete Software" mit Quell-Badges.

    Variante B: volle Breite, Einträge mit Quelle-Badge + Produkt + Datum.
    """

    def zeige_eintraege(self, eintraege: list[dict]) -> None:
        """Befuellt die Sektion mit:class:`_ConsumerZeile`-Eintraegen."""
        self._leeren()
        for eintrag in eintraege:
            self._liste_layout.addWidget(
                _ConsumerZeile(
                    produkt=eintrag.get("produkt", ""),
                    quelle=eintrag.get("quelle", ""),
                    beschreibung=eintrag.get("beschreibung", ""),
                    datum=eintrag.get("datum", ""),
                )
            )


class _PhishingSektion(QWidget):
    """Phishing-Sektion des Briefings: 2 Gruppen + Inline-Toggle (c1).

    Zeigt aktuelle Betrugsmaschen getrennt nach KMU-relevant (CEO-Fraud,
    Rechnungs-/Lieferantenbetrug) und Consumer (Bank-/Paket-Phishing). Der
    Toggle (Beide/Unternehmen/Privat) blendet Gruppen aus und persistiert die
    Wahl in ``FeedSettings.phishing_ebene``. Default ``beide`` — beide Ebenen
    treffen KMU-Inhaber (privat UND geschaeftlich).
    """

    #: (Label, FeedSettings-Wert) — Reihenfolge = Toggle-Reihenfolge.
    _OPTIONEN: tuple[tuple[str, str], ...] = (
        ("Beide", "beide"),
        ("Unternehmen", "kmu"),
        ("Privat", "consumer"),
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        try:
            self._ebene = load_feed_settings().phishing_ebene
        except OSError:
            self._ebene = "beide"
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        kopf = QHBoxLayout()
        kopf.setSpacing(6)
        self._lbl_titel = QLabel("Aktuelle Betrugsmaschen")
        self._lbl_titel.setObjectName("spalten_titel")
        kopf.addWidget(self._lbl_titel)
        kopf.addStretch()
        self._combo_ebene = QComboBox()
        self._combo_ebene.setObjectName("phishing_ebene_combo")
        for label, key in self._OPTIONEN:
            self._combo_ebene.addItem(label, key)
        self._combo_ebene.setCurrentIndex(max(0, self._combo_ebene.findData(self._ebene)))
        self._combo_ebene.setToolTip(
            "Welche Phishing-Warnungen angezeigt werden (Unternehmen / Privat / beide)"
        )
        self._combo_ebene.currentIndexChanged.connect(self._on_ebene_changed)
        kopf.addWidget(self._combo_ebene)
        layout.addLayout(kopf)

        self._gruppe_kmu = _Spalte("🏢 Unternehmen (KMU)")
        self._gruppe_consumer = _Spalte("👤 Privat")
        layout.addWidget(self._gruppe_kmu)
        layout.addWidget(self._gruppe_consumer)
        layout.addStretch()
        self._apply_ebene_visibility()

    @staticmethod
    def _map(eintrag: dict) -> dict:
        """Phishing-Eintrag ``{titel,beschreibung,quelle}`` -> _Spalte-Format."""
        return {
            "produkt": eintrag.get("quelle", ""),
            "cve_id": "",
            "beschreibung": eintrag.get("beschreibung", "")
            or eintrag.get("titel", ""),
        }

    def zeige_eintraege(self, kmu: list[dict], consumer: list[dict]) -> None:
        """Befuellt beide Gruppen (Eintraege je ``{titel,beschreibung,quelle}``)."""
        if kmu:
            self._gruppe_kmu.zeige_eintraege([self._map(e) for e in kmu])
        else:
            self._gruppe_kmu.zeige_hinweis("Keine Unternehmens-Warnungen.")
        if consumer:
            self._gruppe_consumer.zeige_eintraege([self._map(e) for e in consumer])
        else:
            self._gruppe_consumer.zeige_hinweis("Keine Privat-Warnungen.")
        self._apply_ebene_visibility()

    def zeige_hinweis(self, text: str) -> None:
        """Empty-/Fehler-State in beiden Gruppen."""
        self._gruppe_kmu.zeige_hinweis(text)
        self._gruppe_consumer.zeige_hinweis(text)
        self._apply_ebene_visibility()

    @Slot()
    def _on_ebene_changed(self) -> None:
        self._ebene = self._combo_ebene.currentData() or "beide"
        try:
            settings = load_feed_settings()
            settings.phishing_ebene = self._ebene
            save_feed_settings(settings)
        except OSError as exc:
            log.warning("phishing_ebene nicht gespeichert: %s", exc)
        self._apply_ebene_visibility()

    def _apply_ebene_visibility(self) -> None:
        self._gruppe_kmu.setVisible(self._ebene in ("beide", "kmu"))
        self._gruppe_consumer.setVisible(self._ebene in ("beide", "consumer"))

    def apply_theme(self) -> None:
        """Aktualisiert Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QLabel#spalten_titel {{ color: {c.TEXT_DIM};"
            f" font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: 600;"
            f" letter-spacing: 0.5px; text-transform: uppercase;"
            f" background: transparent; border: none; padding: 0 0 2px 0; }}"
        )


class BriefingTab(QWidget):
    """KI-Briefing Tab mit zweispaltigem Layout (techstack / allgemein).

    Zeigt gecachtes Briefing sofort an. "Neu generieren" startet den
    Ollama-Aufruf im Hintergrund.

    Args:
        service: DashboardService-Instanz.
        parent: Optionales Eltern-Widget.

    Signals:
        phishing_aktualisiert: Emittiert das komplette Briefing-Dict, sobald
            ``aktualisiere`` laeuft — der eigenstaendige Phishing-Tab
            spiegelt die Phishing-Sektion daraus, ohne den Briefing-Worker
            anzufassen.
    """

    phishing_aktualisiert: Signal = Signal(dict)

    def __init__(
        self,
        service: DashboardService,
        parent: QWidget | None = None,
    ) -> None:
        """Initialisiert den Briefing-Tab."""
        super().__init__(parent)
        self._service = service
        self._thread: _BriefingThread | None = None
        self._start_thread: _OllamaStartThread | None = None
        self._modelle_thread: _ModelleladenThread | None = None
        self._ollama_check_thread: _OllamaCheckThread | None = None
        # Live-Dauer waehrend "Modell anfragen" (Stage 2). Die Modell-
        # Inferenz ist der laengste, gefuehlt "eingefrorene" Abschnitt — ohne
        # Tick wirkt das Briefing haengengeblieben ("progressiver Aufbau nicht
        # umgesetzt"). Der Timer zaehlt nur Sekunden hoch und aktualisiert das
        # Status-Label; er aendert NICHTS am Generierungs-Flow.
        self._stage2_start = 0.0
        self._stage_label = ""
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._tick_stage_elapsed)
        # Stage-Ladebalken statt Punkt-Animation. Der ProgressBar wird
        # in _build_ui erzeugt; sichtbar nur waehrend einer Generierung.
        self._build_ui()
        theme.register_listener(self.apply_theme)
        self.apply_theme()
        self._gecachtes_briefing_laden()
        # Ollama-Check läuft async — das Tab öffnet sich niemals mehr durch
        # einen synchronen HTTP-Aufruf verzögert.
        self._ollama_check_starten()

    def _build_ui(self) -> None:
        """Erstellt das Tab-Layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        root.addWidget(KiDisclaimerWidget("KI-Zusammenfassung"))

        # Kompakte Kachel-Überschrift + Steuerleiste in einer Zeile
        kopf = QHBoxLayout()
        kopf.setSpacing(8)

        self._lbl_titel = QLabel("KI-Zusammenfassung")
        self._lbl_titel.setObjectName("briefing_titel")
        kopf.addWidget(self._lbl_titel)

        self._lbl_generiert = QLabel("")
        self._lbl_generiert.setObjectName("briefing_meta")
        kopf.addWidget(self._lbl_generiert)

        kopf.addStretch()

        kopf.addWidget(QLabel("Modell:"))
        self._combo_modell = QComboBox()
        # Combo bleibt initial leer; Modelle kommen via _modelle_laden nach
        # dem asynchronen Ollama-Check — kein Netz-IO im __init__.
        self._combo_modell.setFixedWidth(150)
        kopf.addWidget(self._combo_modell)

        self._btn_generieren = QPushButton("Neu generieren")
        self._btn_generieren.setIcon(get_icon(Icons.SYNC))
        self._btn_generieren.setMinimumHeight(32)
        self._btn_generieren.clicked.connect(self._generieren_starten)
        kopf.addWidget(self._btn_generieren)

        self._btn_abbrechen = QPushButton("Abbrechen")
        self._btn_abbrechen.setIcon(get_icon(Icons.CANCEL))
        self._btn_abbrechen.setMinimumHeight(32)
        self._btn_abbrechen.setToolTip(
            "Bricht die laufende Briefing-Generierung ab"
        )
        self._btn_abbrechen.clicked.connect(self._generieren_abbrechen)
        self._btn_abbrechen.setVisible(False)
        kopf.addWidget(self._btn_abbrechen)

        self._btn_ollama_starten = QPushButton("Ollama starten")
        self._btn_ollama_starten.setIcon(get_icon(Icons.PLAY_ARROW))
        self._btn_ollama_starten.setMinimumHeight(32)
        self._btn_ollama_starten.setToolTip(
            "Startet den lokalen Ollama-Server damit KI-Briefings generiert werden können"
        )
        self._btn_ollama_starten.clicked.connect(self._ollama_starten)
        # Sichtbarkeit wird nach asynchronem Check in _on_ollama_checked gesetzt.
        self._btn_ollama_starten.setVisible(False)
        kopf.addWidget(self._btn_ollama_starten)

        root.addLayout(kopf)

        # 3-Stage-Ladebalken (Daten sammeln / Modell anfragen / Antwort
        # verarbeiten). Sichtbar nur waehrend einer laufenden Generierung.
        self._progress_bar = FinlaiProgressBar(total=_BriefingThread._STAGE_TOTAL)
        self._progress_bar.setVisible(False)
        root.addWidget(self._progress_bar)

        # Scrollbarer Container — obere 2 Spalten + untere Full-Width-Sektion.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        outer_container = QWidget()
        outer_layout = QVBoxLayout(outer_container)
        outer_layout.setContentsMargins(0, 4, 0, 0)
        outer_layout.setSpacing(16)

        # Obere Reihe: zwei Spalten (Techstack / Allgemein)
        spalten_container = QWidget()
        spalten_layout = QHBoxLayout(spalten_container)
        spalten_layout.setContentsMargins(0, 0, 0, 0)
        spalten_layout.setSpacing(12)

        # c1: oben Stack | Phishing (die fruehere "Allgemein"-Spalte entfaellt
        # sichtbar — am wenigsten handlungsrelevant; Patrick-Entscheid: Stack +
        # Consumer behalten, Phishing aufnehmen). Consumer bleibt unten.
        self._spalte_techstack = _Spalte("Relevant für deine IT")
        self._sektion_phishing = _PhishingSektion()

        spalten_layout.addWidget(self._spalte_techstack, 1)
        spalten_layout.addWidget(self._sektion_phishing, 1)

        outer_layout.addWidget(spalten_container)

        # Untere Sektion: Verbreitete Software (volle Breite).
        self._sektion_consumer = _ConsumerSektion("Verbreitete Software")
        outer_layout.addWidget(self._sektion_consumer)

        outer_layout.addStretch()
        scroll.setWidget(outer_container)
        root.addWidget(scroll)

        # Initialer Empty-State
        self._spalte_techstack.zeige_hinweis(
            "Noch kein Briefing vorhanden — klicke 'Neu generieren'."
        )
        self._sektion_phishing.zeige_hinweis(
            "Noch kein Briefing vorhanden — klicke 'Neu generieren'."
        )
        self._sektion_consumer.zeige_hinweis(
            "Noch kein Briefing vorhanden — klicke 'Neu generieren'."
        )

    def aktualisiere(self, briefing: dict) -> None:
        """Zeigt ein Briefing-Dict im Tab an.

        Args:
            briefing: Dict mit techstack_eintraege / allgemein_eintraege /
                      techstack_leer / Metadaten.
        """
        # den eigenstaendigen Phishing-Tab mitversorgen (spiegelt die
        # Phishing-Sektion). Vor der eigenen Verarbeitung, deckt Fehler- UND
        # Erfolgspfad ab; der Tab extrahiert phishing_kmu/-_consumer selbst.
        self.phishing_aktualisiert.emit(briefing or {})
        if not briefing or "_fehler" in briefing:
            grund = briefing.get("_fehler") if briefing else None
            titel, hinweis = _briefing_fehler_texte(grund)
            self._lbl_generiert.setText(titel)
            self._spalte_techstack.zeige_hinweis(hinweis)
            # c1 (Review P2): Phishing trotz CVE-Fehler zeigen, wenn vorhanden.
            phishing_kmu = briefing.get("phishing_kmu", []) if briefing else []
            phishing_consumer = (
                briefing.get("phishing_consumer", []) if briefing else []
            )
            if phishing_kmu or phishing_consumer:
                self._sektion_phishing.zeige_eintraege(phishing_kmu, phishing_consumer)
            else:
                self._sektion_phishing.zeige_hinweis("Kein Briefing verfügbar.")
            self._sektion_consumer.zeige_hinweis("Kein Briefing verfügbar.")
            return

        datum = briefing.get("datum", "")
        generiert_um = briefing.get("generiert_um", "")
        modell = briefing.get("modell", "")
        if datum or generiert_um:
            self._lbl_generiert.setText(
                f"Generiert: {datum} {generiert_um}  |  Modell: {modell}"
            )

        # Neues Format — zweispaltige Struktur
        if (
            "techstack_eintraege" in briefing
            or "allgemein_eintraege" in briefing
            or "phishing_kmu" in briefing
        ):
            techstack_eintraege = briefing.get("techstack_eintraege", [])
            consumer_eintraege = briefing.get("consumer_eintraege", [])
            techstack_leer = briefing.get("techstack_leer", False)

            if techstack_leer:
                self._spalte_techstack.zeige_hinweis(_TECHSTACK_LEER_HINT)
            elif techstack_eintraege:
                self._spalte_techstack.zeige_eintraege(techstack_eintraege)
            else:
                self._spalte_techstack.zeige_hinweis(_KEINE_TREFFER_HINT)

            # c1: Phishing-Sektion ersetzt sichtbar die fruehere "Allgemein"-Spalte.
            phishing_kmu = briefing.get("phishing_kmu", [])
            phishing_consumer = briefing.get("phishing_consumer", [])
            if phishing_kmu or phishing_consumer:
                self._sektion_phishing.zeige_eintraege(phishing_kmu, phishing_consumer)
            else:
                self._sektion_phishing.zeige_hinweis(_KEINE_PHISHING_HINT)

            if consumer_eintraege:
                self._sektion_consumer.zeige_eintraege(consumer_eintraege)
            else:
                self._sektion_consumer.zeige_hinweis(_KEINE_CONSUMER_HINT)
            return

        # Alt-Format (lagebild als Markdown) — zeige Migrationshinweis
        self._spalte_techstack.zeige_hinweis(
            "Alter Briefing-Cache im bisherigen Format. Klicke 'Neu "
            "generieren' für das neue Layout."
        )
        self._sektion_phishing.zeige_hinweis(
            "Alter Briefing-Cache im bisherigen Format."
        )
        self._sektion_consumer.zeige_hinweis(
            "Alter Briefing-Cache im bisherigen Format."
        )

    def _gecachtes_briefing_laden(self) -> None:
        """Zeigt ein vorhandenes gecachtes Briefing an — ohne LLM-Aufruf."""
        try:
            briefing_svc = BriefingService()
            cached = briefing_svc.lade_briefing()
            if cached:
                self.aktualisiere(cached)
        except (OSError, RuntimeError, ValueError) as exc:
            log.debug("Gecachtes Briefing nicht verfügbar: %s", exc)

    def _generieren_starten(self) -> None:
        """Startet die Briefing-Generierung im Hintergrund."""
        if self._thread and self._thread.isRunning():
            return

        modell = self._combo_modell.currentText()
        if not modell:
            self._lbl_generiert.setText(
                "Kein Modell verfügbar — starte Ollama oder installiere ein Modell"
            )
            return

        self._btn_generieren.setEnabled(False)
        self._btn_abbrechen.setVisible(True)
        # Ladebalken sichtbar machen, Stage 1 setzen.
        self._progress_bar.setVisible(True)
        self._progress_bar.set_stage(1, _BriefingThread._STAGE_TOTAL, "Daten sammeln")
        self._lbl_generiert.setText("Generiere Briefing")

        self._thread = _BriefingThread(self._service, modell)
        # Explizite QueuedConnection — Worker emittiert aus eigenem Thread,
        # Slot muss im UI-Thread laufen. AutoConnection erkennt das heute
        # zwar korrekt (QThread-Subclass-Affinitaet), aber bei kuenftigem
        # ``moveToThread``-Refactor wuerde es subtil brechen.
        self._thread.ergebnis.connect(
            self._briefing_empfangen, Qt.ConnectionType.QueuedConnection
        )
        self._thread.abgebrochen.connect(
            self._briefing_abgebrochen, Qt.ConnectionType.QueuedConnection
        )
        self._thread.stage_changed.connect(
            self._on_stage_changed, Qt.ConnectionType.QueuedConnection
        )
        self._thread.start()

    def _generieren_abbrechen(self) -> None:
        """Setzt das Stop-Flag im laufenden Briefing-Thread."""
        if self._thread and self._thread.isRunning():
            self._thread.cancel()
            self._elapsed_timer.stop()  # Sekunden-Tick beenden
            self._btn_abbrechen.setEnabled(False)
            # Bar in Indeterminate-Modus, da naechster Chunk-Check
            # bis ~500ms dauern kann.
            self._progress_bar.start_indeterminate(label="Abbrechen ...")
            self._lbl_generiert.setText("Breche ab …")

    @Slot(int, str)
    def _on_stage_changed(self, idx: int, label: str) -> None:
        """Aktualisiert den Stage-Ladebalken + Live-Dauer."""
        if 1 <= idx <= _BriefingThread._STAGE_TOTAL:
            self._progress_bar.set_stage(
                idx, _BriefingThread._STAGE_TOTAL, label
            )
            self._stage_label = label
            # Nur die Modell-Anfrage (Stage 2) ist lang genug, dass eine
            # hochzaehlende Sekunden-Anzeige hilft ("laeuft noch"); in Stage 1/3
            # den Tick stoppen, damit das Label nicht weiterzaehlt.
            if idx == 2:
                self._stage2_start = time.monotonic()
                self._lbl_generiert.setText(
                    f"Generiere Briefing — {label} (0 s)"
                )
                self._elapsed_timer.start()
            else:
                self._elapsed_timer.stop()
                self._lbl_generiert.setText(f"Generiere Briefing — {label}")

    def _tick_stage_elapsed(self) -> None:
        """Zeigt die verstrichene Sekunden waehrend der Modell-Anfrage."""
        elapsed = int(time.monotonic() - self._stage2_start)
        self._lbl_generiert.setText(
            f"Generiere Briefing — {self._stage_label} ({elapsed} s)"
        )

    @Slot(dict)
    def _briefing_empfangen(self, briefing: dict) -> None:
        """Zeigt das neu generierte Briefing an.

        Args:
            briefing: Generiertes Briefing-Dict.
        """
        self._elapsed_timer.stop()  # Sekunden-Tick beenden
        # Hotfix: Bar VOR setVisible(False) zuruecksetzen — verhindert
        # Format-Leak ("Schritt 3/3 —...") + Wert-Sprung beim naechsten
        # Generieren-Klick.
        self._progress_bar.reset()
        self._progress_bar.setVisible(False)
        self._btn_generieren.setEnabled(True)
        self._btn_abbrechen.setVisible(False)
        self._btn_abbrechen.setEnabled(True)
        self.aktualisiere(briefing)

    @Slot()
    def _briefing_abgebrochen(self) -> None:
        """Reagiert auf eine vom User ausgelöste Abbruchbestätigung."""
        self._elapsed_timer.stop()  # Sekunden-Tick beenden
        # Hotfix: Bar VOR setVisible(False) zuruecksetzen.
        self._progress_bar.reset()
        self._progress_bar.setVisible(False)
        self._btn_generieren.setEnabled(True)
        self._btn_abbrechen.setVisible(False)
        self._btn_abbrechen.setEnabled(True)
        self._lbl_generiert.setText("Generierung abgebrochen")

    def _modelle_laden(self) -> None:
        """Lädt installierte Ollama-Modelle asynchron."""
        if self._modelle_thread and self._modelle_thread.isRunning():
            return
        self._modelle_thread = _ModelleladenThread()
        self._modelle_thread.modelle.connect(self._modelle_empfangen)
        self._modelle_thread.start()

    @Slot(list)
    def _modelle_empfangen(self, modelle: list) -> None:
        """Befüllt die Modell-Combo mit installierten Ollama-Modellen.

        Args:
            modelle: Liste der installierten Modellnamen.
        """
        if not modelle:
            return
        aktuell = self._combo_modell.currentText()
        self._combo_modell.clear()
        for m in modelle:
            self._combo_modell.addItem(m)
        idx = self._combo_modell.findText(aktuell)
        if idx >= 0:
            self._combo_modell.setCurrentIndex(idx)
        log.debug("Ollama-Modelle aktualisiert: %s", modelle)

    def _ollama_check_starten(self) -> None:
        """Startet den nicht-blockierenden Ollama-Health-Check."""
        if self._ollama_check_thread and self._ollama_check_thread.isRunning():
            return
        self._ollama_check_thread = _OllamaCheckThread()
        self._ollama_check_thread.checked.connect(self._on_ollama_checked)
        self._ollama_check_thread.start()

    @Slot(bool)
    def _on_ollama_checked(self, running: bool) -> None:
        """Reagiert auf das Ergebnis des asynchronen Ollama-Checks."""
        self._btn_ollama_starten.setVisible(not running)
        if running:
            self._modelle_laden()

    def _ollama_starten(self) -> None:
        """Startet Ollama im Hintergrund."""
        if self._start_thread and self._start_thread.isRunning():
            return
        self._btn_ollama_starten.setEnabled(False)
        self._btn_ollama_starten.setText("Starte Ollama …")
        self._btn_ollama_starten.setIcon(get_icon(Icons.HOURGLASS))
        self._start_thread = _OllamaStartThread()
        self._start_thread.bereit.connect(self._ollama_bereit)
        self._start_thread.start()

    @Slot(bool)
    def _ollama_bereit(self, ok: bool) -> None:
        """Reagiert auf das Ergebnis des Ollama-Starts.

        Args:
            ok: True wenn Ollama bereit ist.
        """
        if ok:
            self._btn_ollama_starten.setVisible(False)
            self._lbl_generiert.setText("Ollama bereit — klicke 'Neu generieren'")
            self._modelle_laden()
        else:
            self._btn_ollama_starten.setEnabled(True)
            self._btn_ollama_starten.setText("Ollama starten")
            self._btn_ollama_starten.setIcon(get_icon(Icons.PLAY_ARROW))
            self._lbl_generiert.setText(
                "Ollama-Start fehlgeschlagen — ist Ollama installiert?"
            )

    def apply_theme(self) -> None:
        """Aktualisiert Widget-Farben für das aktive Theme."""
        c = theme.get()
        self.setStyleSheet(
            f"QWidget {{ background-color: {c.BG_MAIN}; color: {c.TEXT_MAIN}; }}"
            f"QScrollArea {{ border: none; background: {c.BG_MAIN}; }}"
            f"QComboBox {{ background-color: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
            f"QLabel#briefing_titel {{ color: {c.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px;"
            f" font-weight: 600; background: transparent; border: none; }}"
            f"QLabel#briefing_meta {{ color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px;"
            f" background: transparent; border: none; }}"
        )
