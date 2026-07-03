"""
org_assessment_wizard — 4-seitiger Wizard für das Organisations-Sicherheits-Assessment.

Seiten (jede Frage als 3er-Auswahl Ja / Nein / „trifft nicht zu"):
  1) DSGVO-Compliance — Self-Assessment (6 Fragen)
  2) Phishing-Schutz — Self-Assessment (5 Fragen)
  3) Multi-Factor Authentication — Auto-Detection (Windows Hello) + 6 Fragen
  4) Passwort-Manager — Auto-Detection (installierte Manager) +
                                    3 Fragen + Freitext „Anderer Manager"

„trifft nicht zu" (NICHT_ANWENDBAR) fällt aus dem Score-Nenner; eine
unbeantwortete Frage zählt als UNBEKANNT (Microsoft-Secure-Score-Stil).
Auto-Detection-Ergebnisse werden als informative Labels angezeigt
(„aktiv" / „inaktiv" / „unbekannt").

Schichtzugehörigkeit: gui/ — nutzt den application-Service, keine
Business-Logik im Widget.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.logger import get_logger
from core.widgets.finlai_progress import FinlaiProgressBar
from tools.security_scoring.application.org_security_service import OrgSecurityService
from tools.security_scoring.application.os_detection_service import (
    STATUS_AKTIV,
    STATUS_INAKTIV,
    STATUS_UNBEKANNT,
    check_installed_password_managers,
    check_windows_hello,
)
from tools.security_scoring.domain.org_security import (
    FRAGEN_DSGVO,
    FRAGEN_MFA,
    FRAGEN_PASSWORT_MANAGER,
    FRAGEN_PHISHING,
    METRIK_DSGVO,
    METRIK_MFA,
    METRIK_PASSWORT_MANAGER,
    METRIK_PHISHING,
    OrgAntwort,
    OrgFrage,
    OrgMetrikErgebnis,
)

log = get_logger(__name__)

_MFA_HINWEIS = (
    "Windows Hello schützt den Login zu deinem PC. Für Mandantendaten ist "
    "zusätzlich MFA auf den jeweiligen Anwendungen entscheidend."
)

_PM_HINWEIS = (
    "Nicht erkannte Programme bedeuten nicht automatisch, dass kein Passwort-"
    "Manager installiert ist. Das Feld 'Anderer Passwort-Manager' erlaubt "
    "einen manuellen Eintrag."
)

_SEITEN_TITEL: tuple[str, ...] = (
    "DSGVO-Compliance",
    "Phishing-Schutz",
    "Multi-Factor Authentication",
    "Passwort-Manager",
)


class _FrageZeile(QWidget):
    """Eine Self-Assessment-Frage mit 3er-Auswahl.

    Ja / Nein / „trifft nicht zu". Keine Auswahl → UNBEKANNT (unbeantwortet
    zählt im Score-Nenner weiter, Microsoft-Secure-Score-Stil); „trifft nicht
    zu" → NICHT_ANWENDBAR (fällt aus dem Nenner, senkt den Score nicht).
    """

    _OPTIONEN: tuple[tuple[str, OrgAntwort], ...] = (
        ("Ja", OrgAntwort.JA),
        ("Nein", OrgAntwort.NEIN),
        ("trifft nicht zu", OrgAntwort.NICHT_ANWENDBAR),
    )

    def __init__(
        self,
        frage: OrgFrage,
        parent: QWidget | None = None,
        *,
        vorbelegt_na: bool = False,
        na_tooltip: str | None = None,
    ) -> None:
        super().__init__(parent)
        self._key = frage.key
        t = theme.get()
        row = QHBoxLayout(self)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(10)

        lbl = QLabel(frage.text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: 13px; border: none;")
        row.addWidget(lbl, stretch=1)

        self._gruppe = QButtonGroup(self)
        self._radios: dict[OrgAntwort, QRadioButton] = {}
        radio_style = self._radio_style()
        for label, antwort in self._OPTIONEN:
            rb = QRadioButton(label)
            rb.setStyleSheet(radio_style)
            self._gruppe.addButton(rb)
            self._radios[antwort] = rb
            row.addWidget(rb)

        if vorbelegt_na:
            # Ebene 2/3: laut Firmenprofil (Größe) ODER erkannter
            # Nicht-Nutzung (Ebene 3 → ``na_tooltip``) nicht anwendbar — auf
            # „trifft nicht zu" vorbelegt, bleibt aber editierbar.
            self._radios[OrgAntwort.NICHT_ANWENDBAR].setChecked(True)
            self.setToolTip(
                na_tooltip
                or "Wegen Firmengröße als nicht zutreffend vorbelegt — "
                "bitte prüfen und ggf. anpassen."
            )

    def antwort(self) -> OrgAntwort:
        """Gewählte Antwort; ``UNBEKANNT`` wenn nichts ausgewählt ist."""
        for antwort, rb in self._radios.items():
            if rb.isChecked():
                return antwort
        return OrgAntwort.UNBEKANNT

    def set_antwort(self, antwort: OrgAntwort) -> None:
        """Setzt die Auswahl auf ``antwort`` Vorbefüllung).

        ``UNBEKANNT`` (keine passende Radio-Option) ist bewusst ein No-op: eine
        nicht konkret beantwortete Frage behält ihre aktuelle Darstellung — die
        Profil-/Nutzungs-N/A-Vorbelegung bleibt für unbeantwortete
        Fragen erhalten. Eine konkrete gespeicherte Antwort (Ja/Nein/N/A) gewinnt
        dagegen — exakt Mechanismus 2 (jüngere Antwort = stärkeres Signal).
        """
        rb = self._radios.get(antwort)
        if rb is not None:
            rb.setChecked(True)

    @staticmethod
    def _radio_style() -> str:
        t = theme.get()
        return (
            f"QRadioButton {{ color: {t.TEXT_MAIN}; font-size: 12px;"
            f" border: none; }}"
            f"QRadioButton::indicator {{ width: 14px; height: 14px; }}"
            f"QRadioButton::indicator:unchecked {{"
            f" border: 1px solid {t.BORDER}; background-color: {t.BG_BUTTON};"
            f" border-radius: 7px; }}"
            f"QRadioButton::indicator:checked {{"
            f" border: 1px solid {t.ACCENT}; background-color: {t.ACCENT};"
            f" border-radius: 7px; }}"
        )


def _nutzungs_tooltip(audit_datum: str) -> str:
    """Tooltip-Text für eine nutzungs-bedingt vorbelegte Frage Ebene 3).

    Args:
        audit_datum: ISO-Datum des zugrunde liegenden SELF-Sovereignty-Audits
            (``""`` wenn unbekannt).

    Returns:
        Erklärender, datierter Hinweis (Sie-Form), der auf Editierbarkeit und
        Aktualisierungs-Möglichkeit verweist Mechanismus 3).
    """
    datum = audit_datum[:10] if audit_datum else ""
    quelle = f"vom {datum} " if datum else ""
    return (
        f"Laut deinem Sovereignty-Audit {quelle}wurde diese Nutzung nicht "
        "erfasst — auf „trifft nicht zu“ vorbelegt. Heute anders? Wähle "
        "Ja/Nein oder aktualisiere das Sovereignty-Audit."
    )


class _AssessmentSeite(QWidget):
    """Abstrakte Grundstruktur einer Wizard-Seite.

    Implementiert Titel + Subtitle + Scrollbereich; konkrete Seiten
    befüllen den Scrollbereich über ``_baue_inhalt``.
    """

    def __init__(
        self,
        titel: str,
        parent: QWidget | None = None,
        *,
        na_keys: frozenset[str] = frozenset(),
        na_nutzungs_keys: frozenset[str] = frozenset(),
        na_audit_datum: str = "",
    ) -> None:
        super().__init__(parent)
        self._fragen_zeilen: dict[str, _FrageZeile] = {}
        self._na_keys = na_keys
        self._na_nutzungs_keys = na_nutzungs_keys
        self._na_audit_datum = na_audit_datum
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        t = theme.get()
        lbl_titel = QLabel(titel)
        lbl_titel.setStyleSheet(
            f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_H3}px; font-weight: 600;"
        )
        layout.addWidget(lbl_titel)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        self._content_layout = QVBoxLayout(container)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._content_layout.setSpacing(6)
        self._content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        scroll.setWidget(container)
        layout.addWidget(scroll, stretch=1)

    def _fuege_fragen_ein(self, fragen: tuple[OrgFrage, ...]) -> None:
        """Rendert pro Frage eine 3er-Auswahl (Ja/Nein/trifft nicht zu).

 Ebene 2/3: Fragen in ``_na_keys`` werden auf „trifft nicht zu"
        vorbelegt. Stammt die Vorbelegung aus einem Nutzungssignal
        (``_na_nutzungs_keys``, Ebene 3), erhält die Zeile den erklärenden,
        datierten Nutzungs-Tooltip statt des Firmengrößen-Hinweises.
        """
        for frage in fragen:
            vorbelegt = frage.key in self._na_keys
            na_tooltip = (
                _nutzungs_tooltip(self._na_audit_datum)
                if vorbelegt and frage.key in self._na_nutzungs_keys
                else None
            )
            zeile = _FrageZeile(frage, vorbelegt_na=vorbelegt, na_tooltip=na_tooltip)
            self._fragen_zeilen[frage.key] = zeile
            self._content_layout.addWidget(zeile)

    def _fuege_hinweis_ein(self, text: str) -> None:
        """Zeigt einen kursiven Hinweistext."""
        t = theme.get()
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; font-style: italic;"
            f" padding: 4px 8px 4px 0;"
        )
        self._content_layout.addWidget(lbl)

    def sammle_antworten(self) -> dict[str, OrgAntwort]:
        """Gibt die gewählte OrgAntwort je Frage zurück: inkl. N/A)."""
        return {
            key: zeile.antwort() for key, zeile in self._fragen_zeilen.items()
        }

    def set_antworten(self, antworten: dict[str, OrgAntwort]) -> None:
        """Belegt die Seiten-Fragen aus gespeicherten Antworten vor.

        Nur Keys, die als Frage-Zeile existieren, werden gesetzt; ``UNBEKANNT``
        lässt die N/A-Vorbelegung unberührt (siehe ``_FrageZeile.set_antwort``).
        """
        for key, antwort in antworten.items():
            zeile = self._fragen_zeilen.get(key)
            if zeile is not None:
                zeile.set_antwort(antwort)


class _DsgvoSeite(_AssessmentSeite):
    """Seite 1 — DSGVO-Compliance."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        na_keys: frozenset[str] = frozenset(),
        na_nutzungs_keys: frozenset[str] = frozenset(),
        na_audit_datum: str = "",
    ) -> None:
        super().__init__(
            _SEITEN_TITEL[0],
            parent,
            na_keys=na_keys,
            na_nutzungs_keys=na_nutzungs_keys,
            na_audit_datum=na_audit_datum,
        )
        self._fuege_fragen_ein(FRAGEN_DSGVO)

    def ergebnis(self) -> OrgMetrikErgebnis:
        return OrgMetrikErgebnis(
            metrik=METRIK_DSGVO,
            antworten=self.sammle_antworten(),
        )


class _PhishingSeite(_AssessmentSeite):
    """Seite 2 — Phishing-Schutz."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        na_keys: frozenset[str] = frozenset(),
        na_nutzungs_keys: frozenset[str] = frozenset(),
        na_audit_datum: str = "",
    ) -> None:
        super().__init__(
            _SEITEN_TITEL[1],
            parent,
            na_keys=na_keys,
            na_nutzungs_keys=na_nutzungs_keys,
            na_audit_datum=na_audit_datum,
        )
        self._fuege_fragen_ein(FRAGEN_PHISHING)

    def ergebnis(self) -> OrgMetrikErgebnis:
        return OrgMetrikErgebnis(
            metrik=METRIK_PHISHING,
            antworten=self.sammle_antworten(),
        )


class _MfaSeite(_AssessmentSeite):
    """Seite 3 — MFA inkl. Windows-Hello-Auto-Detection."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        na_keys: frozenset[str] = frozenset(),
        na_nutzungs_keys: frozenset[str] = frozenset(),
        na_audit_datum: str = "",
    ) -> None:
        super().__init__(
            _SEITEN_TITEL[2],
            parent,
            na_keys=na_keys,
            na_nutzungs_keys=na_nutzungs_keys,
            na_audit_datum=na_audit_datum,
        )

        # Auto-Detection-Label
        self._hello_status = check_windows_hello()
        auto_lbl = _AutoStatusLabel(
            titel="Windows-Login",
            status=self._hello_status.status,
            detail=self._hello_status.detail,
        )
        self._content_layout.addWidget(auto_lbl)
        self._fuege_hinweis_ein(_MFA_HINWEIS)

        trenner = QFrame()
        trenner.setFrameShape(QFrame.Shape.HLine)
        trenner.setStyleSheet(f"color: {theme.get().BORDER};")
        self._content_layout.addWidget(trenner)

        self._fuege_fragen_ein(FRAGEN_MFA)

    def ergebnis(self) -> OrgMetrikErgebnis:
        return OrgMetrikErgebnis(
            metrik=METRIK_MFA,
            antworten=self.sammle_antworten(),
            auto_status=self._hello_status.status,
            auto_details=self._hello_status.detail,
        )


class _PasswortManagerSeite(_AssessmentSeite):
    """Seite 4 — Passwort-Manager inkl. Installationserkennung."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        na_keys: frozenset[str] = frozenset(),
        na_nutzungs_keys: frozenset[str] = frozenset(),
        na_audit_datum: str = "",
    ) -> None:
        super().__init__(
            _SEITEN_TITEL[3],
            parent,
            na_keys=na_keys,
            na_nutzungs_keys=na_nutzungs_keys,
            na_audit_datum=na_audit_datum,
        )

        # Auto-Detection
        self._pm_status = check_installed_password_managers()
        auto_lbl = _AutoStatusLabel(
            titel="Erkannte Passwort-Manager",
            status=self._pm_status.status,
            detail=self._pm_status.detail,
        )
        self._content_layout.addWidget(auto_lbl)
        self._fuege_hinweis_ein(_PM_HINWEIS)

        trenner = QFrame()
        trenner.setFrameShape(QFrame.Shape.HLine)
        trenner.setStyleSheet(f"color: {theme.get().BORDER};")
        self._content_layout.addWidget(trenner)

        self._fuege_fragen_ein(FRAGEN_PASSWORT_MANAGER)

        # Freitext-Feld
        t = theme.get()
        eingabe_row = QHBoxLayout()
        eingabe_row.setSpacing(8)
        lbl = QLabel("Anderer Passwort-Manager:")
        lbl.setStyleSheet(f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY}px;")
        eingabe_row.addWidget(lbl)

        self._input_custom = QLineEdit()
        self._input_custom.setPlaceholderText("z.B. Securden, Keeper, Passbolt …")
        self._input_custom.setStyleSheet(
            f"QLineEdit {{ background-color: {t.BG_BUTTON};"
            f" color: {t.TEXT_MAIN}; border: 1px solid {t.BORDER};"
            f" border-radius: 4px; padding: 4px 8px; font-size: {theme.FONT_SIZE_BODY}px; }}"
        )
        eingabe_row.addWidget(self._input_custom, stretch=1)
        row_widget = QWidget()
        row_widget.setLayout(eingabe_row)
        self._content_layout.addWidget(row_widget)

    def ergebnis(self) -> OrgMetrikErgebnis:
        return OrgMetrikErgebnis(
            metrik=METRIK_PASSWORT_MANAGER,
            antworten=self.sammle_antworten(),
            auto_status=self._pm_status.status,
            auto_details=self._pm_status.detail,
            custom_pm_name=self._input_custom.text().strip(),
        )

    def set_custom_pm_name(self, name: str) -> None:
        """Belegt das Freitext-Feld „Anderer Passwort-Manager" vor."""
        self._input_custom.setText(name or "")


class _AutoStatusLabel(QFrame):
    """Kompaktes Label für Auto-Detection-Status.

    Zeigt Titel + Statusmarker (aktiv/inaktiv/unbekannt) + Detailtext.
    Farben folgen dem vorhandenen Rot-Grün-Gradient des Scoring-Systems.
    """

    _STATUS_FARBE: dict[str, str] = {
        STATUS_AKTIV: theme.GRADE_A,
        STATUS_INAKTIV: theme.GRADE_F,
        STATUS_UNBEKANNT: theme.SEVERITY_SIGNAL_INFO,
    }

    def __init__(
        self,
        titel: str,
        status: str,
        detail: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        t = theme.get()
        self.setStyleSheet(
            f"QFrame {{ background-color: {t.CARD_BG};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(2)

        farbe = self._STATUS_FARBE.get(status, theme.SEVERITY_SIGNAL_INFO)
        kopf = QHBoxLayout()
        lbl_titel = QLabel(titel)
        lbl_titel.setStyleSheet(
            f"color: {t.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: 600;"
            f" letter-spacing: 0.5px; text-transform: uppercase; border: none;"
        )
        kopf.addWidget(lbl_titel)
        kopf.addStretch()
        lbl_status = QLabel(status.upper())
        lbl_status.setStyleSheet(
            f"color: {farbe}; font-size: {theme.FONT_SIZE_CAPTION}px; font-weight: 700; border: none;"
        )
        kopf.addWidget(lbl_status)
        layout.addLayout(kopf)

        lbl_detail = QLabel(detail)
        lbl_detail.setWordWrap(True)
        lbl_detail.setStyleSheet(
            f"color: {t.TEXT_MAIN}; font-size: {theme.FONT_SIZE_BODY_SM}px; border: none;"
        )
        layout.addWidget(lbl_detail)


class OrgAssessmentWizard(QDialog):
    """4-seitiger Wizard für das Organisations-Sicherheits-Assessment.

    Args:
        service: OrgSecurityService zur Persistenz.
        parent: Optionales Eltern-Widget.
        na_keys: Frage-Keys, die als „trifft nicht zu" vorzubelegen sind
 Ebene 2 Firmengröße ∪ Ebene 3 Nutzung). Leer = keine
            Vorbelegung.
        na_nutzungs_keys: Teilmenge von ``na_keys``, deren Vorbelegung aus einem
            Nutzungssignal stammt (Ebene 3) — steuert den differenzierten Tooltip.
        na_audit_datum: ISO-Datum des SELF-Sovereignty-Audits für den Tooltip
            (``""`` wenn keins).

    Signals:
        assessment_gespeichert: Emittiert nach erfolgreicher Speicherung.
    """

    assessment_gespeichert = Signal()

    def __init__(
        self,
        service: OrgSecurityService,
        parent: QWidget | None = None,
        *,
        na_keys: frozenset[str] = frozenset(),
        na_nutzungs_keys: frozenset[str] = frozenset(),
        na_audit_datum: str = "",
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._na_keys = na_keys
        self._na_nutzungs_keys = na_nutzungs_keys
        self._na_audit_datum = na_audit_datum
        self.setWindowTitle("Organisatorische Sicherheit — Assessment")
        self.setMinimumSize(640, 520)
        self._aktuelle_seite = 0
        self._build_ui()
        # zuletzt gespeicherte Antworten vorbefüllen (NACH dem Bau, damit
        # konkrete Antworten die N/A-Vorbelegung der Seiten überschreiben).
        self._vorbefuellen_aus_letztem()

    def _build_ui(self) -> None:
        """Erstellt das Dialog-Layout."""
        t = theme.get()
        self.setStyleSheet(f"background-color: {t.BG_MAIN}; color: {t.TEXT_MAIN};")

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        # Fortschritt: kanonischer FinlaiProgressBar).
        # Wizard-Sonderfall: 18 px Hoehe + Format-Text — der Default-Bar
        # ist 8 px, daher hier explizit hochgesetzt damit die
        # ``"Schritt %v von %m"``-Beschriftung lesbar bleibt P2-Hotfix).
        self._progress = FinlaiProgressBar(total=4)
        self._progress.setFixedHeight(18)
        self._progress.setValue(1)
        self._progress.setTextVisible(True)
        self._progress.setFormat("Schritt %v von %m")
        root.addWidget(self._progress)

        # Seiten
        self._stack = QStackedWidget()
        na_kwargs = {
            "na_keys": self._na_keys,
            "na_nutzungs_keys": self._na_nutzungs_keys,
            "na_audit_datum": self._na_audit_datum,
        }
        self._seite_dsgvo = _DsgvoSeite(**na_kwargs)
        self._seite_phishing = _PhishingSeite(**na_kwargs)
        self._seite_mfa = _MfaSeite(**na_kwargs)
        self._seite_pm = _PasswortManagerSeite(**na_kwargs)
        for seite in (
            self._seite_dsgvo,
            self._seite_phishing,
            self._seite_mfa,
            self._seite_pm,
        ):
            self._stack.addWidget(seite)
        root.addWidget(self._stack, stretch=1)

        # Navigation
        nav = QHBoxLayout()
        nav.setSpacing(8)
        self._btn_zurueck = QPushButton("Zurück")
        self._btn_zurueck.setEnabled(False)
        self._btn_zurueck.clicked.connect(self._auf_zurueck)
        self._btn_zurueck.setStyleSheet(self._btn_style())
        nav.addWidget(self._btn_zurueck)

        nav.addStretch()

        self._btn_abbrechen = QPushButton("Abbrechen")
        self._btn_abbrechen.clicked.connect(self.reject)
        self._btn_abbrechen.setStyleSheet(self._btn_style())
        nav.addWidget(self._btn_abbrechen)

        self._btn_weiter = QPushButton("Weiter")
        self._btn_weiter.clicked.connect(self._auf_weiter)
        self._btn_weiter.setStyleSheet(self._btn_style(accent=True))
        nav.addWidget(self._btn_weiter)

        root.addLayout(nav)

    def _vorbefuellen_aus_letztem(self) -> None:
        """Befüllt die Seiten aus dem zuletzt gespeicherten Assessment.

        Behebt den vom Live-Test gemeldeten „organisatorische Sicherheit
        speichert nicht": ohne Vorbefüllung startete der Wizard nach jedem
        Öffnen leer (als wäre nichts gespeichert) — und ein erneutes Speichern
        aus dem leeren Wizard überschrieb die alten Antworten mit ``UNBEKANNT``
        (Folge-Symptom: Risikomatrix/Score kippt).

        Vervollständigt Mechanismus 2 („jüngere konkrete Antwort gewinnt"):
        die N/A-Vorbelegung aus aktuellem Profil/Nutzung bleibt für *unbeantwortete*
        Fragen erhalten (``set_antwort(UNBEKANNT)`` ist no-op), konkrete gespeicherte
        Antworten überschreiben sie. Fail-soft: jeder Fehler lässt den Wizard
        einfach frisch starten (nie Crash).
        """
        try:
            letztes = self._service.lade_letztes()
        except Exception as exc:  # noqa: BLE001 -- Vorbefüllung darf den Wizard nie crashen
            log.warning(
                "Org-Assessment-Vorbefüllung fehlgeschlagen: %s", type(exc).__name__
            )
            return
        if letztes is None:
            return
        self._seite_dsgvo.set_antworten(letztes.dsgvo.antworten)
        self._seite_phishing.set_antworten(letztes.phishing.antworten)
        self._seite_mfa.set_antworten(letztes.mfa.antworten)
        self._seite_pm.set_antworten(letztes.passwort_manager.antworten)
        self._seite_pm.set_custom_pm_name(letztes.passwort_manager.custom_pm_name)

    def _auf_weiter(self) -> None:
        """Geht zur nächsten Seite oder speichert auf der letzten."""
        if self._aktuelle_seite < self._stack.count() - 1:
            self._aktuelle_seite += 1
            self._stack.setCurrentIndex(self._aktuelle_seite)
            self._progress.setValue(self._aktuelle_seite + 1)
            self._btn_zurueck.setEnabled(True)
            if self._aktuelle_seite == self._stack.count() - 1:
                self._btn_weiter.setText("Speichern")
            return

        self._speichern()

    def _auf_zurueck(self) -> None:
        """Geht eine Seite zurück."""
        if self._aktuelle_seite <= 0:
            return
        self._aktuelle_seite -= 1
        self._stack.setCurrentIndex(self._aktuelle_seite)
        self._progress.setValue(self._aktuelle_seite + 1)
        self._btn_weiter.setText("Weiter")
        self._btn_zurueck.setEnabled(self._aktuelle_seite > 0)

    def _speichern(self) -> None:
        """Sammelt alle Ergebnisse ein und persistiert das Assessment."""
        try:
            self._service.speichere_assessment(
                dsgvo=self._seite_dsgvo.ergebnis(),
                phishing=self._seite_phishing.ergebnis(),
                mfa=self._seite_mfa.ergebnis(),
                passwort_manager=self._seite_pm.ergebnis(),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Assessment-Speicherung fehlgeschlagen: %s", type(exc).__name__)
            self.reject()
            return

        self.assessment_gespeichert.emit()
        self.accept()

    @staticmethod
    def _btn_style(accent: bool = False) -> str:
        t = theme.get()
        bg = t.ACCENT if accent else t.BG_BUTTON
        text_color = t.BG_MAIN if accent else t.TEXT_MAIN
        return (
            f"QPushButton {{ background-color: {bg}; color: {text_color};"
            f" border: 1px solid {t.BORDER}; border-radius: 4px;"
            f" padding: 6px 16px; font-size: {theme.FONT_SIZE_BODY_SM}px; min-width: 88px; }}"
            f"QPushButton:hover {{ background-color: {t.ACCENT}; color: {t.BG_MAIN};"
            f" border-color: {t.ACCENT}; }}"
            f"QPushButton:disabled {{ background-color: {t.BG_BUTTON_DISABLED};"
            f" color: {t.TEXT_BUTTON_DISABLED}; border-color: {t.BORDER_BUTTON_DISABLED}; }}"
        )
