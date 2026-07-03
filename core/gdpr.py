"""
gdpr — DSGVO-Hinweis und Datenschutzverwaltung für FINLAI

Zeigt beim ersten Start einen Datenschutzhinweis-Dialog an und verwaltet
die Zustimmung des Nutzers. Bietet außerdem Funktionen zur Verwaltung
der Audit-Log-Dateien im Sinne des DSGVO-Löschrechts.

Zustimmung wird gespeichert in: ``~/.finlai/gdpr.json``
Audit-Logs befinden sich in: ``~/.finlai/audit/``

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.audit_log import AuditLogger
from core.finlai_paths import finlai_dir
from core.icons import get_icon
from core.logger import get_logger
from core.theme import (
    BG_PANEL_DARK,
    BG_PANEL_LIGHT,
    DARK_ACCENT,
    DARK_ACCENT_DIM,
    DARK_BG_PRIMARY,
    DARK_BG_SECONDARY,
    DARK_BORDER,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
    TEXT_ON_ACCENT_DEEP,
)

log = get_logger(__name__)

_GDPR_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
_FINLAI_DIR = finlai_dir()
_AUDIT_DIR = _FINLAI_DIR / "audit"
_GDPR_FILE = _FINLAI_DIR / "gdpr.json"

_GDPR_TEXT = (
    "FINLAI verarbeitet keine Daten online. "
    "Alle Daten bleiben ausschließlich auf Ihrem lokalen Gerät.\n\n"
    "Folgende Metadaten werden in einer lokalen Audit-Log-Datei gespeichert:\n"
    "  •  Aktionen innerhalb der App\n"
    "  •  Dateinamen geladener Dateien\n"
    "  •  Zeitstempel der Aktionen\n\n"
    "Kein Dateiinhalt wird gespeichert. Keine Daten werden übertragen.\n\n"
    "Mit „Verstanden\" akzeptieren Sie diese Bedingungen und können FINLAI nutzen."
)


# ---------------------------------------------------------------------------
# GDPRManager
# ---------------------------------------------------------------------------
class GDPRManager:
    """Verwaltet den DSGVO-Hinweis und das Löschrecht für Audit-Logs."""

    def __init__(self) -> None:
        """Initialisiert den GDPRManager und erstellt das finlai-Verzeichnis."""
        _FINLAI_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def show_first_run_dialog(
        self,
        app: QApplication,  # noqa: ARG002
        parent: QWidget | None = None,
        runner: Callable[[QDialog], int] | None = None,
    ) -> bool:
        """Zeigt den DSGVO-Hinweis-Dialog beim ersten Start.

        Args:
            app: Laufende QApplication (nicht aktiv genutzt, Rückwärtskompat.).
            parent: Elternfenster (typ. StartupWindow). Ohne Parent stapelt
                    sich der Dialog unter maximierten Hauptfenstern.
            runner: Optionaler Anzeige-Callback (typ. ``StartupWindow.
                    run_embedded``), der den Dialog als eingebettete Seite statt
                    als Popup zeigt und den Result-Code zurückgibt. Ohne
                    ``runner`` fällt die Methode auf den klassischen modalen
                    ``exec``-Pfad zurück (z. B. in Tests).

        Returns:
            True wenn zugestimmt (oder bereits zugestimmt), sonst False.
        """
        if self._is_already_accepted():
            log.debug("DSGVO-Zustimmung bereits vorhanden.")
            return True

        log.info("Erster Start — zeige DSGVO-Dialog.")
        dialog = _GDPRDialog(parent=parent)
        if runner is not None:
            result = runner(dialog)
        else:
            dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
            dialog.raise_()
            dialog.activateWindow()
            result = dialog.exec()
        now = datetime.now().isoformat(timespec="seconds")

        if result == QDialog.DialogCode.Accepted:
            self._save_acceptance(now)
            AuditLogger().log_action(
                "GDPR_ACCEPTED",
                {"version": _GDPR_VERSION, "accepted_at": now},
            )
            log.info("DSGVO-Zustimmung gespeichert.")
            return True

        AuditLogger().log_action(
            "GDPR_DECLINED",
            {"version": _GDPR_VERSION, "accepted_at": now},
        )
        log.info("DSGVO abgelehnt — Anwendung wird beendet.")
        return False

    # ------------------------------------------------------------------
    def get_audit_log_path(self) -> str:
        """Gibt den Pfad zum aktuellen Audit-Log-Verzeichnis zurück."""
        return str(_AUDIT_DIR)

    # ------------------------------------------------------------------
    def delete_audit_logs(self) -> None:
        """Löscht alle Audit-Log-Dateien (DSGVO-Löschrecht)."""
        if not _AUDIT_DIR.exists():
            log.info("Audit-Verzeichnis existiert nicht — nichts zu löschen.")
            return

        deleted_count = 0
        for log_file in _AUDIT_DIR.glob("audit_*.log"):
            try:
                log_file.unlink()
                deleted_count += 1
                log.info("Audit-Log gelöscht: %s", log_file.name)
            except OSError as exc:
                log.error("Fehler beim Löschen von %s: %s", log_file.name, exc)
                raise

        log.info("DSGVO-Löschung abgeschlossen — %d Datei(en) entfernt.", deleted_count)

    # ------------------------------------------------------------------
    def update_username(self, username: str) -> None:
        """Ergänzt die Zustimmungs-Datei um den Admin-Usernamen.

        Wird nach erfolgreichem First-Run-Wizard aufgerufen, damit der
        zustimmende Benutzer eindeutig zuordenbar ist. Schreibt nichts,
        wenn noch keine Zustimmung existiert — in dem Fall legt der
        Wizard keine DSGVO-Zustimmung an (das macht das Bootstrap).

        Args:
            username: Username des im Wizard angelegten Admins.
        """
        if not _GDPR_FILE.exists():
            return
        try:
            data = json.loads(_GDPR_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            log.warning("gdpr.json unlesbar — update_username ignoriert.")
            return
        data["user_name"] = username
        try:
            _GDPR_FILE.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            log.error("gdpr.json konnte nicht aktualisiert werden: %s", exc)

    # ------------------------------------------------------------------
    def _is_already_accepted(self) -> bool:
        """Prüft ob der Nutzer die DSGVO bereits akzeptiert hat."""
        if not _GDPR_FILE.exists():
            return False
        try:
            data = json.loads(_GDPR_FILE.read_text(encoding="utf-8"))
            return bool(data.get("accepted", False))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return False

    def _save_acceptance(self, accepted_at: str) -> None:
        """Speichert die DSGVO-Zustimmung in ``~/.finlai/gdpr.json``."""
        data = {
            "accepted": True,
            "accepted_at": accepted_at,
            "version": _GDPR_VERSION,
        }
        try:
            _GDPR_FILE.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            log.error("DSGVO-Zustimmung konnte nicht gespeichert werden: %s", exc)


# ---------------------------------------------------------------------------
# DSGVO-Dialog (intern)
# ---------------------------------------------------------------------------
class _GDPRDialog(QDialog):
    """Modaler DSGVO-Dialog — Dark-Theme, FINLAI Teal, 640x480."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Datenschutzhinweis")
        self.setModal(True)
        self.setFixedSize(640, 480)
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.CustomizeWindowHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        self._build_ui()

    # ------------------------------------------------------------------
    # Keyboard & Close
    # ------------------------------------------------------------------

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: D401
        """Escape schließt den Dialog als Ablehnung."""
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
            event.accept()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """X-Button zählt ebenfalls als Ablehnung."""
        self.reject()
        event.accept()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Erstellt die Dialog-Oberfläche im Dark-Theme."""
        self.setStyleSheet(f"QDialog {{ background-color: {DARK_BG_PRIMARY}; }}")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Header
        header = QWidget()
        header.setFixedHeight(72)
        header.setStyleSheet(
            f"background-color: {DARK_BG_SECONDARY};"
            f" border-bottom: 1px solid {DARK_BORDER};"
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)
        header_layout.setSpacing(14)

        icon_label = QLabel()
        icon_label.setFixedSize(32, 32)
        icon_label.setPixmap(
            get_icon("privacy_tip", color=DARK_ACCENT).pixmap(32, 32)
        )
        icon_label.setStyleSheet("background: transparent; border: none;")
        header_layout.addWidget(icon_label)

        title = QLabel("Datenschutzhinweis")
        title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 18px; font-weight: bold;"
            f" color: {DARK_ACCENT}; background: transparent;"
        )
        header_layout.addWidget(title)
        header_layout.addStretch(1)

        outer.addWidget(header)

        # Body
        body = QWidget()
        body.setStyleSheet(f"background-color: {DARK_BG_PRIMARY};")
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(32, 24, 32, 16)
        body_layout.setSpacing(16)

        text_label = QLabel(_GDPR_TEXT)
        text_label.setWordWrap(True)
        text_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        text_label.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 13px;"
            f" color: {DARK_TEXT_PRIMARY}; background: transparent;"
            f" line-height: 140%;"
        )
        body_layout.addWidget(text_label, stretch=1)

        hint = QLabel(
            "Version "
            f"{_GDPR_VERSION}  •  Zustimmung wird lokal in ~/.finlai/gdpr.json gespeichert."
        )
        hint.setStyleSheet(
            f"font-family: 'Raleway'; font-size: 11px;"
            f" color: {DARK_TEXT_SECONDARY}; background: transparent;"
        )
        body_layout.addWidget(hint)

        outer.addWidget(body, stretch=1)

        # Footer
        footer = QWidget()
        footer.setFixedHeight(72)
        footer.setStyleSheet(
            f"background-color: {DARK_BG_SECONDARY};"
            f" border-top: 1px solid {DARK_BORDER};"
        )
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(24, 0, 24, 0)
        footer_layout.setSpacing(12)
        footer_layout.addStretch(1)

        btn_exit = QPushButton("Beenden")
        btn_exit.setFixedHeight(40)
        btn_exit.setMinimumWidth(120)
        btn_exit.setStyleSheet(
            "QPushButton {"
            f" background-color: {BG_PANEL_DARK}; color: {DARK_TEXT_PRIMARY};"
            f" border: 1px solid {DARK_BORDER}; border-radius: 6px;"
            " font-family: 'Raleway'; font-size: 13px; padding: 0 16px;"
            f"}} QPushButton:hover {{ background-color: {BG_PANEL_LIGHT}; }}"
        )
        btn_exit.clicked.connect(self.reject)
        footer_layout.addWidget(btn_exit)

        btn_accept = QPushButton("Verstanden")
        btn_accept.setFixedHeight(40)
        btn_accept.setMinimumWidth(140)
        btn_accept.setDefault(True)
        btn_accept.setStyleSheet(
            "QPushButton {"
            f" background-color: {DARK_ACCENT}; color: {TEXT_ON_ACCENT_DEEP};"
            " border: none; border-radius: 6px;"
            " font-family: 'Raleway'; font-size: 13px; font-weight: bold;"
            " padding: 0 20px;"
            "} QPushButton:hover {"
            f" background-color: {DARK_ACCENT_DIM};"
            "}"
        )
        btn_accept.clicked.connect(self.accept)
        footer_layout.addWidget(btn_accept)

        outer.addWidget(footer)
