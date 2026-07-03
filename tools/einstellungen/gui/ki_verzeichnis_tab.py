"""
tools/einstellungen/gui/ki_verzeichnis_tab.py — KI-Verzeichnis + Audit-Trail (KI-VO Art. 4).

Zwei-Tab-Widget:
  Tab 1: KI-Verzeichnis — alle KI-Einsätze, PDF-Export
  Tab 2: KI-Audit-Trail — letzte 50 KI-Aktionen, Filter, CSV-Export

Schichtzugehörigkeit: gui/ (darf application/, domain/, core/ importieren).

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.audit_log import _AUDIT_DIR
from core.dialogs import FinlaiInfoDialog, FinlaiSuccessDialog
from core.icons import Icons, get_icon
from core.ki_verzeichnis.ki_verzeichnis_service import KiEintrag, KiVerzeichnisService

_LOGO_PATH = Path(__file__).parents[3] / "assets" / "logo" / "finlai_logo.png"

_VERZ_COLS = [
    "Name",
    "Kategorie",
    "Modell",
    "Lokal/Cloud",
    "Zweck",
    "Human Review",
    "Zuletzt aktiv",
]

_AUDIT_COLS = [
    "Zeitpunkt",
    "Tool",
    "Aktion",
    "Modell",
    "Input (Z.)",
    "Output (Z.)",
    "Erfolg",
]

_AUDIT_FILTERS = [
    ("Alle", ""),
    ("Nur Fehler", "fehler"),
    ("Nur Chat", "ollama_chat"),
]

_MAX_AUDIT_ROWS = 50


def _btn_accent(c) -> str:
    return (
        f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.ACCENT};"
        f" border: 1px solid {c.ACCENT}; border-radius: 4px;"
        f" padding: 4px 12px; font-family: 'Raleway'; }}"
        f"QPushButton:hover {{ background: {c.BG_SIDEBAR_HOVER}; }}"
    )


def _btn_normal(c) -> str:
    return (
        f"QPushButton {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
        f" border: 1px solid {c.BORDER}; border-radius: 4px;"
        f" padding: 4px 12px; font-family: 'Raleway'; }}"
        f"QPushButton:hover {{ background: {c.BG_SIDEBAR_HOVER}; }}"
    )


def _table_style(c) -> str:
    return (
        f"QTableWidget {{ background: {c.BG_MAIN}; color: {c.TEXT_MAIN};"
        f" gridline-color: {c.BORDER}; border: 1px solid {c.BORDER};"
        f" font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_SM}px; }}"
        f"QHeaderView::section {{ background: {c.BG_DARK}; color: {c.ACCENT};"
        f" border: none; border-right: 1px solid {c.BORDER};"
        f" padding: 4px 8px; font-weight: bold; }}"
        f"QTableWidget::item:selected {{ background: {c.ACCENT}; color: {c.BG_DARK}; }}"
    )


class KiVerzeichnisTab(QWidget):
    """Zweiseitiger Tab: KI-Verzeichnis + KI-Audit-Trail."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._eintraege: list[KiEintrag] = []
        self._audit_rows: list[dict] = []
        self._service = KiVerzeichnisService()
        self._build_ui()
        from core import theme as _t  # noqa: PLC0415

        _t.register_listener(self.apply_theme)
        self._aktualisieren()
        self._lade_audit()

    # ──────────────────────────────────────────────────────────────────
    # Theme
    # ──────────────────────────────────────────────────────────────────

    def apply_theme(self) -> None:
        """Aktualisiert alle Widget-Farben für das aktive Theme."""
        c = theme.get()
        # Verzeichnis-Tab
        self._lbl_generiert.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; font-family: 'Raleway';"
        )
        self._btn_refresh.setStyleSheet(_btn_accent(c))
        self._btn_pdf.setStyleSheet(_btn_normal(c))
        self._verz_table.setStyleSheet(_table_style(c))
        self._befuelle_verz_tabelle()

        # Audit-Tab
        self._lbl_audit_count.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; font-family: 'Raleway';"
        )
        self._btn_audit_refresh.setStyleSheet(_btn_accent(c))
        self._btn_csv.setStyleSheet(_btn_normal(c))
        self._filter_combo.setStyleSheet(
            f"QComboBox {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 2px 8px; font-family: 'Raleway'; }}"
        )
        self._audit_table.setStyleSheet(_table_style(c))
        self._befuelle_audit_tabelle()

    # ──────────────────────────────────────────────────────────────────
    # Build UI
    # ──────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        c = theme.get()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Logo + Titel (gemeinsamer Header) ────────────────────────
        header_row = QHBoxLayout()
        header_row.setContentsMargins(20, 12, 20, 8)
        header_row.setSpacing(12)

        logo_lbl = QLabel()
        logo_lbl.setFixedSize(40, 40)
        logo_lbl.setStyleSheet("background: transparent; border: none;")
        pixmap = QPixmap(str(_LOGO_PATH))
        if not pixmap.isNull():
            logo_lbl.setPixmap(
                pixmap.scaled(
                    40,
                    40,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        else:
            logo_lbl.setText("FINLAI")
            logo_lbl.setStyleSheet(
                f"color: {c.ACCENT}; font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY}px; font-weight: bold;"
            )
        header_row.addWidget(logo_lbl)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        lbl_title = QLabel("KI-Verzeichnis & Audit-Trail")
        lbl_title.setStyleSheet(
            f"font-family: 'Raleway'; font-size: {theme.FONT_SIZE_BODY_LG}px; font-weight: bold; color: {c.ACCENT};"
        )
        lbl_subtitle = QLabel("EU KI-VO Art. 4 — Nachvollziehbarkeit KI-Einsätze")
        lbl_subtitle.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; font-family: 'Raleway';"
        )
        title_col.addWidget(lbl_title)
        title_col.addWidget(lbl_subtitle)
        header_row.addLayout(title_col)
        header_row.addStretch()
        outer.addLayout(header_row)

        # ── Interner Tab-Widget ──────────────────────────────────────
        self._inner_tabs = QTabWidget()
        self._inner_tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: none; border-top: 1px solid {c.BORDER}; }}"
            f"QTabBar::tab {{ background: {c.BG_BUTTON}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-bottom: none;"
            f" border-radius: 4px 4px 0 0; padding: 5px 14px; font-family: 'Raleway'; }}"
            f"QTabBar::tab:selected {{ background: {c.ACCENT}; color: {c.BG_DARK};"
            f" font-weight: bold; }}"
        )
        self._inner_tabs.addTab(
            self._build_verzeichnis_tab(), get_icon(Icons.KNOWLEDGE), "KI-Verzeichnis"
        )
        self._inner_tabs.addTab(
            self._build_audit_tab(), get_icon(Icons.SCHEDULE), "KI-Audit-Trail"
        )
        outer.addWidget(self._inner_tabs, stretch=1)

    def _build_verzeichnis_tab(self) -> QWidget:
        """Baut den Verzeichnis-Tab-Inhalt."""
        c = theme.get()
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Statuszeile
        status_row = QHBoxLayout()
        self._lbl_generiert = QLabel("—")
        self._lbl_generiert.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; font-family: 'Raleway';"
        )
        status_row.addWidget(self._lbl_generiert)
        status_row.addStretch()

        self._btn_refresh = QPushButton("Aktualisieren")
        self._btn_refresh.setFixedHeight(28)
        self._btn_refresh.clicked.connect(self._aktualisieren)
        status_row.addWidget(self._btn_refresh)

        self._btn_pdf = QPushButton("Als PDF exportieren")
        self._btn_pdf.setFixedHeight(28)
        self._btn_pdf.clicked.connect(self._export_pdf)
        status_row.addWidget(self._btn_pdf)
        layout.addLayout(status_row)

        # Tabelle
        self._verz_table = QTableWidget(0, len(_VERZ_COLS))
        self._verz_table.setHorizontalHeaderLabels(_VERZ_COLS)
        self._verz_table.horizontalHeader().setStretchLastSection(True)
        self._verz_table.verticalHeader().setVisible(False)
        self._verz_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._verz_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._verz_table.setAlternatingRowColors(True)
        for i, w_px in enumerate([170, 90, 140, 90, 200, 90, 130]):
            self._verz_table.setColumnWidth(i, w_px)
        layout.addWidget(self._verz_table, stretch=1)

        return w

    def _build_audit_tab(self) -> QWidget:
        """Baut den Audit-Trail-Tab-Inhalt."""
        c = theme.get()
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Filterzeile
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        lbl_filter = QLabel("Filter:")
        lbl_filter.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_BODY_SM}px; font-family: 'Raleway';"
        )
        filter_row.addWidget(lbl_filter)

        self._filter_combo = QComboBox()
        self._filter_combo.setFixedHeight(28)
        for label, _ in _AUDIT_FILTERS:
            self._filter_combo.addItem(label)
        self._filter_combo.currentIndexChanged.connect(self._befuelle_audit_tabelle)
        filter_row.addWidget(self._filter_combo)
        filter_row.addStretch()

        self._lbl_audit_count = QLabel("—")
        self._lbl_audit_count.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION}px; font-family: 'Raleway';"
        )
        filter_row.addWidget(self._lbl_audit_count)

        self._btn_audit_refresh = QPushButton("Aktualisieren")
        self._btn_audit_refresh.setFixedHeight(28)
        self._btn_audit_refresh.clicked.connect(self._lade_audit)
        filter_row.addWidget(self._btn_audit_refresh)

        self._btn_csv = QPushButton("Als CSV exportieren")
        self._btn_csv.setFixedHeight(28)
        self._btn_csv.clicked.connect(self._export_csv)
        filter_row.addWidget(self._btn_csv)

        layout.addLayout(filter_row)

        # Tabelle
        self._audit_table = QTableWidget(0, len(_AUDIT_COLS))
        self._audit_table.setHorizontalHeaderLabels(_AUDIT_COLS)
        self._audit_table.horizontalHeader().setStretchLastSection(True)
        self._audit_table.verticalHeader().setVisible(False)
        self._audit_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._audit_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._audit_table.setAlternatingRowColors(True)
        for i, w_px in enumerate([140, 100, 130, 120, 70, 70, 60]):
            self._audit_table.setColumnWidth(i, w_px)
        layout.addWidget(self._audit_table, stretch=1)

        lbl_hinweis = QLabel(
            "ℹ️  Es werden ausschließlich Metadaten geloggt — keine Inhalte, "
            "keine personenbezogenen Daten."
        )
        lbl_hinweis.setWordWrap(True)
        lbl_hinweis.setStyleSheet(
            f"color: {c.TEXT_DIM}; font-size: {theme.FONT_SIZE_CAPTION_XS}px; font-family: 'Raleway'; padding: 4px 0;"
        )
        layout.addWidget(lbl_hinweis)
        return w

    # ──────────────────────────────────────────────────────────────────
    # Verzeichnis-Logik
    # ──────────────────────────────────────────────────────────────────

    def _aktualisieren(self) -> None:
        """Regeneriert das KI-Verzeichnis und befüllt die Tabelle neu."""
        try:
            self._eintraege = self._service.generiere_verzeichnis()
        except (OSError, RuntimeError, ImportError) as exc:
            self._lbl_generiert.setText(f"Fehler: {exc}")
            return
        self._lbl_generiert.setText(
            f"Generiert: {datetime.now().strftime('%d.%m.%Y %H:%M')} "
            f"— {len(self._eintraege)} Einträge"
        )
        self._befuelle_verz_tabelle()

    def _befuelle_verz_tabelle(self) -> None:
        """Füllt die Verzeichnis-Tabelle mit aktuellen Einträgen."""
        c = theme.get()
        warn_color = QColor(c.WARNING)
        warn_bg = QColor(warn_color.red(), warn_color.green(), warn_color.blue(), 40)

        self._verz_table.setRowCount(len(self._eintraege))
        for row, e in enumerate(self._eintraege):
            values = [
                e.name,
                e.kategorie,
                e.modell,
                "lokal" if e.lokal else "Cloud",
                e.zweck,
                "Ja" if e.human_review else "Nein",
                e.zuletzt_aktiv or "—",
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                if not e.lokal:
                    item.setBackground(warn_bg)
                    item.setForeground(QColor(c.WARNING))
                self._verz_table.setItem(row, col, item)

    # ──────────────────────────────────────────────────────────────────
    # Audit-Trail-Logik
    # ──────────────────────────────────────────────────────────────────

    def _lade_audit(self) -> None:
        """Liest KI_* Einträge aus den Audit-Log-Dateien."""
        rows: list[dict] = []
        try:
            # Aktuelle + vorherige Monatsdatei lesen
            for log_file in sorted(_AUDIT_DIR.glob("audit_*.log"), reverse=True)[:2]:
                try:
                    for line in log_file.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        if str(entry.get("action", "")).startswith("KI_"):
                            rows.append(entry)
                except (OSError, json.JSONDecodeError):
                    continue
        except (OSError, RuntimeError):
            pass

        # Neueste zuerst, max. 50
        rows.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
        self._audit_rows = rows[:_MAX_AUDIT_ROWS]
        self._befuelle_audit_tabelle()

    def _befuelle_audit_tabelle(self) -> None:
        """Füllt die Audit-Tabelle nach aktivem Filter."""
        c = theme.get()
        filter_idx = (
            self._filter_combo.currentIndex() if hasattr(self, "_filter_combo") else 0
        )
        _, filter_val = _AUDIT_FILTERS[filter_idx]

        rows = self._audit_rows
        if filter_val == "fehler":
            rows = [
                r for r in rows if not r.get("details", {}).get("erfolgreich", True)
            ]
        elif filter_val:
            rows = [
                r for r in rows if r.get("details", {}).get("tool", "") == filter_val
            ]

        err_bg = QColor(theme.get().DANGER)
        err_bg_t = QColor(err_bg.red(), err_bg.green(), err_bg.blue(), 40)

        self._audit_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            d = entry.get("details", {})
            erfolg = d.get("erfolgreich", True)
            values = [
                entry.get("timestamp", "—"),
                d.get("tool", "—"),
                entry.get("action", "—"),
                d.get("modell", "—"),
                str(d.get("input_zeichen", "—")),
                str(d.get("output_zeichen", "—")),
                "OK" if erfolg else "FEHLER",
            ]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                if not erfolg:
                    item.setBackground(err_bg_t)
                    item.setForeground(QColor(c.DANGER))
                self._audit_table.setItem(row, col, item)

        self._lbl_audit_count.setText(
            f"{len(rows)} von {len(self._audit_rows)} Einträgen"
        )

    # ──────────────────────────────────────────────────────────────────
    # PDF-Export
    # ──────────────────────────────────────────────────────────────────

    def _export_pdf(self) -> None:
        """Exportiert das KI-Verzeichnis als PDF mit FINLAI-Logo."""
        if not self._eintraege:
            FinlaiInfoDialog(
                title="Kein Inhalt",
                message="Bitte zuerst 'Aktualisieren' klicken.",
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "KI-Verzeichnis als PDF speichern",
            str(Path.home() / "ki_verzeichnis_finlai.pdf"),
            "PDF-Dateien (*.pdf)",
        )
        if not path:
            return
        try:
            self._erstelle_pdf(path)
            FinlaiSuccessDialog(
                title="PDF exportiert",
                message="Gespeichert:",
                file_path=str(path),
                parent=self,
            ).exec()
        except (OSError, RuntimeError, ImportError, ValueError) as exc:
            FinlaiInfoDialog(
                title="PDF-Fehler",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()

    def _erstelle_pdf(self, path: str) -> None:
        """Erstellt die PDF-Datei mit ReportLab.

        Args:
            path: Ziel-Dateipfad.
        """
        # ------------------------------------------------------------------
        # SPRIN-MIGRATIONS-AUFGABE (Subagent A, 2026-04-27):
        # Dieser ReportLab-PDF-Block enthält 6 hardcodierte Hex-Werte
        # (NEONBLAU, ANTHRAZIT, CLOUD_BG, WEISS, F5F5F5, CCCCCC, FFA726).
        # Migration nach core/pdf/pdf_light_colors.py wird als separates
        # Sprint-2-Ticket gepflegt — keine mechanische Hex-Ersetzung in
        # Sprint 1, da PDF-Light-Theme abweichende Semantik hat (Cloud-
        # Highlight-Row braucht eigene "warning"-Variante; NEONBLAU ist
        # Customer-Risiko-Palette, nicht Theme-Akzent).
        # ------------------------------------------------------------------
        from reportlab.lib import colors  # noqa: PLC0415
        from reportlab.lib.pagesizes import A4, landscape  # noqa: PLC0415
        from reportlab.lib.styles import getSampleStyleSheet  # noqa: PLC0415
        from reportlab.lib.units import cm  # noqa: PLC0415
        from reportlab.platypus import (  # noqa: PLC0415
            Image,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        NEONBLAU = colors.HexColor("#00D4FF")  # noqa: sprint2-pdf-migration
        ANTHRAZIT = colors.HexColor("#1E1E1E")  # noqa: sprint2-pdf-migration
        CLOUD_BG = colors.HexColor("#3D2800")  # noqa: sprint2-pdf-migration
        WEISS = colors.white

        doc = SimpleDocTemplate(
            path,
            pagesize=landscape(A4),
            leftMargin=1.5 * cm,
            rightMargin=1.5 * cm,
            topMargin=2 * cm,
            bottomMargin=1.5 * cm,
        )
        styles = getSampleStyleSheet()
        story = []

        # Header mit Logo
        header_data: list = []
        if _LOGO_PATH.exists():
            header_data.append(Image(str(_LOGO_PATH), width=1.2 * cm, height=1.2 * cm))
        else:
            header_data.append(Paragraph("FINLAI", styles["Normal"]))

        header_data.append(
            Paragraph(
                f'<font color="#00D4FF" face="Helvetica-Bold" size="16">'  # noqa: sprint2-pdf-migration
                f"FINLAI — KI-Verzeichnis</font><br/>"
                f'<font color="#888888" size="9">'  # noqa: sprint2-pdf-migration
                f"EU KI-VO Art. 4 · Generiert: "
                f"{datetime.now().strftime('%d.%m.%Y %H:%M')}</font>",
                styles["Normal"],
            )
        )
        header_tbl = Table([header_data], colWidths=[1.6 * cm, None])
        header_tbl.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(header_tbl)
        story.append(Spacer(1, 0.4 * cm))

        col_widths_pdf = [
            4.5 * cm,
            2.5 * cm,
            4 * cm,
            2.5 * cm,
            6 * cm,
            2.5 * cm,
            3.5 * cm,
        ]
        tbl_data = [_VERZ_COLS[:]]
        cloud_rows: list[int] = []
        for i, e in enumerate(self._eintraege, start=1):
            tbl_data.append(
                [
                    e.name,
                    e.kategorie,
                    e.modell,
                    "lokal" if e.lokal else "Cloud (!)",
                    e.zweck,
                    "Ja" if e.human_review else "Nein",
                    e.zuletzt_aktiv or "—",
                ]
            )
            if not e.lokal:
                cloud_rows.append(i)

        tbl = Table(tbl_data, colWidths=col_widths_pdf, repeatRows=1)
        tbl_style = [
            ("BACKGROUND", (0, 0), (-1, 0), ANTHRAZIT),
            ("TEXTCOLOR", (0, 0), (-1, 0), NEONBLAU),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WEISS, colors.HexColor("#F5F5F5")]),  # noqa: sprint2-pdf-migration
            ("TEXTCOLOR", (0, 1), (-1, -1), ANTHRAZIT),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),  # noqa: sprint2-pdf-migration
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]
        for r in cloud_rows:
            tbl_style.append(("BACKGROUND", (0, r), (-1, r), CLOUD_BG))
            tbl_style.append(("TEXTCOLOR", (0, r), (-1, r), colors.HexColor("#FFA726")))  # noqa: sprint2-pdf-migration
        tbl.setStyle(TableStyle(tbl_style))
        story.append(tbl)
        story.append(Spacer(1, 0.3 * cm))
        story.append(
            Paragraph(
                '<font color="#888888" size="8">'  # noqa: sprint2-pdf-migration
                "[WARN] Cloud-Einträge (orange) verarbeiten Daten außerhalb des lokalen Systems. "
                "DSGVO-Einwilligung der Mandanten beachten."
                "</font>",
                styles["Normal"],
            )
        )
        doc.build(story)

    # ──────────────────────────────────────────────────────────────────
    # CSV-Export
    # ──────────────────────────────────────────────────────────────────

    def _export_csv(self) -> None:
        """Exportiert den KI-Audit-Trail als CSV für Compliance-Nachweis."""
        if not self._audit_rows:
            FinlaiInfoDialog(
                title="Keine Daten",
                message="Noch keine KI-Aktionen geloggt.",
                icon_name=Icons.INFO,
                parent=self,
            ).exec()
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "KI-Audit-Trail als CSV speichern",
            str(Path.home() / "ki_audit_trail.csv"),
            "CSV-Dateien (*.csv)",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.writer(fh, delimiter=";")
                writer.writerow(_AUDIT_COLS)
                for entry in self._audit_rows:
                    d = entry.get("details", {})
                    writer.writerow(
                        [
                            entry.get("timestamp", ""),
                            d.get("tool", ""),
                            entry.get("action", ""),
                            d.get("modell", ""),
                            d.get("input_zeichen", ""),
                            d.get("output_zeichen", ""),
                            "Ja" if d.get("erfolgreich", True) else "Nein",
                        ]
                    )
            FinlaiSuccessDialog(
                title="CSV exportiert",
                message="Gespeichert:",
                file_path=str(path),
                parent=self,
            ).exec()
        except (OSError, RuntimeError, ValueError) as exc:
            FinlaiInfoDialog(
                title="CSV-Fehler",
                message=str(exc),
                icon_name=Icons.ERROR,
                parent=self,
            ).exec()
