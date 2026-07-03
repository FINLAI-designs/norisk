"""field_styles — Geteilte Eingabefeld-Styles fuer die Audit-Wizard-Steps.

EINE Quelle fuer QLineEdit/QTextEdit/QComboBox-Styling. Vorher
duplizierte jeder Step seinen eigenen ``_input_style``/``_combo_style`` mit
driftenden Werten (1px- vs. 2px-Rahmen, ``ACCENT`` vs. ``BORDER_FOCUS`` beim
Fokus) — dadurch hoben sich Textfelder und Dropdowns beim Fokus
unterschiedlich hervor und Dropdowns sprangen je nach Inhalt in der Breite.

Die Helfer hier vereinheitlichen die Fokus-Hervorhebung auf
``DARK_BORDER_FOCUS`` (helles Teal, identisch zur globalen
``core/theme.py``-Regel ``QLineEdit:focus``) und geben den Dropdowns eine
feste Mindestbreite.

Effekt: konsumiert von allen ``tools/customer_audit/gui/step_widgets/*``-Steps
und vom ``_CustomRiskDialog`` (``risk_matrix_step``). Wer die Fokus-Farbe oder
die Dropdown-Breite aendern will, aendert es HIER — nicht pro Step. ``ACCENT``
ist white-label-konfigurierbar; ``DARK_BORDER_FOCUS`` ist die feste,
strukturelle Fokus-Farbe (analog zur globalen Theme-Regel).

Schichtzugehoerigkeit: gui/ — nur UI-Logik.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core import theme
from core.theme import DARK_BORDER_FOCUS

COMBO_MIN_WIDTH = 200
"""Feste Mindestbreite (px) fuer Audit-Dropdowns.

Effekt: Default-Argument von :func:`combo_style`; verhindert, dass eine
QComboBox je nach Inhalt in der Breite springt (T-397). Pro Step
ueberschreibbar, wenn ein Dropdown breiter sein muss.
"""

FIELD_MIN_WIDTH = COMBO_MIN_WIDTH
"""Feste Breite (px) fuer QLineEdit-Eingabefelder in den Audit-Steps (T-433).

Effekt: Default-Argument von :func:`input_style`. QLineEdit bekommt
``min-width == max-width`` (analog zur Dropdown-Fixierung in
:func:`combo_style`/T-416), damit Eingabefelder NICHT auf die volle
Widget-Breite wachsen, sondern konsistent gleich breit wie die Dropdowns
bleiben — in einem QFormLayout fluchten Textfelder und Combos dadurch in
einer Spalte. Bewusst gleich :data:`COMBO_MIN_WIDTH`. Pro Feld
ueberschreibbar (Argument von :func:`input_style`), wenn ein Eingabefeld
breiter sein muss. Betrifft NICHT :func:`textedit_style` (mehrzeilige
Freitextfelder bleiben voll breit).
"""


def input_style(
    fixed_width: int = FIELD_MIN_WIDTH, border_color: str | None = None
) -> str:
    """QSS fuer QLineEdit in den Audit-Steps: Fokus + feste Feldbreite.

    Args:
        fixed_width: Feste Breite in px (Default:data:`FIELD_MIN_WIDTH` ==
:data:`COMBO_MIN_WIDTH`). ``min-width == max-width``, damit das
            Feld nicht auf volle Breite waechst.
        border_color: Optionale Rahmenfarbe fuer den Normal-State (z.B.
            ``c.DANGER`` im Validierungs-Fehlerfall). ``None`` -> ``c.BORDER``.
            Erlaubt einen Fehler-State OHNE die Breiten-Fixierung zu verlieren
            (vorher schrieb der Fehlerpfad ein eigenes QSS ohne max-width und
            das Feld sprang auf volle Breite).

    Returns:
        QSS-Block mit Normal- und ``:focus``-State (2px ``DARK_BORDER_FOCUS``).
    """
    c = theme.get()
    border = border_color or c.BORDER
    return (
        f"QLineEdit {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
        f" border: 2px solid {border}; border-radius: 4px; padding: 5px 8px;"
        # min-width == max-width -> Eingabefeld bleibt fest, statt bei
        # Widget-Verbreiterung auf volle Breite zu wachsen (analog fuer
        # Combos). Inhalt scrollt horizontal, geht nicht verloren.
        f" min-width: {fixed_width}px; max-width: {fixed_width}px; }}"
        f"QLineEdit:focus {{ border: 2px solid {DARK_BORDER_FOCUS};"
        f" background: {c.BG_INPUT_FOCUS}; }}"
    )


def spinbox_style(fixed_width: int = FIELD_MIN_WIDTH) -> str:
    """QSS fuer QSpinBox/QDoubleSpinBox in den Audit-Steps: Fokus + feste Breite.

    Spiegelt:func:`input_style` fuer numerische Felder. Ohne diesen Style
    erben die Spinboxen nur das globale ``core/theme.py``-Grundstyling OHNE
    Breitenbegrenzung und wachsen im QFormLayout auf die volle Spaltenbreite
    (= die „unendlich lange Felder"-Beschwerde). ``min-width == max-width``
    fixiert sie buendig zu den QLineEdit-/QComboBox-Feldern.

    Args:
        fixed_width: Feste Breite in px (Default:data:`FIELD_MIN_WIDTH`).

    Returns:
        QSS-Block mit Normal- und ``:focus``-State (2px ``DARK_BORDER_FOCUS``).
    """
    c = theme.get()
    return (
        f"QSpinBox, QDoubleSpinBox {{ background: {c.BG_INPUT};"
        f" color: {c.TEXT_MAIN}; border: 2px solid {c.BORDER};"
        f" border-radius: 4px; padding: 5px 8px;"
        f" min-width: {fixed_width}px; max-width: {fixed_width}px; }}"
        f"QSpinBox:focus, QDoubleSpinBox:focus {{"
        f" border: 2px solid {DARK_BORDER_FOCUS};"
        f" background: {c.BG_INPUT_FOCUS}; }}"
    )


def textedit_style() -> str:
    """QSS fuer QTextEdit in den Audit-Steps inkl. Fokus-Hervorhebung.

    Returns:
        QSS-Block mit Normal- und ``:focus``-State (2px ``DARK_BORDER_FOCUS``).
    """
    c = theme.get()
    return (
        f"QTextEdit {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
        f" border: 2px solid {c.BORDER}; border-radius: 4px; padding: 4px 8px; }}"
        f"QTextEdit:focus {{ border: 2px solid {DARK_BORDER_FOCUS};"
        f" background: {c.BG_INPUT_FOCUS}; }}"
    )


def combo_style(min_width: int = COMBO_MIN_WIDTH) -> str:
    """QSS fuer QComboBox in den Audit-Steps: Fokus + feste Mindestbreite.

    Args:
        min_width: Mindestbreite in px (Default:data:`COMBO_MIN_WIDTH`).

    Returns:
        QSS-Block mit Normal-/``:focus``-State, drop-down ohne Rahmen und
        gestyltem Popup (``QAbstractItemView``).
    """
    c = theme.get()
    return (
        f"QComboBox {{ background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
        f" border: 2px solid {c.BORDER}; border-radius: 4px; padding: 5px 8px;"
        # max-width == min-width -> die Combo bleibt fest, statt bei
        # Widget-Verbreiterung "endlos breit" zu wachsen setzte nur die
        # Popup-Breite, nicht die Combo selbst). Popup zeigt den vollen Text.
        f" min-width: {min_width}px; max-width: {min_width}px; }}"
        f"QComboBox:focus {{ border: 2px solid {DARK_BORDER_FOCUS};"
        f" background: {c.BG_INPUT_FOCUS}; }}"
        f"QComboBox::drop-down {{ border: none; }}"
        f"QComboBox QAbstractItemView {{ background: {c.BG_INPUT};"
        f" color: {c.TEXT_MAIN}; selection-background-color: {c.ACCENT}; }}"
    )


def origin_badge_style() -> str:
    """QSS fuer den Herkunfts-Badge der gemessenen SELF-Vorbefuellung Phase 3).

    Dezentes Info-Badge (kein Hardcoding): ``DARK_BORDER_FOCUS`` (Teal) als
    subtiler Mess-Akzent, gedimmter Text. Genutzt von ``infrastructure_step`` und
    ``network_step``, um „gemessen via SH-001 …" theme-konform anzuzeigen.

    Returns:
        QSS-Block fuer ein:class:`QLabel`-Badge.
    """
    c = theme.get()
    return (
        f"QLabel {{ color: {c.TEXT_DIM}; background: {c.BG_INPUT};"
        f" border: 1px solid {DARK_BORDER_FOCUS}; border-radius: 4px;"
        f" padding: 4px 8px; font-size: {theme.FONT_SIZE_CAPTION}px; }}"
    )
