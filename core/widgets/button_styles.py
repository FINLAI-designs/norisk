"""Zentrale QSS-Factories für alle Button-Varianten.

Single Source of Truth für Button-Styling. Hintergrund: Buttons, die in
einem Container mit eigenem ``setStyleSheet`` liegen, bekommen den
Hover-Fill der globalen ``QPushButton:hover``-Regel von Qt NICHT gemalt,
die Hover-``color`` greift aber trotzdem — Resultat: dunkle Schrift auf
dunklem Grund (Bug-Klasse/, Coding-Rules R23 + R26). Jede Factory
liefert deshalb einen vollständigen QSS-Block, der in JEDEM State
(normal/:hover/:pressed/:disabled) ``color``, ``background-color`` und
``border`` explizit setzt.

Varianten (frontend-design Button-Matrix, Patrick-Freigabe 2026-06-10):
    A primary_button_qss — Teal-Fill, Haupt-CTA
    B outline_button_qss — Teal-Rahmen, Sekundär-Aktion
    C link_button_qss — nur Teal-Schrift, Inline-Aktion in Cards
    D toolbar_button_qss — neutraler grauer Button, Werkzeugleisten
    E danger_button_qss — roter Fill, destruktive Aktionen
    F secondary_button_qss — dezenter Dialog-Sekundär ("Abbrechen")

Begleiter, keine QPushButton-Varianten):
    card_menu_button_qss — QToolButton fuer Karten-Menues (InstantPopup)
    status_button_qss — QToolButton mit bedeutungstragender Statusfarbe
    menu_qss — QMenu-Look (global ungestylt)

Verwendung::

    from core.widgets.button_styles import link_button_qss
    btn.setStyleSheet(link_button_qss)

Die Funktionen lesen den aktiven Look zur Laufzeit (``theme.get``) —
bei Theme-Wechsel das Stylesheet im ``apply_theme``-Pfad neu setzen.

Abgrenzung zu ``theme.generate_qss``: Die globalen QPushButton-Regeln
dort bleiben der Default fuer Buttons OHNE Container-Stylesheet; diese
Factories sind die Quelle fuer widget-eigene Stylesheets. Bewusste
Abweichung vom globalen Block: Primary-Schrift nutzt
``TEXT_ON_ACCENT_DEEP`` (kontrastreicher auf Teal als ``BG_DARK``).
Hover-/Pressed-Teal der Link-Variante (``ACCENT_HOVER``/``ACCENT_PRESSED``)
sind statische FINLAI-Aliase — unter White-Label-Accent-Injection bleiben
sie Teal (gleiches Bestandsmuster wie forgot_password_dialog/wizard).
"""

from __future__ import annotations

from core import theme


def link_button_qss() -> str:
    """QSS für Link-/Flat-Buttons (Variante C) — nur Teal-Schrift.

    Für dezente Inline-Aktionen in Cards/Sektionen (z.B. "Tool oeffnen ->").
    Kein Rahmen, kein Hintergrund; Hover hellt die Schrift auf helles Teal
    auf und unterstreicht — kein Fill nötig, damit kaskaden-robust.

    Returns:
        Vollständiger QSS-Block mit allen vier Button-States.
    """
    c = theme.get()
    return (
        "QPushButton {"
        f" color: {c.ACCENT};"
        " background-color: transparent;"
        " border: none;"
        " padding: 4px 8px;"
        " }"
        "QPushButton:hover {"
        f" color: {theme.ACCENT_HOVER};"
        " background-color: transparent;"
        " border: none;"
        " text-decoration: underline;"
        " }"
        "QPushButton:pressed {"
        f" color: {theme.ACCENT_PRESSED};"
        " background-color: transparent;"
        " border: none;"
        " }"
        "QPushButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        " background-color: transparent;"
        " border: none;"
        " }"
    )


def primary_button_qss() -> str:
    """QSS für Primary-Buttons (Variante A) — Teal-Fill, Haupt-CTA.

    Returns:
        Vollständiger QSS-Block mit allen vier Button-States.
    """
    c = theme.get()
    return (
        "QPushButton {"
        f" color: {theme.TEXT_ON_ACCENT_DEEP};"
        f" background-color: {c.ACCENT};"
        f" border: 2px solid {c.ACCENT};"
        " border-radius: 4px;"
        " padding: 6px 14px;"
        " }"
        "QPushButton:hover {"
        f" color: {theme.TEXT_ON_ACCENT_DEEP};"
        f" background-color: {c.ACCENT_DIM};"
        f" border: 2px solid {c.ACCENT_DIM};"
        " }"
        "QPushButton:pressed {"
        f" color: {theme.TEXT_ON_ACCENT_DEEP};"
        f" background-color: {c.ACCENT_DARK};"
        f" border: 2px solid {c.ACCENT_DARK};"
        " padding-top: 7px;"
        " padding-bottom: 5px;"
        " }"
        "QPushButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        f" background-color: {c.BG_BUTTON_DISABLED};"
        f" border: 2px solid {c.BORDER_BUTTON_DISABLED};"
        " }"
    )


def outline_button_qss() -> str:
    """QSS für Outline-/Secondary-Buttons (Variante B) — Teal-Rahmen.

    Hover füllt mit Teal und wechselt auf dunkle Schrift — der Fill wird
    durch das eigene Widget-Stylesheet garantiert gemalt (R23).

    Returns:
        Vollständiger QSS-Block mit allen vier Button-States.
    """
    c = theme.get()
    return (
        "QPushButton {"
        f" color: {c.ACCENT};"
        " background-color: transparent;"
        f" border: 2px solid {c.ACCENT};"
        " border-radius: 4px;"
        " padding: 6px 14px;"
        " }"
        "QPushButton:hover {"
        f" color: {c.BG_DARK};"
        f" background-color: {c.ACCENT};"
        f" border: 2px solid {c.ACCENT};"
        " }"
        "QPushButton:pressed {"
        f" color: {c.BG_DARK};"
        f" background-color: {c.ACCENT_DARK};"
        f" border: 2px solid {c.ACCENT_DARK};"
        " padding-top: 7px;"
        " padding-bottom: 5px;"
        " }"
        "QPushButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        " background-color: transparent;"
        f" border: 2px solid {c.BORDER_BUTTON_DISABLED};"
        " }"
    )


def toolbar_button_qss() -> str:
    """QSS für Toolbar-/Neutral-Buttons (Variante D) — grauer Hintergrund.

    Für Werkzeugleisten und Header (z.B. PDF-Export, Refresh-Icon).
    Hover signalisiert über Teal-Rahmen + Teal-Schrift, Fläche bleibt grau.

    Returns:
        Vollständiger QSS-Block mit allen vier Button-States.
    """
    c = theme.get()
    return (
        "QPushButton {"
        f" color: {c.TEXT_MAIN};"
        f" background-color: {c.BG_BUTTON};"
        f" border: 1px solid {c.BORDER};"
        " border-radius: 4px;"
        " padding: 4px 10px;"
        " }"
        "QPushButton:hover {"
        f" color: {c.ACCENT};"
        f" background-color: {c.BG_BUTTON};"
        f" border: 1px solid {c.ACCENT};"
        " }"
        "QPushButton:pressed {"
        f" color: {c.ACCENT};"
        f" background-color: {c.BG_INPUT};"
        f" border: 1px solid {c.ACCENT_DARK};"
        " padding-top: 5px;"
        " padding-bottom: 3px;"
        " }"
        "QPushButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        f" background-color: {c.BG_BUTTON_DISABLED};"
        f" border: 1px solid {c.BORDER_BUTTON_DISABLED};"
        " }"
    )


def secondary_button_qss() -> str:
    """QSS für Dialog-Sekundär-Buttons (Variante F) — "Abbrechen".

    Dezenter als Outline (gedimmte Schrift, neutraler Rahmen) — für die
    Nicht-Default-Aktion in Dialogen. Hebt das verstreute
    ``_secondary_style``-Muster (u. a. ``FinlaiConfirmDialog``) in die
    Factory; Migration der Alt-Kopien ist Backlog.

    Returns:
        Vollständiger QSS-Block mit allen vier Button-States.
    """
    c = theme.get()
    return (
        "QPushButton {"
        f" color: {c.TEXT_DIM};"
        " background-color: transparent;"
        f" border: 1px solid {c.BORDER};"
        " border-radius: 6px;"
        " padding: 7px 18px;"
        " }"
        "QPushButton:hover {"
        f" color: {c.TEXT_MAIN};"
        f" background-color: {c.CARD_BG};"
        f" border: 1px solid {c.BORDER};"
        " }"
        "QPushButton:pressed {"
        f" color: {c.TEXT_MAIN};"
        f" background-color: {c.BG_INPUT};"
        f" border: 1px solid {c.ACCENT_DARK};"
        " }"
        "QPushButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        " background-color: transparent;"
        f" border: 1px solid {c.BORDER_BUTTON_DISABLED};"
        " }"
    )


def card_menu_button_qss() -> str:
    """QSS für Karten-Menü-Buttons (QToolButton mit InstantPopup).

    QToolButton-Pendant zur Toolbar-Variante D — neutraler grauer Button,
    Hover signalisiert über Teal-Rahmen + Teal-Schrift. Der native
    Menü-Pfeil wird unterdrückt (Icon allein, z. B. ``more_vert``).

    Returns:
        Vollständiger QSS-Block mit allen vier Button-States.
    """
    c = theme.get()
    return (
        "QToolButton {"
        f" color: {c.TEXT_MAIN};"
        f" background-color: {c.BG_BUTTON};"
        f" border: 1px solid {c.BORDER};"
        " border-radius: 4px;"
        " padding: 2px;"
        " }"
        "QToolButton:hover {"
        f" color: {c.ACCENT};"
        f" background-color: {c.BG_BUTTON};"
        f" border: 1px solid {c.ACCENT};"
        " }"
        "QToolButton:pressed {"
        f" color: {c.ACCENT};"
        f" background-color: {c.BG_INPUT};"
        f" border: 1px solid {c.ACCENT_DARK};"
        " }"
        "QToolButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        f" background-color: {c.BG_BUTTON_DISABLED};"
        f" border: 1px solid {c.BORDER_BUTTON_DISABLED};"
        " }"
        "QToolButton::menu-indicator { image: none; }"
    )


def status_button_qss(accent: str) -> str:
    """QSS für einen status-eingefärbten QToolButton (Karten-Statuswahl).

    Anders als:func:`card_menu_button_qss` (fixes Neutral-Grau) traegt dieser
    Button eine *bedeutungstragende* Statusfarbe (``accent``) in Schrift + Rahmen
    — der Aufrufer reicht das Theme-Token des jeweiligen Status durch. Setzt in
    ALLEN vier States ``color``/``background``/``border`` explizit (R26,
    kaskaden-robust) und unterdrueckt den nativen Menue-Pfeil (InstantPopup).

    Args:
        accent: Statusfarbe (Theme-Token-Wert, z. B. ``theme.get.SUCCESS``).

    Returns:
        Vollständiger QSS-Block mit allen vier QToolButton-States.
    """
    c = theme.get()
    return (
        "QToolButton {"
        f" color: {accent};"
        f" background-color: {c.BG_BUTTON};"
        f" border: 1px solid {accent};"
        " border-radius: 4px;"
        " padding: 4px 10px;"
        " font-family: 'Raleway'; font-weight: 600; font-size: 12px;"
        " }"
        "QToolButton:hover {"
        f" color: {c.BG_DARK};"
        f" background-color: {accent};"
        f" border: 1px solid {accent};"
        " }"
        "QToolButton:pressed {"
        f" color: {c.BG_DARK};"
        f" background-color: {accent};"
        f" border: 1px solid {c.ACCENT_DARK};"
        " padding-top: 5px; padding-bottom: 3px;"
        " }"
        "QToolButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        f" background-color: {c.BG_BUTTON_DISABLED};"
        f" border: 1px solid {c.BORDER_BUTTON_DISABLED};"
        " }"
        "QToolButton::menu-indicator { image: none; }"
    )


def menu_qss() -> str:
    """QSS für Kontext-/Dropdown-Menüs (QMenu).

    Es gibt keine globale QMenu-Regel in ``theme.generate_qss`` —
    native Menüs wären hell auf hell. Diese Factory liefert den
    FINLAI-Look: dunkler Grund, Teal-Selektion, gedimmte Separatoren.

    Returns:
        Vollständiger QSS-Block für QMenu inkl. Item-States.
    """
    c = theme.get()
    return (
        "QMenu {"
        f" color: {c.TEXT_MAIN};"
        f" background-color: {c.BG_INPUT};"
        f" border: 1px solid {c.BORDER};"
        " border-radius: 4px;"
        " padding: 4px;"
        " }"
        "QMenu::item {"
        f" color: {c.TEXT_MAIN};"
        " background-color: transparent;"
        " border: none;"
        " border-radius: 3px;"
        " padding: 6px 24px 6px 10px;"
        " }"
        "QMenu::item:selected {"
        f" color: {theme.TEXT_ON_ACCENT_DEEP};"
        f" background-color: {c.ACCENT};"
        " border: none;"
        " }"
        "QMenu::item:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        " background-color: transparent;"
        " border: none;"
        " }"
        "QMenu::separator {"
        " height: 1px;"
        f" background: {c.BORDER};"
        " margin: 4px 8px;"
        " }"
    )


def danger_button_qss() -> str:
    """QSS für Danger-Buttons (Variante E) — roter Fill, destruktiv.

    Returns:
        Vollständiger QSS-Block mit allen vier Button-States.
    """
    c = theme.get()
    return (
        "QPushButton {"
        f" color: {theme.TEXT_ON_DANGER};"
        f" background-color: {c.DANGER};"
        f" border: 2px solid {c.DANGER};"
        " border-radius: 4px;"
        " padding: 6px 14px;"
        " }"
        "QPushButton:hover {"
        f" color: {theme.TEXT_ON_DANGER};"
        f" background-color: {c.DANGER_HOVER};"
        f" border: 2px solid {c.DANGER_HOVER};"
        " }"
        "QPushButton:pressed {"
        f" color: {theme.TEXT_ON_DANGER};"
        f" background-color: {c.DANGER_PRESSED};"
        f" border: 2px solid {c.DANGER_PRESSED};"
        " padding-top: 7px;"
        " padding-bottom: 5px;"
        " }"
        "QPushButton:disabled {"
        f" color: {c.TEXT_BUTTON_DISABLED};"
        f" background-color: {c.BG_BUTTON_DISABLED};"
        f" border: 2px solid {c.BORDER_BUTTON_DISABLED};"
        " }"
    )
