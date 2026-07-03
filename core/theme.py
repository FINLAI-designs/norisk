"""
theme — Dark Theme-System für FINLAI

Ein einziger Look: Dark (neutrales Dunkelgrau + FINLAI Teal-Akzent).
Rückwärtskompatibel: ``set_dark``, ``set_light``, ``is_dark`` funktionieren
weiterhin als Shims (set_light aktiviert ebenfalls Dark).

Typical usage:
    from core import theme

    theme.apply(app)

    label.setStyleSheet(f"color: {theme.ACCENT};")

Author: Patrick Riederich
Version: 5.0
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from pathlib import Path

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTabWidget,
    QTreeWidget,
    QWidget,
)

# Pfad zum weißen Checkmark-SVG (relativ zu dieser Datei)
_CHECK_WHITE_SVG = (
    Path(__file__).parent.parent / "assets" / "icons" / "check_white.svg"
).as_posix()


# ---------------------------------------------------------------------------
# ThemeColors — alle Farbwerte eines Looks
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ThemeColors:
    """Vollständiger Farbsatz für einen Look.

    Jedes Feld entspricht einer benannten Farbkonstante, die im gesamten
    Projekt über ``theme.<NAME>`` referenziert werden kann.
    """

    BG_MAIN: str
    BG_SIDEBAR: str
    BG_SIDEBAR_HOVER: str
    BG_SIDEBAR_SELECTED: str
    BG_SIDEBAR_HEADER: str
    TEXT_SIDEBAR: str
    TEXT_MAIN: str
    TEXT_DIM: str
    BORDER: str
    ACCENT: str
    CARD_BG: str
    DANGER: str
    DANGER_HOVER: str  # FE-9: Hover-Variante fuer Danger-Buttons
    DANGER_PRESSED: str  # FE-9: Pressed-Variante fuer Danger-Buttons

    # Eingabefelder und Buttons
    BG_INPUT: str
    BG_INPUT_FOCUS: str
    BG_BUTTON: str
    BG_BUTTON_DISABLED: str
    TEXT_BUTTON_DISABLED: str
    BORDER_BUTTON_DISABLED: str
    BG_TABLE_ALT: str

    # Bereiche mit fixem Hintergrund
    BG_TITLEBAR: str
    BG_SIDEBAR_FIXED: str
    TEXT_ON_DARK: str
    TEXT_ON_LIGHT: str
    TEXT_TITLEBAR: str  # Text/Icons in der TitleBar (look-abhängig)
    BORDER_SIDEBAR: str  # Shell-Hairline (TitleBar-Unterkante; Sidebar-Kante malt NeonSplitter mit BORDER)
    ACCENT_LINE: str  # Gedimmte dekorative Akzentlinie ~25% (Tabellen-Header u.ä. AP2)

    # Status-Farben und erweiterte Akzente (ab v3.0)
    SUCCESS: str
    WARNING: str
    ERROR: str
    INFO: str  # Severity-INFO-Farbe (analog SUCCESS/WARNING/ERROR — neutralgrau)
    ACCENT_DIM: str
    ACCENT_DARK: str
    BG_DARK: str

    # Diff-Zeilen-Hintergrundfarben (Datenvergleich)
    BG_DIFF_CHANGED: str
    BG_DIFF_NEW: str
    BG_DIFF_REMOVED: str

    # Tabellen-Header (ab v4.0) — von CARD_BG/ACCENT getrennt damit jedes Theme
    # einen eigenen Header-Farbsatz unabhängig von CARD_BG definieren kann.
    TABLE_HEADER_BG: str  # Hintergrund des Tabellen-/Tree-Headers
    TABLE_HEADER_TEXT: str  # Textfarbe im Tabellen-/Tree-Header

    # Status-Farben (ab v4.0)
    STATUS_INFO: str  # Info-Level Status (Blau)

    # Severity-Farben für CVE-/Audit-Tabellen (ab v4.2)
    # Alle Tokens sind Pflicht-Farbpaare (BG+TEXT) — Leer-Strings sind seit
    # verboten, weil QColor("") ungültig ist und Qt dann schwarzen
    # Text auf dunklem Grund malt.
    SEVERITY_CRITICAL_BG: str  # Hintergrund CRITICAL-Zeilen
    SEVERITY_CRITICAL_TEXT: str  # Textfarbe CRITICAL-Zeilen
    SEVERITY_HIGH_BG: str  # Hintergrund HIGH-Zeilen
    SEVERITY_HIGH_TEXT: str  # Textfarbe HIGH-Zeilen
    SEVERITY_MEDIUM_BG: str  # Hintergrund MEDIUM-Zeilen
    SEVERITY_MEDIUM_TEXT: str  # Textfarbe MEDIUM-Zeilen


# ---------------------------------------------------------------------------
# Font-Konstanten (CODING RULE R1)
# ---------------------------------------------------------------------------
TITLE_FONT = "Salaryman"  # App-Name in der TitleBar
TITLE_FONT_FALLBACK = "Raleway"  # Fallback wenn Salaryman nicht geladen
BODY_FONT = "Inter"  # Fließtext, kleine Texte, Beschreibungen, Tabellen
BODY_FONT_FALLBACK = "Raleway"  # Fallback wenn Inter nicht geladen


# ---------------------------------------------------------------------------
# Font-Size-Konstanten (FE-6, Code-Review 2026-05-19)
# ---------------------------------------------------------------------------
#
# 640 Inline-`font-size: Npx`-Treffer in tools/*/gui/ verteilt sich auf
# ~15 verschiedene Werte (9-48px). Die haeufigsten Stufen sind 11/12/13
# (Caption/Body, je ~170 Treffer) und 14/16/18/22 (Body-LG bis H2).
#
# Semantische Tokens analog Material-Type-Scale + Quick-Win-Anpassung
# fuer FINLAI-Stil:
#
# CAPTION (11px) — Hint-Text, Sekundaer-Labels, Footnotes
# BODY_SM (12px) — Kompakte Texte, Tabellen-Zellen, Buttons
# BODY (13px) — Standard-Fliesstext (Material 'Body Medium')
# BODY_LG (14px) — Hervorgehobene Body-Texte
# H3 (16px) — Sub-Section-Header
# H2 (18px) — Section-Header
# H1 (22px) — Hero-Header (Hauptseiten-Titel)
# HERO (28px) — Hero-Display (Dashboard-Zahlen)
#
# Pre-FE-6 ist `font-size: 9px` ein Material-Minimum-Bruch (Hi-DPI un-
# lesbar). Die Tokens definieren 11px als Untergrenze (CAPTION).
# FE-6-Folge: CAPTION_XS=10 ergaenzt fuer Dense-UI-Stellen
# (z. B. Taskboard-Footer-Texte), die historisch 10px hatten. Patrick-
# Hinweis: Hi-DPI macht 10px grenzwertig, aber besser als ein Hard-Cap
# auf 11px ohne UX-Pruefung.
FONT_SIZE_CAPTION_XS: int = 10
FONT_SIZE_CAPTION: int = 11
FONT_SIZE_BODY_SM: int = 12
FONT_SIZE_BODY: int = 13
FONT_SIZE_BODY_LG: int = 14
FONT_SIZE_H3: int = 16
FONT_SIZE_H2: int = 18
FONT_SIZE_H1: int = 22
FONT_SIZE_HERO: int = 28


# ---------------------------------------------------------------------------
# Dark-Theme Farbkonstanten — neutrales Dunkelgrau + Material Teal-Akzent (CODING RULE R1)
# Alle DARK_* Werte HIER definieren — nirgendwo sonst im Projekt hardcoden.
# ---------------------------------------------------------------------------

# Hintergründe (neutral dunkelgrau — KEINE Navy-Tönung auf Flächen!)
DARK_BG_PRIMARY = "#1e1e1e"  # Haupthintergrund (neutrales Dunkelgrau)
DARK_BG_SECONDARY = "#252525"  # Sekundär (Panels, Cards, GroupBoxes)
DARK_BG_DEEP = "#141414"  # Tiefster Hintergrund (Panel-Tiefe)
DARK_BG_INPUT = "#2a2a2a"  # Input-Felder
DARK_BG_INPUT_FOCUS = "#333333"  # Input Fokus-Hintergrund
DARK_BG_BUTTON = "#2a2a2a"  # Button-Hintergrund
DARK_BG_BUTTON_DISABLED = "#222222"  # Disabled Button
DARK_BG_TABLE_ALT = "#252525"  # Zebra-Streifen

# Header / Sidebar / TitleBar (neutral dunkel)
DARK_HEADER = "#181818"  # Sidebar + TitleBar — eine Tonstufe unter DARK_BG_PRIMARY (tonale Schale)
DARK_SIDEBAR_HEADER = "#131313"  # Sidebar Header-Bereich (App-Name, minimal dunkler als Schale)

# Text (gedämpft statt grell-weiß)
DARK_TEXT_PRIMARY = "#C8CCD0"  # Haupttext (weiches Silbergrau)
DARK_TEXT_SECONDARY = "#7A7F8C"  # Sekundärtext (mit leichtem Blauton)
DARK_TEXT_DISABLED = "#4A4E5C"  # Disabled Text
DARK_TEXT_ON_ACCENT = "#E0F2F1"  # Text auf Akzent-Hintergründen (Teal 50)

# Akzent — FINLAI Brand Teal für markante Stellen
DARK_ACCENT = "#51dacf"  # FINLAI Teal — aktive Sidebar, primäre Buttons, aktive Tabs
DARK_ACCENT_DIM = "#45b9b0"  # 15% dunkler — Hover-States, sekundäre Interaktion
DARK_ACCENT_DARK = "#3da49b"  # 25% dunkler — Pressed-States, Selection-BG
DARK_ACCENT_SUBTLE = "#7ae8e2"  # Heller Teal — Fokus-Borders, Links

# Borders
DARK_BORDER = "#2d2d2d"  # Allgemeine Borders (neutrales Dunkelgrau)
DARK_BORDER_FOCUS = "#7ae8e2"  # Fokus-Border (helles Teal)
DARK_BORDER_SIDEBAR = "#2d2d2d"  # Shell-Hairline (neutral, = DARK_BORDER — Teal nur als Zustands-Signal)
DARK_ACCENT_LINE = "rgba(81, 218, 207, 64)"  # ~25% Teal — dekorative Akzentlinien AP2; Präzedenz DARK_CODE_BORDER)
DARK_BORDER_BUTTON_DISABLED = "#2a2a2a"  # Disabled Button Border

# Tabellen
DARK_TABLE_HEADER_BG = "#252525"  # Tabellenheader (neutral, = DARK_BG_SECONDARY)
DARK_TABLE_HEADER_TEXT = "#80CBC4"  # Header-Text (Teal 200 — gedämpft, kein Neonblau)

# Scrollbar
DARK_SCROLLBAR = "#2d2d2d"  # Scrollbar Handle (= DARK_BORDER)
DARK_SCROLLBAR_HOVER = "#3d3d3d"  # Scrollbar Handle Hover

# Selection
DARK_SELECTION_BG = "#3da49b"  # Textauswahl Hintergrund (25% dunkler Teal)
DARK_SELECTION_TEXT = "#E0F2F1"  # Textauswahl Text (Teal 50)

# Sidebar-Interaktion
DARK_SIDEBAR_HOVER = "#45b9b0"  # Hover (15% dunkler Teal)
DARK_SIDEBAR_SELECTED = "#51dacf"  # Aktiver Eintrag (FINLAI Teal — markant)
DARK_SIDEBAR_TEXT = "#C8CCD0"  # Sidebar Text (= DARK_TEXT_PRIMARY)

# Status-Farben
DARK_SUCCESS = "#4CAF50"  # Erfolg (klares Grün)
DARK_WARNING = "#FFB74D"  # Warnung (warmes Orange)
DARK_ERROR = "#EF5350"  # Fehler (nicht zu aggressiv)
DARK_DANGER = "#F44336"  # Kritisch/Danger
DARK_DANGER_HOVER = "#FF6E60"  # FE-9: ~10% heller — Hover ueber Danger-Buttons
DARK_DANGER_PRESSED = "#D32F2F"  # FE-9: ~15% dunkler — Pressed (Material 700)
DARK_STATUS_INFO = "#4DB6AC"  # Info (Teal 300 = DARK_ACCENT_SUBTLE)
DARK_STATUS_BLOCKED = "#D32F2F"  # Blockiert

# ---------------------------------------------------------------------------
# Hardening-Score-Stage-Farben v2, Phase 1.3)
# ---------------------------------------------------------------------------
# Lynis-inspirierte Ampel-Farben fuer den NoRisk-Hardening-Score (4 Stufen).
# Diese 4 Farben sind semantisch fix und Theme-unabhaengig — sie sollen
# auf Light-/Dark-Mode gleich aussehen, weil der Score-Status nicht durch
# einen Theme-Wechsel veraendert werden darf (rotes "Critical" bleibt rot).
#
# Werte stammen aus dem Konzeptvorschlag NoRisk_HARDENING_SCORE.md und sind
# in:data:`SCORE_STAGE_COLORS` als Lookup-Dict + als Einzel-Konstanten
# (fuer R1-konforme Imports) angelegt.
SCORE_STAGE_SECURE = "#2ECC71"  # >=85 Punkte — Gruen
SCORE_STAGE_MODERATE = "#F1C40F"  # 65-84 — Gelb
SCORE_STAGE_AT_RISK = "#E67E22"  # 40-64 — Orange
SCORE_STAGE_CRITICAL = "#E74C3C"  # <40 — Rot

#: Lookup-Dict fuer den Hardening-Score (
#: ``tools/security_scoring/domain/hardening_stages.py``). Keys sind
#: ``ScoreStage.color_key``-Werte, Values sind Hex-Strings.
SCORE_STAGE_COLORS: dict[str, str] = {
    "score_secure":   SCORE_STAGE_SECURE,
    "score_moderate": SCORE_STAGE_MODERATE,
    "score_at_risk":  SCORE_STAGE_AT_RISK,
    "score_critical": SCORE_STAGE_CRITICAL,
}

# ---------------------------------------------------------------------------
# Status-Aliase (Sprint 1, 2026-04-27) — sprechende Namen für GUI-Code
# ---------------------------------------------------------------------------
# Plain-English-Aliase für die Material-Status-Farben oben. Erlauben Tools,
# semantisch (`SUCCESS_GREEN`) statt theme-intern (`DARK_SUCCESS`) zu
# referenzieren. Identische Hex-Werte — keine neue Optik.
SUCCESS_GREEN = DARK_SUCCESS  # Alias für DARK_SUCCESS (#4CAF50)
ERROR_RED = DARK_DANGER  # Alias für DARK_DANGER (#F44336)
WARNING_ORANGE = "#FF9800"  # Material Orange 500 — kräftiger als DARK_WARNING (FFB74D)
WARNING_AMBER = DARK_WARNING  # Alias für DARK_WARNING (#FFB74D, Material Amber 300)

# Teal-Akzent-Aliase: hover/pressed-Namensgebung gespiegelt zum Bestand
ACCENT_HOVER = DARK_ACCENT_SUBTLE  # Helles Teal #7ae8e2 — Fokus-Borders, Hover-Highlight
ACCENT_PRESSED = DARK_ACCENT_DIM  # Dunkleres Teal #45b9b0 — Pressed/Hover-Fill

# Text-/Background-Spezial: Text auf hellem Teal-Akzent (z.B. CTA-Button
# mit DARK_ACCENT-Hintergrund). Sehr dunkler Teal-Schwarz, kontrastiert
# besser gegen #51dacf als pures Schwarz/Grau.
TEXT_ON_ACCENT_DEEP = "#0b1e1c"  # Dunkler Teal-Schwarz für Text auf DARK_ACCENT-Fill

# Heller Teal-Hover (für Buttons, deren Standard-BG bereits DARK_ACCENT ist)
ACCENT_HOVER_BRIGHT = "#7de3d8"  # 5% heller als DARK_ACCENT — Hover über Teal-Buttons

# Text auf Danger-Fill Button-Matrix Variante E): reines Weiß statt
# Silbergrau — auf #F44336 braucht es maximalen Kontrast (dialog-skill
# "Destruktiv"-Vorgabe).
TEXT_ON_DANGER = "#ffffff"  # Schrift auf DARK_DANGER-/DANGER_HOVER-Fill

# Standard-Icon-Default (wenn keine Spezialfarbe angefragt wird)
ICON_DEFAULT = "#e0e0e0"  # Helles Neutralgrau für Tool-Icons ohne Akzent

# ---------------------------------------------------------------------------
# Pseudo-Panel-Hintergründe (Sprint 1) — semantische Aliase auf Bestand
# ---------------------------------------------------------------------------
BG_PANEL_DARK = DARK_BG_INPUT  # Alias für DARK_BG_INPUT (#2a2a2a) — Panel-/Card-BG
BG_PANEL_LIGHT = DARK_BG_INPUT_FOCUS  # Alias für DARK_BG_INPUT_FOCUS (#333333) — Hover-Panel
BG_PANEL_ERROR = "#2a1a1a"  # Dunkles Rotbraun — Background für Error-Inline-Hinweise
BG_PANEL_SUCCESS = "#1a2a1a"  # Dunkles Grünbraun — Background für Success-Inline-Hinweise

# ---------------------------------------------------------------------------
# Severity-Signal-Farben (Sprint 1) — Live-GUI Indikatoren
# ---------------------------------------------------------------------------
# Vereinheitlicht die "Signal-Leucht-Palette" aus tools/api_security,
# cyber_dashboard, network_scanner, password_checker, system_scanner,
# cert_monitor, email_scanner, pdf_risk_scanner. Helle, sättigungsstarke
# Farben für QPainter-Bars, Status-Punkte, Foreground-Highlights.
SEVERITY_SIGNAL_CRITICAL = "#ff4444"  # Hell-Rot — kritisch
SEVERITY_SIGNAL_HIGH = "#ff8800"  # Orange — hoch
SEVERITY_SIGNAL_MEDIUM = "#ffcc00"  # Gelb — mittel
SEVERITY_SIGNAL_LOW = "#44bbff"  # Hell-Blau — niedrig
SEVERITY_SIGNAL_INFO = "#888888"  # Mittelgrau — info / unbekannt
SEVERITY_SIGNAL_OK = "#44cc44"  # Hell-Grün — ok / safe

# Severity-Deep-Farben (Material 700) — für Reports/Charts auf hellem BG
# (csaf_advisor, dependency_auditor, norisk_dashboard chart export, PDF).
SEVERITY_DEEP_CRITICAL = "#d32f2f"  # Material Red 700
SEVERITY_DEEP_HIGH = "#f57c00"  # Material Orange 700
SEVERITY_DEEP_MEDIUM = "#fbc02d"  # Material Yellow 700
SEVERITY_DEEP_LOW = "#388e3c"  # Material Green 700

# A-F-Grading-Palette (security_scoring) — fünfstufig, kontrastreich
GRADE_A = "#43a047"  # Material Green 600 — Note A (sehr gut)
GRADE_B = "#7cb342"  # Material Light Green 600 — Note B
GRADE_C = "#f9a825"  # Material Yellow 800 — Note C
GRADE_D = "#ef6c00"  # Material Orange 800 — Note D
GRADE_F = "#c62828"  # Material Red 800 — Note F (kritisch)
GRADE_MID_AMBER = "#c9a227"  # Mittlerer Bernstein-Ton — "Warnung"-Balken (norisk_dashboard)

# Severity-Farben für CVE-/Audit-Tabellen (Dark-Theme — gedämpft, neutral dunkel)
DARK_SEVERITY_CRITICAL_BG = "#3B1111"  # Dunkles Rotbraun (neutraler als #4d1111)
DARK_SEVERITY_CRITICAL_TEXT = "#FCA5A5"  # Helles Rot — gut lesbar auf dunklem Rot
DARK_SEVERITY_HIGH_BG = "#3B2508"  # Dunkles Orange-Braun
DARK_SEVERITY_HIGH_TEXT = "#FCD34D"  # Helles Gelb — gut lesbar auf dunklem Orange
# MEDIUM bekommt ein echtes Farbpaar. Der frühere Leer-String führte
# zu QColor("") = ungültig -> Qt malte SCHWARZEN Text auf Olive (unlesbar).
DARK_SEVERITY_MEDIUM_BG = "#3B3508"  # Dunkles Gelb-Braun (Muster: HIGH #3B2508)
DARK_SEVERITY_MEDIUM_TEXT = "#FDE68A"  # Helles Gelb — lesbar, abgegrenzt von HIGH-Text

# Diff-Farben
DARK_DIFF_CHANGED = "#3d1a1a"  # Geändert (Dunkelrot, neutral)
DARK_DIFF_NEW = "#1A3D2E"  # Neu (Dunkelgrün mit Navy-Ton)
DARK_DIFF_REMOVED = "#2D2D1A"  # Entfernt (Dunkelgelb)

# Code-Block-Farben (Cheatsheet-Cards, Mathe-Trainer Formelanzeige)
DARK_CODE_BG = (
    "#0d1b2a"  # Tiefes Navy-Blau — harmoniert mit FINLAI-Teal (13:1 Kontrast)
)
DARK_CODE_BORDER = "rgba(81, 218, 207, 51)"  # Teal #51dacf mit 20 % Opacity (51/255)


# ---------------------------------------------------------------------------
# Look-Instanzen
# ---------------------------------------------------------------------------
DARK = ThemeColors(
    # Hintergründe: Navy-getönt — Tiefenstaffelung durch unterschiedliche Navy-Töne
    BG_MAIN=DARK_BG_PRIMARY,
    BG_SIDEBAR=DARK_HEADER,  # Dunkler als BG — visuelle Tiefe
    BG_SIDEBAR_HOVER=DARK_SIDEBAR_HOVER,  # Teal 600 — Hover
    BG_SIDEBAR_SELECTED=DARK_SIDEBAR_SELECTED,  # Teal 400 — markant, aktiver Eintrag
    BG_SIDEBAR_HEADER=DARK_SIDEBAR_HEADER,  # Dunkelster Wert — App-Name-Bereich
    TEXT_SIDEBAR=DARK_SIDEBAR_TEXT,
    # Text
    TEXT_MAIN=DARK_TEXT_PRIMARY,
    TEXT_DIM=DARK_TEXT_SECONDARY,
    BORDER=DARK_BORDER,
    # Akzent: Material Teal für markante aktive Stellen
    ACCENT=DARK_ACCENT,
    CARD_BG=DARK_BG_SECONDARY,
    DANGER=DARK_DANGER,
    DANGER_HOVER=DARK_DANGER_HOVER,
    DANGER_PRESSED=DARK_DANGER_PRESSED,
    # Eingabefelder
    BG_INPUT=DARK_BG_INPUT,
    BG_INPUT_FOCUS=DARK_BG_INPUT_FOCUS,
    BG_BUTTON=DARK_BG_BUTTON,
    BG_BUTTON_DISABLED=DARK_BG_BUTTON_DISABLED,
    TEXT_BUTTON_DISABLED=DARK_TEXT_DISABLED,
    BORDER_BUTTON_DISABLED=DARK_BORDER_BUTTON_DISABLED,
    BG_TABLE_ALT=DARK_BG_TABLE_ALT,
    # Bereiche mit fixem Hintergrund
    BG_TITLEBAR=DARK_HEADER,
    BG_SIDEBAR_FIXED=DARK_HEADER,
    TEXT_ON_DARK=DARK_TEXT_PRIMARY,
    TEXT_ON_LIGHT=DARK_TEXT_ON_ACCENT,  # Off-white auf Akzent-Hintergrund
    TEXT_TITLEBAR=DARK_TEXT_PRIMARY,
    BORDER_SIDEBAR=DARK_BORDER_SIDEBAR,  # Neutrale Shell-Hairline (accent-unabhängig)
    ACCENT_LINE=DARK_ACCENT_LINE,  # Gedimmte Akzentlinie (folgt dem Accent, s. set_accent_color)
    # Status-Farben
    SUCCESS=DARK_SUCCESS,
    WARNING=DARK_WARNING,
    ERROR=DARK_ERROR,
    INFO=SEVERITY_SIGNAL_INFO,  # Mittelgrau "#888888" — Severity-INFO/Niedrig/Unbekannt
    ACCENT_DIM=DARK_ACCENT_DIM,  # Teal 600 — Hover/Dim-Hintergründe
    ACCENT_DARK=DARK_ACCENT_DARK,  # Teal 700 — Pressed-States
    BG_DARK=DARK_BG_DEEP,
    BG_DIFF_CHANGED=DARK_DIFF_CHANGED,
    BG_DIFF_NEW=DARK_DIFF_NEW,
    BG_DIFF_REMOVED=DARK_DIFF_REMOVED,
    # Tabellen-Header: dunkler Header mit Himmelblau-Text
    TABLE_HEADER_BG=DARK_TABLE_HEADER_BG,
    TABLE_HEADER_TEXT=DARK_TABLE_HEADER_TEXT,
    STATUS_INFO=DARK_STATUS_INFO,
    # Severity-Farben (Dark-Theme)
    SEVERITY_CRITICAL_BG=DARK_SEVERITY_CRITICAL_BG,
    SEVERITY_CRITICAL_TEXT=DARK_SEVERITY_CRITICAL_TEXT,
    SEVERITY_HIGH_BG=DARK_SEVERITY_HIGH_BG,
    SEVERITY_HIGH_TEXT=DARK_SEVERITY_HIGH_TEXT,
    SEVERITY_MEDIUM_BG=DARK_SEVERITY_MEDIUM_BG,
    SEVERITY_MEDIUM_TEXT=DARK_SEVERITY_MEDIUM_TEXT,
)


# ---------------------------------------------------------------------------
# Aktiven Look verwalten
# ---------------------------------------------------------------------------
_current_name: str = "dark"
_current: ThemeColors = DARK

# ---------------------------------------------------------------------------
# Listener-System — Theme-Wechsel propagieren
# ---------------------------------------------------------------------------
_listeners: list = []


def register_listener(fn) -> None:  # noqa: ANN001
    """Registriert eine Callback-Funktion die bei Theme-Wechsel aufgerufen wird.

    Args:
        fn: Callable ohne Argumente (z.B. ``widget.apply_theme``).
    """
    if fn not in _listeners:
        _listeners.append(fn)


def unregister_listener(fn) -> None:  # noqa: ANN001
    """Entfernt eine Callback-Funktion aus dem Listener-Register.

    Args:
        fn: Zuvor registriertes Callable.
    """
    if fn in _listeners:
        _listeners.remove(fn)


def _notify_theme_changed() -> None:
    """Ruft alle registrierten Listener auf.

    Tote Qt-Objekte (RuntimeError) werden still ignoriert.
    """
    for fn in list(_listeners):
        try:
            fn()
        except RuntimeError:
            pass
        except Exception:  # noqa: BLE001 -- Listener-Callbacks: ein fehlerhafter Subscriber darf andere nicht blockieren
            pass


def get(name: str | None = None) -> ThemeColors:
    """Gibt ThemeColors für den aktuellen (oder benannten) Look zurück.

    Args:
        name: Wird ignoriert — es gibt nur noch Dark. None = aktuell aktiv.
    """
    return DARK


def set_theme(name: str) -> None:
    """Aktiviert Dark-Look (einziger unterstützter Look).

    Unbekannte Namen werden still ignoriert — immer Dark.
    """
    global _current, _current_name
    _current_name = "dark"
    _current = DARK


# --- Rückwärtskompatible Shims ---
def set_dark() -> None:
    """Aktiviert Dark-Look (Shim für Backward-Compat)."""
    set_theme("dark")


def set_light() -> None:
    """Shim für Backward-Compat — aktiviert ebenfalls Dark (Light-Theme entfernt)."""
    set_theme("dark")


def is_dark() -> bool:
    """True wenn der Dark-Look aktiv ist."""
    return _current_name == "dark"


# ---------------------------------------------------------------------------
# Accent-Color-Injection — für White-Label-Kunden
# ---------------------------------------------------------------------------

_DEFAULT_ACCENT = "#51dacf"


def _darken_hex(hex_color: str, factor: float) -> str:
    """Berechnet eine dunklere Variante einer Hex-Farbe.

    Args:
        hex_color: Hex-Farbwert, z.B. "#26A69A".
        factor: Faktor 0.0 (schwarz) bis 1.0 (unverändert).

    Returns:
        Dunklerer Hex-Farbwert mit führendem #.
    """
    h = hex_color.lstrip("#")
    if len(h) < 6:
        return hex_color
    r = max(0, min(255, round(int(h[0:2], 16) * factor)))
    g = max(0, min(255, round(int(h[2:4], 16) * factor)))
    b = max(0, min(255, round(int(h[4:6], 16) * factor)))
    return f"#{r:02x}{g:02x}{b:02x}"


def _accent_line_rgba(hex_color: str, alpha: int = 64) -> str:
    """Leitet die gedimmte Akzentlinien-Farbe aus einem Hex-Wert ab.

    Args:
        hex_color: Voll deckender Accent als Hex (z.B. "#51dacf").
        alpha: Alpha-Anteil 0–255 (Default ~25%).

    Returns:
        QSS-rgba-String, z.B. ``"rgba(81, 218, 207, 64)"``. Bei zu
        kurzem Hex wird der Teal-Default zurückgegeben (fail-closed).
    """
    h = hex_color.lstrip("#")
    if len(h) < 6:
        return DARK_ACCENT_LINE
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r}, {g}, {b}, {alpha})"


def set_accent_color(hex_color: str) -> None:
    """Setzt die Akzentfarbe für das Dark-Theme (White-Label-Injection).

    Überschreibt alle Accent-abgeleiteten Felder in DARK via
    ``dataclasses.replace`` (keine Mutation der frozen-Instanz):

    DARK: ACCENT, ACCENT_DIM, ACCENT_DARK, ACCENT_LINE,
          BG_SIDEBAR_SELECTED, BG_SIDEBAR_HOVER

    BORDER_SIDEBAR bleibt bewusst neutral (Shell-Hairline) — die
    Bereichsabgrenzung folgt NICHT dem Kunden-Accent.

    Bei leerem oder ungültigem Wert bleibt der Default (#51dacf) erhalten.

    Args:
        hex_color: Hex-Farbwert, z.B. "#51dacf". Leer/None → kein Effekt.
    """
    global DARK, _current
    if not hex_color:
        return
    h = hex_color.lstrip("#")
    if len(h) < 6:
        return

    dim = _darken_hex(hex_color, 0.85)
    dark_v = _darken_hex(hex_color, 0.75)

    DARK = replace(
        DARK,
        ACCENT=hex_color,
        ACCENT_DIM=dim,
        ACCENT_DARK=dark_v,
        ACCENT_LINE=_accent_line_rgba(hex_color),  # gedimmte Linie folgt Accent
        BG_SIDEBAR_SELECTED=hex_color,  # orientiert sich am Accent
        BG_SIDEBAR_HOVER=dim,  # orientiert sich am ACCENT_DIM
    )
    _current = DARK


# ---------------------------------------------------------------------------
# Rückwärtskompatibilität — theme.ACCENT etc. als Modul-Attribute
# ---------------------------------------------------------------------------
_FIELD_NAMES = frozenset(f.name for f in fields(ThemeColors))


def __getattr__(name: str) -> str:
    """Leitet Modul-Attributzugriffe auf den aktiven Look weiter.

    Ermöglicht ``theme.ACCENT`` statt ``theme.get.ACCENT``.
    """
    if name in _FIELD_NAMES:
        return getattr(_current, name)  # type: ignore[no-any-return]
    raise AttributeError(f"module 'core.theme' has no attribute {name!r}")


# ---------------------------------------------------------------------------
# QSS generieren
# ---------------------------------------------------------------------------
def generate_qss(colors: ThemeColors | None = None) -> str:
    """Erzeugt das vollständige Qt Style Sheet für ein ThemeColors-Objekt.

    Seit v5.0 gibt es nur den Dark-Look. Bereichsabgrenzung folgt der
    „tonalen Schale": Sidebar+TitleBar eine Tonstufe dunkler als
    der Content, neutrale 1px-Hairlines statt Akzent-Balken — Teal nur
    als Zustands-Signal (aktiv/Hover/Fokus).
    """
    c = colors or _current
    base = f"""
/* ─── Basis ───────────────────────────────────── */
QWidget {{
    background-color: {c.BG_MAIN};
    color: {c.TEXT_MAIN};
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 400;
}}

/* ─── H1 Überschriften ───────────────────────── */
QLabel[heading="true"], QLabel[class="heading"] {{
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 20px;
    font-weight: 600;
}}

/* ─── H2 Unter-Überschriften ─────────────────── */
QLabel[class="subheading"] {{
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 16px;
    font-weight: 500;
}}

/* ─── App-Name (Sidebar / Titlebar) ──────────── */
QLabel[class="app-title"], QLabel#app_title {{
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 18px;
    font-weight: 400;
    letter-spacing: 1px;
}}

/* ─── Labels / Body ──────────────────────────── */
QLabel {{
    font-family: "Inter", "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 400;
    color: {c.TEXT_MAIN};
    background: transparent;
}}

/* ─── Kleine Info-Texte ──────────────────────── */
QLabel[class="info"], QLabel[class="hint"] {{
    font-family: "Inter", "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 400;
}}

/* ─── Buttons — Outline-Stil ─────────────────── */
/* Standard: transparenter Hintergrund, Teal-Rand, Teal-Text.
   Hover/Pressed: Teal-Fill mit DUNKLER Schrift (#141414) — kein Weiß auf Teal! */
QPushButton {{
    background-color: transparent;
    color: {c.ACCENT};
    border: 2px solid {c.ACCENT};
    border-radius: 4px;
    padding: 6px 14px;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: {c.ACCENT};
    color: {c.BG_DARK};
    border-color: {c.ACCENT};
}}
QPushButton:pressed {{
    background-color: {c.ACCENT_DARK};
    color: {c.BG_DARK};
    border-color: {c.ACCENT_DARK};
    padding-top: 7px;
    padding-bottom: 5px;
}}
QPushButton:disabled {{
    background-color: {c.BG_BUTTON_DISABLED};
    color: {c.TEXT_BUTTON_DISABLED};
    border-color: {c.BORDER_BUTTON_DISABLED};
}}

/* ─── Primary Action Buttons ─────────────────── */
/* Login, Speichern, Bestätigen — immer gefüllt, aber DUNKLE Schrift auf Teal */
QPushButton[class="primary"] {{
    background-color: {c.ACCENT};
    color: {c.BG_DARK};
    border: 2px solid {c.ACCENT};
}}
QPushButton[class="primary"]:hover {{
    background-color: {c.ACCENT_DIM};
    color: {c.BG_DARK};
    border-color: {c.ACCENT_DIM};
}}
QPushButton[class="primary"]:pressed {{
    background-color: {c.ACCENT_DARK};
    color: {c.BG_DARK};
    border-color: {c.ACCENT_DARK};
}}
QPushButton[class="primary"]:disabled {{
    background-color: {c.BG_BUTTON_DISABLED};
    color: {c.TEXT_BUTTON_DISABLED};
    border-color: {c.BORDER_BUTTON_DISABLED};
}}

/* ─── Dialog-Buttons (QDialogButtonBox) ─────── */
/* Solid-Style für Dialog-Kontext (OK/Abbrechen etc.) — dunkle Schrift auf Teal */
QDialogButtonBox QPushButton,
QMessageBox QPushButton {{
    min-width: 80px;
    min-height: 28px;
    padding: 6px 16px;
    background-color: {c.BG_BUTTON};
    color: {c.TEXT_MAIN};
    border: 1px solid {c.BORDER};
    border-radius: 4px;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 500;
}}
QDialogButtonBox QPushButton:hover,
QMessageBox QPushButton:hover {{
    background-color: {c.ACCENT};
    color: {c.BG_DARK};
    border-color: {c.ACCENT};
}}
QDialogButtonBox QPushButton:pressed,
QMessageBox QPushButton:pressed {{
    background-color: {c.ACCENT_DARK};
    color: {c.BG_DARK};
    border-color: {c.ACCENT_DARK};
    padding-top: 7px;
    padding-bottom: 5px;
}}

/* ─── Eingabefelder ──────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {{
    background-color: {c.BG_INPUT};
    color: {c.TEXT_MAIN};
    border: 2px solid {c.ACCENT};
    border-radius: 4px;
    padding: 6px 10px;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 400;
    selection-background-color: {c.ACCENT_DIM};
    selection-color: {c.TEXT_MAIN};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border: 2px solid {c.ACCENT};
    background-color: {c.BG_INPUT_FOCUS};
}}
QLineEdit::placeholder {{
    color: {c.TEXT_DIM};
    font-style: italic;
}}

/* ─── Checkbox ───────────────────────────────── */
QCheckBox {{
    color: {c.TEXT_MAIN};
    spacing: 8px;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 2px solid {c.BORDER};
    border-radius: 3px;
    background-color: {c.BG_INPUT};
}}
QCheckBox::indicator:hover {{
    border-color: {c.ACCENT};
}}
QCheckBox::indicator:checked {{
    background-color: {c.ACCENT};
    border-color: {c.ACCENT};
    image: url({_CHECK_WHITE_SVG});
}}
QCheckBox::indicator:disabled {{
    background-color: {c.BG_BUTTON_DISABLED};
    border-color: {c.BORDER_BUTTON_DISABLED};
}}

/* ─── RadioButton ────────────────────────────── */
QRadioButton {{
    color: {c.TEXT_MAIN};
    spacing: 8px;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
}}
QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 2px solid {c.BORDER};
    border-radius: 8px;
    background-color: {c.BG_INPUT};
}}
QRadioButton::indicator:hover {{
    border-color: {c.ACCENT};
}}
QRadioButton::indicator:checked {{
    background-color: {c.ACCENT};
    border-color: {c.ACCENT};
}}

/* ─── Zahlentabellen ─────────────────────────── */
QTableWidget, QTableView, QTreeWidget {{
    background-color: {c.BG_MAIN};
    alternate-background-color: {c.BG_TABLE_ALT};
    gridline-color: {c.BORDER};
    color: {c.TEXT_MAIN};
    border: 1px solid {c.BORDER};
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 12px;
    font-weight: 400;
}}
QTableWidget::item, QTableView::item, QTreeWidget::item {{
    font-family: "JetBrains Mono", "Consolas", monospace;
    font-size: 12px;
}}
QTableWidget::item:selected, QTableView::item:selected, QTreeWidget::item:selected {{
    background-color: {c.BG_SIDEBAR_SELECTED};
    color: {c.TEXT_SIDEBAR};
}}
QHeaderView::section {{
    background-color: {c.TABLE_HEADER_BG};
    color: {c.TABLE_HEADER_TEXT};
    border: none;
    border-bottom: 1px solid {c.BORDER};
    padding: 6px 8px;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 600;
}}

/* ─── Container-Widgets ──────────────────────── */
QFrame {{
    background-color: {c.BG_MAIN};
    color: {c.TEXT_MAIN};
}}
QStackedWidget {{
    background-color: {c.BG_MAIN};
}}
QSplitter {{
    background-color: {c.BG_MAIN};
}}
QSplitter::handle {{
    background-color: {c.BORDER};
    width: 2px;
    height: 2px;
}}

/* ─── ScrollArea ─────────────────────────────── */
QScrollArea {{
    background-color: {c.BG_MAIN};
    border: none;
}}
QScrollArea > QWidget > QWidget {{
    background-color: {c.BG_MAIN};
}}

/* ─── Scrollbars ─────────────────────────────── */
QScrollBar:vertical {{
    background: {c.BG_MAIN};
    width: 8px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {c.BORDER};
    border-radius: 4px;
    min-height: 24px;
}}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: {c.BG_MAIN};
    height: 8px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {c.BORDER};
    border-radius: 4px;
    min-width: 24px;
}}
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ─── Listen (QListWidget) ───────────────────── */
/* T-350: Die Haupt-Sidebar ist ein Custom-Widget und nutzt diese Regel
   NICHT. Content-Listen bleiben auf BG_MAIN — sonst erbten sie die
   dunklere Schalen-Tonstufe (BG_SIDEBAR) samt Sidebar-Hairline. */
QListWidget {{
    background-color: {c.BG_MAIN};
    border: none;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 400;
    outline: none;
}}
QListWidget::item {{
    color: {c.TEXT_SIDEBAR};
    padding: 12px 16px;
}}
QListWidget::item:selected {{
    background-color: {c.BG_SIDEBAR_SELECTED};
    color: {TEXT_ON_ACCENT_DEEP};
}}
QListWidget::item:hover:!selected {{
    background-color: {c.BG_SIDEBAR_HOVER};
    color: {TEXT_ON_ACCENT_DEEP};
}}

/* ─── Tab Widget ─────────────────────────────── */
QTabWidget {{
    background-color: {c.BG_MAIN};
}}
QTabWidget::pane {{
    background-color: {c.BG_MAIN};
    border: 1px solid {c.BORDER};
}}
QTabBar::tab {{
    background-color: {c.CARD_BG};
    color: {c.TEXT_MAIN};
    border: 1px solid {c.BORDER};
    border-bottom: none;
    padding: 6px 12px;
    font-family: "Raleway", "Segoe UI", sans-serif;
    font-size: 13px;
    font-weight: 500;
}}
QTabBar::tab:hover {{
    background-color: {c.ACCENT_DIM};
    color: {c.TEXT_MAIN};
}}
QTabBar::tab:selected {{
    background-color: {c.BG_MAIN};
    border-bottom: 2px solid {c.ACCENT};
}}

/* ─── GroupBox ───────────────────────────────── */
QGroupBox {{
    background-color: {c.BG_MAIN};
    color: {c.TEXT_MAIN};
    border: 1px solid {c.BORDER};
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 8px;
}}
QGroupBox::title {{
    color: {c.ACCENT};
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
    font-weight: 600;
}}

/* ─── ProgressBar ────────────────────────────── */
QProgressBar {{
    background-color: {c.BG_BUTTON};
    color: {c.TEXT_MAIN};
    border: 1px solid {c.BORDER};
    border-radius: 4px;
    text-align: center;
    font-size: 13px;
}}
QProgressBar::chunk {{
    background-color: {c.ACCENT};
    border-radius: 3px;
}}

/* ─── FinlaiProgressBar (T-042 — kanonischer Ladebalken) ─── */
/* Wird von core/widgets/finlai_progress.py gesetzt — wer einen Ladebalken
   braucht, importiert FinlaiProgressBar. Hier die zentrale Stelle fuer
   Border + Chunk-Look. Hoehe kommt aus dem Widget (Default 8 px via
   setFixedHeight), damit Wizard-Sonderfaelle hochsetzen koennen. */
QProgressBar#FinlaiProgressBar {{
    background-color: {c.BG_INPUT};
    color: {c.TEXT_MAIN};
    border: none;
    border-radius: 4px;
    text-align: center;
    font-size: 12px;
}}
QProgressBar#FinlaiProgressBar::chunk {{
    background-color: {c.ACCENT};
    border-radius: 4px;
}}

/* ─── StatusBar ──────────────────────────────── */
QStatusBar {{
    background-color: {c.CARD_BG};
    color: {c.TEXT_DIM};
    font-size: 13px;
}}

/* ─── Tooltips ───────────────────────────────── */
QToolTip {{
    background-color: {c.CARD_BG};
    color: {c.TEXT_MAIN};
    border: 1px solid {c.BORDER};
    padding: 4px;
}}

/* ─── TitleBar ───────────────────────────────── */
QWidget#titlebar {{
    background-color: {c.BG_TITLEBAR};
    border-bottom: 1px solid {c.BORDER_SIDEBAR};
}}
QWidget#titlebar QLabel {{
    color: {c.TEXT_TITLEBAR};
    background: transparent;
}}
QWidget#titlebar QLineEdit {{
    color: {c.TEXT_TITLEBAR};
    background: rgba(128,128,128,0.12);
}}
QWidget#titlebar QPushButton {{
    color: {c.TEXT_TITLEBAR};
    background: transparent;
    border: none;
}}

/* ─── Sidebar (Widget) ───────────────────────── */
/* Kein eigener border-right — die Trennlinie zum Content malt allein
   der NeonSplitter-Handle (T-350, tonale Schale). */
QWidget#sidebar {{
    background-color: {c.BG_SIDEBAR};
    border: none;
}}
QWidget#sidebar QLabel {{
    color: {c.TEXT_SIDEBAR};
    background: transparent;
}}
QWidget#sidebar QPushButton {{
    color: {c.TEXT_SIDEBAR};
    background: transparent;
    border: none;
}}
/* FE-8 (Code-Review 2026-05-19): Universalselektor `QWidget#sidebar *`
   ersetzt durch konkrete Targets. Aggressive Stilkollisionen mit
   Child-Widget-QSS (z. B. QLabel-eigene Backgrounds) sind damit weg.
   Hover-Regel auf `*:hover` entfernt — sidebar.py hat ohnehin
   enterEvent/leaveEvent-basiertes Hover (siehe Z.593/737), das war
   redundant und potentiell konfligierend mit dem QSS-Hover. */
QWidget#sidebar QLabel,
QWidget#sidebar QFrame {{
    background-color: transparent;
    color: {c.TEXT_SIDEBAR};
}}

/* ─── Tool-Bereich ───────────────────────────── */
QWidget#tool_content {{
    background-color: {c.BG_MAIN};
}}

/* ─── Dock Widgets ───────────────────────────── */
QDockWidget {{
    background: {c.BG_MAIN};
    color: {c.TEXT_ON_LIGHT};
}}
QDockWidget::title {{
    background: {c.CARD_BG};
    color: {c.TEXT_ON_LIGHT};
    border-bottom: 1px solid {c.BORDER};
    padding: 4px 8px;
}}

/* ─── ComboBox Dropdown ──────────────────────── */
QComboBox QAbstractItemView {{
    background-color: {c.CARD_BG};
    border: 1px solid {c.BORDER};
    color: {c.TEXT_MAIN};
    selection-background-color: {c.ACCENT};
    selection-color: {c.TEXT_ON_LIGHT};
}}
"""
    if c is DARK:
        base += f"""
/* ─── Dark-Theme Overrides (Material Teal-Palette) ── */

/* Button hover: Teal 600 — ruhiger als Teal 400.
   Dunkle Schrift (#1e1e1e) statt near-white — sonst kaum lesbar auf Teal! */
QPushButton:hover {{
    background-color: {DARK_ACCENT_DIM};
    color: {DARK_BG_PRIMARY};
    border-color: {DARK_ACCENT_DIM};
}}
QPushButton:pressed {{
    background-color: {DARK_ACCENT_DARK};
    color: {DARK_BG_PRIMARY};
    border-color: {DARK_ACCENT_DARK};
}}
QPushButton[class="primary"] {{
    background-color: {DARK_ACCENT};
    color: {DARK_BG_PRIMARY};
    border-color: {DARK_ACCENT};
}}
QPushButton[class="primary"]:hover {{
    background-color: {DARK_ACCENT_DIM};
    color: {DARK_BG_PRIMARY};
    border-color: {DARK_ACCENT_DIM};
}}

/* Input-Felder: neutraler Border standard, Teal 300 bei Fokus */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {{
    border: 2px solid {DARK_BORDER};
    selection-background-color: {DARK_SELECTION_BG};
    selection-color: {DARK_SELECTION_TEXT};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 2px solid {DARK_BORDER_FOCUS};
}}

/* ComboBox: Navy-Border, Mittleres Blau bei Fokus */
QComboBox {{
    border: 2px solid {DARK_BORDER};
}}
QComboBox:focus {{
    border: 2px solid {DARK_BORDER_FOCUS};
}}
QComboBox QAbstractItemView {{
    background-color: {DARK_BG_SECONDARY};
    border: 1px solid {DARK_BORDER};
    color: {DARK_TEXT_PRIMARY};
    selection-background-color: {DARK_SELECTION_BG};
    selection-color: {DARK_SELECTION_TEXT};
}}

/* Checkbox / Radio: Mittleres Blau für Hover statt Neonblau */
QCheckBox::indicator:hover {{
    border-color: {DARK_BORDER_FOCUS};
}}
QRadioButton::indicator:hover {{
    border-color: {DARK_BORDER_FOCUS};
}}

/* Scrollbar: dedizierte Handle- und Hover-Farbe */
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background: {DARK_SCROLLBAR};
}}
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
    background: {DARK_SCROLLBAR_HOVER};
}}

/* GroupBox: Navy-Sekundär als Hintergrund — abgesetzt vom Haupt-BG */
QGroupBox {{
    background-color: {DARK_BG_SECONDARY};
}}
QGroupBox::title {{
    color: {DARK_ACCENT};
}}

/* Tabellen-Selection: Deep Royal mit off-white Text */
QTableWidget::item:selected,
QTableView::item:selected,
QTreeWidget::item:selected {{
    background-color: {DARK_SELECTION_BG};
    color: {DARK_SELECTION_TEXT};
}}

/* Tab hover: Teal 600 Hintergrund */
QTabBar::tab:hover {{
    background-color: {DARK_ACCENT_DIM};
    color: {DARK_TEXT_ON_ACCENT};
}}

/* Tooltip: Deep Royal als Hintergrund — klar abgesetzt vom BG */
QToolTip {{
    background-color: {DARK_ACCENT_DARK};
    color: {DARK_TEXT_ON_ACCENT};
    border: 1px solid {DARK_ACCENT};
    padding: 4px 6px;
}}

/* Statusbar: Sekundärer Navy-Hintergrund */
QStatusBar {{
    background-color: {DARK_BG_SECONDARY};
    color: {DARK_TEXT_SECONDARY};
    border-top: 1px solid {DARK_BORDER};
}}
"""
    return base


# ---------------------------------------------------------------------------
# Force-Repolish — Theme-Wechsel auf bereits gerenderte Widgets erzwingen
# ---------------------------------------------------------------------------
def _force_repolish_recursive(widget: QWidget) -> None:
    """Erzwingt Style-Neuberechnung für Widget und alle Kind-Widgets.

    PySide6 cached QSS auf bereits gerenderten Widgets. unpolish → polish →
    update erzwingt eine vollständige Neuberechnung. Iteriert nur direkte
    Kinder (nicht findChildren) um O(n²)-Repolish zu vermeiden.

    Spezialbehandlungen:
    - QTableWidget: Viewport + Header separat repolishen
    - QTabWidget / QStackedWidget: versteckte Seiten explizit repolishen
    - Widgets mit refresh_severity_colors: programmatische Farben aktualisieren

    Args:
        widget: Wurzel-Widget ab dem rekursiv repolished wird.
    """
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    QWidget.update(widget)

    # Programmatische Farben (z.B. CVE-Severity-Tabellen) aktualisieren
    if hasattr(widget, "refresh_severity_colors"):
        widget.refresh_severity_colors()

    # Scrollbarer Viewport (QTableWidget, QTreeWidget, QScrollArea)
    if isinstance(widget, (QTableWidget, QTreeWidget, QScrollArea)):
        vp = widget.viewport()
        if vp is not None:
            vp.style().unpolish(vp)
            vp.style().polish(vp)
            QWidget.update(vp)

    # QTableWidget: Header separat repolishen
    if isinstance(widget, QTableWidget):
        for header in (widget.horizontalHeader(), widget.verticalHeader()):
            if header is not None:
                header.style().unpolish(header)
                header.style().polish(header)
                QWidget.update(header)

    # QTabWidget/QStackedWidget: alle Seiten explizit repolishen (auch versteckte)
    if isinstance(widget, (QTabWidget, QStackedWidget)):
        for i in range(widget.count()):
            page = widget.widget(i)
            if page is not None:
                _force_repolish_recursive(page)

    # Nur direkte Kinder-Widgets — findChildren würde O(n²) verursachen
    for child in widget.children():
        if isinstance(child, QWidget):
            _force_repolish_recursive(child)


# ---------------------------------------------------------------------------
# Palette + Stylesheet anwenden
# ---------------------------------------------------------------------------
def apply(app: QApplication, name: str | None = None) -> None:
    """Wendet Palette und globales QSS auf die QApplication an.

    Args:
        app: Die laufende Qt-Applikationsinstanz.
        name: Optionaler Look-Name — aktiviert diesen Look vor dem Anwenden.
    """
    if name is not None:
        set_theme(name)
    c = _current
    palette = QPalette()

    palette.setColor(QPalette.ColorRole.Window, QColor(c.BG_MAIN))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(c.TEXT_MAIN))
    palette.setColor(QPalette.ColorRole.Base, QColor(c.BG_INPUT))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(c.BG_TABLE_ALT))
    palette.setColor(QPalette.ColorRole.Text, QColor(c.TEXT_MAIN))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(c.ACCENT))
    palette.setColor(QPalette.ColorRole.Button, QColor(c.BG_BUTTON))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(c.TEXT_MAIN))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(c.ACCENT_DIM))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(c.TEXT_MAIN))
    palette.setColor(QPalette.ColorRole.Link, QColor(c.ACCENT))
    palette.setColor(QPalette.ColorRole.Mid, QColor(c.BORDER))
    palette.setColor(QPalette.ColorRole.Dark, QColor(c.BORDER))

    app.setPalette(palette)
    app.setStyleSheet("")  # Erst leeren — erzwingt vollständigen Style-Cache-Flush
    app.processEvents()  # Event-Queue abarbeiten damit der Reset propagiert
    app.setStyleSheet(generate_qss(c))
    _notify_theme_changed()

    # Force-Repolish: alle bereits gerenderten Widgets zwingen das neue QSS
    # zu übernehmen. Ohne dies behalten geöffnete Tools die alten Farben.
    for top in app.topLevelWidgets():
        _force_repolish_recursive(top)
