"""
icons — Zentrales Icon-Management mit Google Material Symbols.

Verwendung::

    from core.icons import get_icon, Icons

    button.setIcon(get_icon(Icons.SECURITY))
    action.setIcon(get_icon(Icons.SETTINGS, color="#00d4ff"))

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QIcon
from qt_material_icons import MaterialIcon

from core import theme

# FE-10 (Code-Review 2026-05-19): Material-Standard-Icon-Sizes als
# zentrale Konstanten. Skill 'frontend-design' fordert konsistente
# 16/20/24 fuer regulaere UI, 40/56 fuer Hero/Dashboard. 32 ist
# etabliertes Pattern fuer Dialog-Icons (kein Material-Standard, aber
# bewusst beibehalten — siehe core/dialogs.py).
#
# Nutzung: ``get_icon(Icons.SHIELD).pixmap(ICON_SIZE_LG, ICON_SIZE_LG)``
#
# Pre-FE-10 waren 22/28/48 als Bruch-Werte in Verwendung; mit der
# Konstanten-Migration auf 24/24/40 normalisiert.
ICON_SIZE_SM: int = 16  # Inline-Icons (z. B. in Buttons, Listen)
ICON_SIZE_MD: int = 20  # Standard-Toolbar-Icons
ICON_SIZE_LG: int = 24  # Tab-/Sidebar-Icons (Material-Standard)
ICON_SIZE_DIALOG: int = 32  # Dialog-Header-Icons (etabliert in core/dialogs.py)
ICON_SIZE_XL: int = 40  # Material-XL fuer Empty-State + Dropzone
ICON_SIZE_HERO: int = 56  # Hero-Dashboard-Icons (z. B. SHIELD im Cyber-Dashboard)


class Icons:
    """Alle Icon-Namen als Konstanten.

    Referenz: https://fonts.google.com/icons
    """

    # ─── Allgemein / Navigation ────────────────────────────
    DASHBOARD = "dashboard"
    SETTINGS = "settings"
    LINK = "link"
    CHAT = "smart_toy"
    PEOPLE = "group"
    ASSESSMENT = "assignment"  # Bereich „Security-Bewertung" (Container)
    HOME = "home"
    MENU = "menu"
    CLOSE = "close"
    CANCEL = "cancel"
    SEARCH = "search"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CHECK_CIRCLE = "check_circle"
    DONE = "done"
    PENDING = "pending"
    BLOCK = "block"
    HELP = "help"
    LOGOUT = "logout"
    MINIMIZE = "remove"
    MAXIMIZE = "crop_square"
    VISIBILITY = "visibility"
    VISIBILITY_OFF = "visibility_off"
    PERSON = "person"
    PALETTE = "palette"
    GAVEL = "gavel"
    ADMIN_PANEL = "manage_accounts"
    LICENSE = "card_membership"
    PASSWORD_CHANGE = "lock_reset"
    EXPAND_MORE = "expand_more"
    EXPAND_LESS = "expand_less"
    CHEVRON_LEFT = "chevron_left"
    CHEVRON_RIGHT = "chevron_right"
    ARROW_BACK = "arrow_back"
    ARROW_FORWARD = "arrow_forward"
    ARROW_UP = "arrow_upward"
    ARROW_DOWN = "arrow_downward"
    SEND = "send"  # Send-CTA im Handbuch-Assistenten (Glyph-Gate bestanden)
    REFRESH = "refresh"
    DOWNLOAD = "download"
    UPLOAD = "upload_file"
    SAVE = "save"
    PLAY_ARROW = "play_arrow"
    FOLDER_OPEN = "folder_open"
    DELETE = "delete"
    DELETE_SWEEP = "delete_sweep"
    EDIT = "edit"
    ADD = "add"
    COPY = "content_copy"
    PRINT = "print"
    PDF = "picture_as_pdf"
    HOURGLASS = "hourglass_empty"
    CIRCLE = "circle"
    PRIORITY_HIGH = "priority_high"
    TIMER = "timer"
    MAIL = "mail"
    ANCHOR = "anchor"
    BUILD = "build"
    DANGEROUS = "dangerous"
    OPEN_IN_FULL = "open_in_full"
    CLOSE_FULLSCREEN = "close_fullscreen"
    #/ — Taskboard-Karten-Menue + Aufgabenlog
    MORE_VERT = "more_vert"
    UNDO = "undo"
    THUMB_UP = "thumb_up"
    THUMB_DOWN = "thumb_down"
    HISTORY = "history"

    # ─── FINLAI / Finance ──────────────────────────────────
    BUCHPRUEFUNG = "fact_check"
    BILANZPRUEFUNG = "balance"
    FINANZPRUEFUNG = "monitoring"
    FINANCE_DASHBOARD = "bar_chart"
    KLIENT = "person"
    KLIENTEN = "people"
    KONTENPLAN = "account_tree"
    IMPORT = "file_upload"
    EXPORT = "file_download"
    EURO = "euro"
    RECHNUNG = "receipt_long"
    KALENDER = "calendar_month"
    TREND_UP = "trending_up"
    TREND_DOWN = "trending_down"
    PROGNOSE = "auto_graph"

    # ─── NoRisk / Security ─────────────────────────────────
    SECURITY = "security"
    SHIELD = "shield"
    API = "api"
    NETWORK = "lan"
    NETWORK_SCAN = "wifi_find"
    NETWORK_MONITOR = "monitor_heart"
    CERTIFICATE = "verified_user"
    DEPENDENCY = "inventory_2"
    PASSWORD = "password"
    KEY = "key"
    LOCK = "lock"
    LOCK_OPEN = "lock_open"
    SCORE = "speed"
    VULNERABILITY = "bug_report"
    SCAN = "radar"
    TUNE = "tune"  # system_tuner — "System optimieren" (Datenschutz/Telemetrie)
    HOST = "dns"
    PORT = "electrical_services"
    FIREWALL = "local_fire_department"
    ADVISORY_MONITOR = "security_update_warning"
    PATCH_MONITOR = "system_update_alt"
    SUPPLY_CHAIN = "hub"
    MAIL_SCAN = "mark_email_unread"
    OPEN_IN_NEW = "open_in_new"
    TABLE_VIEW = "table_view"
    DATA_OBJECT = "data_object"

    # ─── Teachings ─────────────────────────────────────────
    SCHOOL = "school"
    BOOK = "menu_book"
    AUTO_STORIES = "auto_stories"
    HELP_CENTER = "help_center"
    HELP_OUTLINE = "help_outline"
    LIGHTBULB = "lightbulb"  # Erklaer-Modus-Toggle (klar erkennbares Icon)
    LIBRARY = "local_library"
    LERNKARTEN = "style"
    CALCULATE = "calculate"
    QUIZ = "quiz"
    KNOWLEDGE = "psychology"
    OCR = "document_scanner"
    AUTO_EXTRACT = "auto_awesome"

    # ─── AUTOMATE / TaxTech ────────────────────────────────
    AUTOMATE = "precision_manufacturing"
    ROBOT = "smart_toy"
    SYNC = "sync"
    SCHEDULE = "schedule"
    SFTP = "cloud_upload"

    # ─── TeachMe / Programmierlehrer ──────────────────────
    CHEATSHEET = "integration_instructions"
    FLASHCARD = "style"
    CODE_CHALLENGE = "code"
    PROG_TEACHINGS = "school"
    SYNTAX_HIGHLIGHT = "developer_mode"
    LANGUAGE_PYTHON = "code"
    LANGUAGE_JS = "javascript"
    LANGUAGE_CSS = "css"
    LANGUAGE_PHP = "php"
    LANGUAGE_HTML = "html"
    LANGUAGE_MYSQL = "storage"
    LANGUAGE_VBA = "table_chart"

    # ─── Link-Icons (für Einstellungen → Wichtige Links) ──
    LINK_WEB = "language"
    LINK_PUBLIC = "public"
    LINK_MAIL = "mail"
    LINK_PHONE = "call"
    LINK_CHAT_LINK = "forum"
    LINK_FINANCE = "account_balance"
    LINK_PAYMENT = "payments"
    LINK_DOCUMENT = "description"
    LINK_FOLDER = "folder"
    LINK_ATTACH = "attach_file"
    LINK_LOCK = "lock"
    LINK_SHIELD = "shield"
    LINK_VERIFIED = "verified"
    LINK_STAR = "star"
    LINK_BOOKMARK = "bookmark"
    LINK_PIN = "push_pin"
    LINK_INFO = "info"
    LINK_BUSINESS = "business"
    LINK_SUPPORT = "support_agent"
    LINK_CODE = "code"

    # ─── Sammlung für Link-Icon-Auswahl ────────────────────
    LINK_ICON_CHOICES: list[tuple[str, str]] = [
        ("language", "Webseite"),
        ("public", "Öffentlich"),
        ("mail", "E-Mail"),
        ("call", "Telefon"),
        ("forum", "Chat/Forum"),
        ("account_balance", "Bank/Finanzen"),
        ("payments", "Zahlung"),
        ("description", "Dokument"),
        ("folder", "Ordner"),
        ("attach_file", "Anhang"),
        ("lock", "Sicherheit"),
        ("shield", "Schutz"),
        ("verified", "Verifiziert"),
        ("star", "Favorit"),
        ("bookmark", "Lesezeichen"),
        ("push_pin", "Angeheftet"),
        ("info", "Info"),
        ("business", "Unternehmen"),
        ("support_agent", "Support"),
        ("code", "Code/Technik"),
    ]


def get_icon(name: str, color: str | None = None) -> QIcon:
    """Erstellt ein Material Symbol Icon.

    Args:
        name: Icon-Name aus der Icons-Klasse oder direkt aus Google Material Symbols.
        color: Hex-Farbcode (z.B. ``"#00d4ff"``). None = Standard (#e0e0e0).

    Returns:
        QIcon-Objekt.
    """
    icon = MaterialIcon(name)
    if color:
        icon.set_color(QColor(color))
    else:
        icon.set_color(QColor(theme.ICON_DEFAULT))
    return icon


def get_accent_icon(name: str) -> QIcon:
    """Icon mit FINLAI-Akzentfarbe (#51dacf).

    Args:
        name: Icon-Name.

    Returns:
        QIcon in Akzentfarbe.
    """
    return get_icon(name, color=theme.DARK_ACCENT)


def get_sidebar_icon(name: str, app: str = "finlai") -> QIcon:
    """Icon für Sidebar mit FINLAI Teal-Akzentfarbe.

    Args:
        name: Icon-Name.
        app: App-ID (alle Apps verwenden einheitlich FINLAI Teal #51dacf).

    Returns:
        QIcon in Akzentfarbe.
    """
    return get_icon(name, color=theme.DARK_ACCENT)
