"""
ui_settings — Persistente UI-Einstellungen für FINLAI.

Lädt und speichert Sidebar-Breite und Einklapp-Zustand in
``~/.finlai/ui_settings.json``. Das Verzeichnis wird bei Bedarf
automatisch erstellt. Fehler beim Lesen oder Schreiben werden
geloggt, aber nie nach oben weitergeleitet — die App startet
immer mit Standardwerten wenn die Datei nicht vorhanden oder
beschädigt ist.

Typical usage::

    from core.ui_settings import UISettings

    settings = UISettings.load
    settings.sidebar_width = 240
    settings.save

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from core.finlai_paths import finlai_dir

from .logger import get_logger

_log = get_logger(__name__)

_SETTINGS_FILE = finlai_dir() / "ui_settings.json"

# Gültige Breiten-Grenzen (müssen mit sidebar.py übereinstimmen)
_WIDTH_MIN = 52
_WIDTH_MAX = 320


@dataclass
class UISettings:
    """Persistente UI-Einstellungen für die Sidebar und KI-Integration.

    Attributes:
        sidebar_width: Letzte gespeicherte Sidebar-Breite in Pixeln (52–320).
        sidebar_collapsed: True wenn die Sidebar im Icon-Modus (52 px) war.
        ollama_base_url: Basis-URL des Ollama-Servers.
    """

    sidebar_width: int = 220
    sidebar_collapsed: bool = False
    ollama_base_url: str = "http://localhost:11434"  # noqa
    dock_state: str = ""
    # Versionsstempel des dock_state-Blobs. Springt die Version (Wegfall
    # eines Docks, z.B. nis2_incidents→Tab), wird der Alt-Blob einmalig
    # verworfen, statt verwaiste objectNames defensiv zu interpretieren
    #.
    dock_state_version: int = 0
    theme: str = "dark"

    # Nutzungsvereinbarung — ISO-Zeitstempel der Zustimmung, leer = noch nicht zugestimmt
    terms_accepted: str = ""
    privacy_accepted: str = ""
    terms_version: str = ""

    # Username des im First-Run-Wizard angelegten Admins. Wird nach
    # erfolgreichem Wizard-Durchlauf persistiert, damit Folge-Dialoge
    # (z. B. Welcome-Toast) den Namen wiederfinden.
    user_name: str = ""

    # Window-Geometry-Persistenz. ``0`` als Sentinel fuer "noch nicht
    # gesetzt" (Erst-Start nutzt Default 1920x1080 zentriert). ``-1`` fuer x/y
    # bedeutet "OS soll positionieren" (typisch beim Erst-Start ohne Snapshot).
    window_width: int = 0
    window_height: int = 0
    window_x: int = -1
    window_y: int = -1
    window_maximized: bool = False

    # (Phase 3d): Profil-Gating der Sidebar. Default True = profil-
    # irrelevante Module (z. B. API-Security ohne eigene API) werden ausgegraut.
    # Reversibles Override: setzt der Nutzer dies auf False ("Alle Module
    # anzeigen"), greift kein Gating — gegen Fehlklassifikation im W1-Interview.
    # Bewusst: bei korrupter/fehlender Settings-Datei fällt dies wie alle Felder
    # auf den Default (Gating an) zurück — kein eigener Sonderpfad. Das ist
    # vertretbar, weil Gating NUR bei explizitem Flag==0 ausgraut (frisches
    # Profil = überall None = kein Versteck), rein visuell ist (Scans/Scoring
    # unberührt) und jederzeit über die Einstellungen reversibel.
    profile_gating_enabled: bool = True

    # ------------------------------------------------------------------
    def update_username(self, username: str) -> None:
        """Setzt den Admin-Usernamen und persistiert sofort.

        Wird nach erfolgreichem First-Run-Wizard aufgerufen.

        Args:
            username: Vom User im Wizard gewählter Admin-Username.
        """
        self.user_name = username
        self.save()

    # ------------------------------------------------------------------
    def update_profile_gating(self, enabled: bool) -> None:
        """Setzt das Sidebar-Profil-Gating-Flag und persistiert sofort.

        Args:
            enabled: True = Gating aktiv (profil-irrelevante Module ausgrauen);
                False = „Alle Module anzeigen" (Override).
        """
        self.profile_gating_enabled = enabled
        self.save()

    # ------------------------------------------------------------------
    def save(self) -> None:
        """Speichert die Einstellungen in ``~/.finlai/ui_settings.json``.

        Erstellt das Verzeichnis falls nötig. I/O-Fehler werden mit
        WARNING geloggt und ignoriert.
        """
        try:
            _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
            _SETTINGS_FILE.write_text(
                json.dumps(asdict(self), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            _log.debug("UI-Einstellungen gespeichert: %s", _SETTINGS_FILE)
        except OSError as exc:
            _log.warning("UI-Einstellungen konnten nicht gespeichert werden: %s", exc)

    # ------------------------------------------------------------------
    @classmethod
    def load(cls) -> UISettings:
        """Lädt UISettings aus ``~/.finlai/ui_settings.json``.

        Bei fehlender Datei, ungültigem JSON oder Typfehlern werden die
        Standardwerte der Klasse verwendet.

        Returns:
            UISettings: Geladene oder Standard-Einstellungen.
        """
        try:
            data = json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
            width = int(data.get("sidebar_width", 220))
            # Breite auf gültige Grenzen beschränken
            width = max(_WIDTH_MIN, min(_WIDTH_MAX, width))
            saved_theme = str(data.get("theme", "dark"))
            if saved_theme != "dark":
                saved_theme = "dark"
            return cls(
                sidebar_width=width,
                sidebar_collapsed=bool(data.get("sidebar_collapsed", False)),
                ollama_base_url=str(
                    data.get("ollama_base_url", "http://localhost:11434")  # noqa
                ),
                dock_state=str(data.get("dock_state", "")),
                dock_state_version=int(data.get("dock_state_version", 0)),
                theme=saved_theme,
                terms_accepted=str(data.get("terms_accepted", "")),
                privacy_accepted=str(data.get("privacy_accepted", "")),
                terms_version=str(data.get("terms_version", "")),
                user_name=str(data.get("user_name", "")),
                window_width=int(data.get("window_width", 0)),
                window_height=int(data.get("window_height", 0)),
                window_x=int(data.get("window_x", -1)),
                window_y=int(data.get("window_y", -1)),
                window_maximized=bool(data.get("window_maximized", False)),
                profile_gating_enabled=bool(
                    data.get("profile_gating_enabled", True)
                ),
            )
        except FileNotFoundError:
            _log.debug("Keine UI-Einstellungen gefunden — Standardwerte verwendet.")
            return cls()
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            _log.warning("UI-Einstellungen beschädigt, Standardwerte: %s", exc)
            return cls()
