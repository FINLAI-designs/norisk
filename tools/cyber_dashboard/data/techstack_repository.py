"""
techstack_repository — Persönlicher Tech-Stack für CVE-Monitoring.

Speichert Produkte in einer JSON-Datei unter ~/.finlai/techstack.json.
Neu-Installationen starten mit leerem Stack; die Vorschlagsliste für
österreichische Steuerkanzleien (:data:`AT_STARTER_STACK`) wird nur auf
explizite User-Aktion aus der Techstack-UI geladen.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

import json

from core.finlai_paths import finlai_dir
from core.logger import get_logger
from tools.cyber_dashboard.domain.interfaces import ITechStackRepository
from tools.cyber_dashboard.domain.models import TechStackEintrag

log = get_logger(__name__)

STACK_PATH = finlai_dir() / "techstack.json"

# Default beim ersten Start: leer. Beta-Tester sahen sonst die frühere
# hardcodierte AT-Kanzlei-Liste und hielten sie für Entwicklerdaten.
DEFAULT_STACK: list[TechStackEintrag] = []

# Opt-in-Vorschlagsliste für österreichische Steuerkanzleien.
# Wird ausschließlich auf Knopfdruck im leeren Techstack-Tab geladen.
AT_STARTER_STACK: list[TechStackEintrag] = [
    TechStackEintrag("Windows", "Server 2022", "OS"),
    TechStackEintrag("Windows", "11", "OS"),
    TechStackEintrag("Python", "3.12", "Runtime"),
    TechStackEintrag("SQLite", "", "Datenbank"),
    TechStackEintrag("OpenSSL", "", "Security"),
    TechStackEintrag("Apache", "", "Webserver"),
    TechStackEintrag("Microsoft Office", "", "App"),
    TechStackEintrag("BMD", "", "Branchensoftware"),
]


class TechStackRepository(ITechStackRepository):
    """Verwaltet den persönlichen Tech-Stack für CVE-Monitoring.

    Speichert Einträge als JSON-Datei unter ~/.finlai/techstack.json.
    Fällt auf den Default-Stack zurück wenn keine Konfiguration vorhanden ist.
    """

    def lade(self) -> list[TechStackEintrag]:
        """Lädt den Tech-Stack aus der JSON-Datei.

        Fällt auf DEFAULT_STACK zurück wenn keine Datei vorhanden ist
        oder die Datei nicht geparst werden kann.

        Returns:
            Liste der Tech-Stack-Einträge.
        """
        if not STACK_PATH.exists():
            return DEFAULT_STACK.copy()
        try:
            data = json.loads(STACK_PATH.read_text(encoding="utf-8"))
            return [TechStackEintrag(**e) for e in data]
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as exc:
            log.warning("TechStack laden fehlgeschlagen: %s", type(exc).__name__)
            return DEFAULT_STACK.copy()

    def speichere(self, stack: list[TechStackEintrag]) -> None:
        """Speichert den kompletten Tech-Stack als JSON.

        Args:
            stack: Vollständige Liste der Einträge.
        """
        STACK_PATH.parent.mkdir(parents=True, exist_ok=True)
        STACK_PATH.write_text(
            json.dumps(
                [
                    {
                        "name": e.name,
                        "version": e.version,
                        "kategorie": e.kategorie,
                        "aktiv": e.aktiv,
                        "cpe": e.cpe,
                    }
                    for e in stack
                ],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    def hinzufuegen(self, eintrag: TechStackEintrag) -> None:
        """Fügt einen Eintrag hinzu wenn der Name noch nicht vorhanden ist.

        Args:
            eintrag: Neuer Tech-Stack-Eintrag.
        """
        stack = self.lade()
        namen = {e.name.lower() for e in stack}
        if eintrag.name.lower() not in namen:
            stack.append(eintrag)
            self.speichere(stack)

    def entfernen(self, name: str) -> None:
        """Entfernt einen Eintrag nach Name (case-insensitive).

        Args:
            name: Name des zu entfernenden Produkts.
        """
        stack = self.lade()
        stack = [e for e in stack if e.name.lower() != name.lower()]
        self.speichere(stack)
