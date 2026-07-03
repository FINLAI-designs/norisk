"""
provider — Lazy-Singleton-Slot für den vereinten FINLAI-Assistenten, C).

``core/`` definiert hier nur den *Slot*; der Composition-Root
(``apps/__init__.py``) füllt ihn mit einer Factory, die den ``tools/``-Handbuch-
Retriever verdrahtet. So bleibt die Abhängigkeitsrichtung gewahrt: der im
Handbuch-Dialog eingebettete Assistenz-Reiter (``core/help``) ruft nur
``get_assistant_service`` auf und importiert NIEMALS aus ``tools/``
(Layering-Regel R5).

Die Service-Instanz wird LAZY beim ersten Zugriff gebaut — nicht beim App-Start.
Dadurch muss weder Ollama laufen noch der RAG-Index aufgebaut sein, bevor der
Nutzer den Assistenten tatsächlich öffnet. Eine Instanz OHNE aufgelöstes Modell
(Ollama beim ersten Aufbau nicht erreichbar) wird absichtlich NICHT gecacht —
so heilt sich der Assistent selbst, sobald Ollama später verfügbar ist.

Thread-Sicherheit: Der erste (bauende) Zugriff erfolgt aus dem Assistenz-Worker-
Thread (blockierendes I/O: Modell-Auflösung). Ein Lock serialisiert den seltenen
parallelen Doppel-Aufbau (zwei gleichzeitig offene Handbuch-Dialoge).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from core.assistant.unified_assistant_service import UnifiedAssistantService
from core.logger import get_logger

_log = get_logger(__name__)

#: Vom Composition-Root registrierte Factory (None = kein App-Kontext / Test).
_factory: Callable[[], UnifiedAssistantService] | None = None
#: Gecachte Instanz — nur gesetzt, wenn ein Modell aufgelöst werden konnte.
_instance: UnifiedAssistantService | None = None
_lock = threading.Lock()


def register_assistant_factory(
    factory: Callable[[], UnifiedAssistantService],
) -> None:
    """Registriert die Service-Factory am Composition-Root (``apps/``).

    Invalidiert eine etwaig gecachte Instanz (z. B. bei Re-Login mit anderer
    App-Konfiguration).

    Args:
        factory: Parameterlose Funktion, die einen frisch verdrahteten
            ``UnifiedAssistantService`` liefert.
    """
    global _factory, _instance
    with _lock:
        _factory = factory
        _instance = None


def get_assistant_service() -> UnifiedAssistantService | None:
    """Liefert die (lazy gebaute) Service-Instanz oder ``None`` ohne App-Kontext.

    LÄUFT IM WORKER-THREAD — kann blockierendes I/O auslösen (Modell-Auflösung,
    erster Index-Aufbau). NICHT im Main-Thread aufrufen. Eine Instanz ohne
    aufgelöstes Modell wird nicht gecacht (Selbstheilung bei spätem Ollama).

    Returns:
        Singleton-Service oder ``None``, wenn keine Factory registriert ist
        (Dialog außerhalb des laufenden App-Kontexts / Test ohne Wiring) oder der
        Aufbau fehlschlug.
    """
    global _instance
    with _lock:
        if _instance is not None:
            return _instance
        if _factory is None:
            return None
        try:
            service = _factory()
        except Exception as exc:  # noqa: BLE001 — Aufbau fail-soft, UI zeigt Hinweis
            _log.error(
                "Assistenz-Service-Aufbau fehlgeschlagen: %s", type(exc).__name__
            )
            return None
        # Nur eine voll nutzbare Instanz (Modell aufgelöst) cachen.
        if service.model:
            _instance = service
        return service


def peek_assistant_service() -> UnifiedAssistantService | None:
    """Liefert die GECACHTE Instanz, ohne sie zu bauen (für Cleanup/Reset)."""
    return _instance


def reset_assistant_service() -> None:
    """Verwirft die gecachte Instanz (Tests / App-Teardown)."""
    global _instance
    with _lock:
        _instance = None
