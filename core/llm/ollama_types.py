"""
ollama_types — Gemeinsame Wertobjekte für die lokale Ollama-Anbindung.

Reine Datenklassen ohne Framework-Abhängigkeiten. Aus
``tools/ki_integration/domain/models.py`` nach ``core/llm/`` gehoben, damit der Ollama-Adapter und der vereinte FINLAI-Assistent
tool-übergreifend (KI-Integration + Handbuch-Assistent) dieselben Typen
nutzen, ohne Cross-Tool-Importe.

Schichtzugehörigkeit: core/ (Shared Utilities).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OllamaModel:
    """Ein lokal verfügbares Ollama-Modell.

    Attributes:
        name: Vollständiger Modellname (z. B. ``"llama3:8b"``).
        size: Modellgröße in Bytes.
        modified_at: ISO-8601-Zeitpunkt der letzten Änderung.
        is_running: True wenn das Modell aktuell im Speicher geladen ist.
    """

    name: str
    size: int
    modified_at: str
    is_running: bool = False


@dataclass
class OllamaStatus:
    """Verbindungsstatus des lokalen Ollama-Servers.

    Attributes:
        is_available: True wenn Ollama erreichbar ist.
        version: Ollama-Versionsstring (leer wenn nicht verfügbar).
        models: Liste der lokal installierten Modelle.
        error_message: Fehlermeldung wenn ``is_available`` False ist.
    """

    is_available: bool
    version: str = ""
    models: list[OllamaModel] = field(default_factory=list)
    error_message: str = ""
