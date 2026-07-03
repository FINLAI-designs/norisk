"""
core.help.tabs — Inline-Reiter-Widgets des zentralen FINLAI-Handbuch-Dialogs.

Enthält das schlanke ``AssistantTab``, Workstream C): Eingabe +
gestreamte Antwort + nach Domäne gruppiertes Quellen-Panel. Nutzt den am
Composition-Root verdrahteten ``UnifiedAssistantService`` über
``core.assistant.provider`` — ohne Einbettung der schweren Standalone-
``OllamaPanel`` (vermeidet Thread-/Session-Divergenz).

Schichtzugehörigkeit: ``core/`` (PySide6 erlaubt, da GUI-Schicht von core/help).
Importiert NIEMALS aus ``tools/``.
"""
