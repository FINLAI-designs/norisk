"""
help — In-App-Hilfesystem für NoRisk (Phase 1).

Dreistufig:
  1. ``HelpPanel`` — zusammenfaltbares Info-Panel oben in jedem Tool-Widget
  2. ``HelpButton`` / ``HelpTooltip`` — ``?``-Buttons neben wichtigen Elementen
  3. ``HelpDialog`` — zentrales Handbuch-Fenster mit Volltextsuche

Datenbasis::mod:`core.help.help_content` (alle Texte zentral, kein
Hardcoding in Widgets).

Author: Patrick Riederich
Version: 1.0
"""
