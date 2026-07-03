"""
signals — Globale Application-Signals für app-übergreifende Events.

Singleton-QObject (`global_signals`) mit klassen-level Signals. Tools,
Widgets und Dialoge können hier subscriben/emittieren, ohne sich gegenseitig
per ``hasattr(window, "_xxx")``-Magic finden zu müssen — Audit-Befunde S2-5,
S2-6 und Cross-Cutting CC-3.

Hintergrund: PySide6-Signals brauchen ein QObject als Parent. Modul-Level-
Signals ohne QObject-Parent funktionieren nicht. Das hier ist das Standard-
PySide6-Idiom für globale Application-Signals: ein Singleton-QObject mit
Klassenvariablen-Signals, plus eine Modul-Level-Instanz als Import-Alias.

Beispiel::

    # Subscriben (z. B. in einem Tool-Widget)
    from core.signals import global_signals
    global_signals.theme_changed.connect(self._on_global_theme_changed)

    # Emittieren (z. B. in MainWindow.apply_theme)
    from core.signals import global_signals
    global_signals.theme_changed.emit

Lifecycle: Die `global_signals`-Instanz lebt für die gesamte Application-
Lebensdauer. Listener müssen sich nicht aktiv abmelden — Qt räumt
disconnected Slots automatisch beim Garbage-Collect des Listener-Objekts
auf. Trotzdem sollten kurzlebige Widgets im `closeEvent` explizit
`global_signals.theme_changed.disconnect(self._slot)` aufrufen, um
Memory-Leaks bei häufigem Re-Open zu vermeiden.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal


class _GlobalSignals(QObject):
    """Singleton-QObject mit globalen Application-Signals.

    Wird **nicht direkt instanziert** — stattdessen die Modul-Level-Instanz
    `global_signals` importieren.
    """

    # Emittiert nach erfolgreicher Theme-Anwendung (siehe MainWindow.apply_theme).
    # Tools, die lokale Stylesheets nachziehen müssen, abonnieren dieses Signal.
    theme_changed = Signal()


# Singleton-Instanz — Import-Alias zur einfachen Verwendung.
global_signals = _GlobalSignals()
