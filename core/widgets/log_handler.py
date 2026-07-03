"""
log_handler — Qt-Bridge fuer Python-Logging.

Sprint 7 Phase 1: Aus core/main_window.py extrahiert.
Zwei eng zusammenhaengende Klassen die in MainWindow.__init__
verkabelt werden, um Live-Log-Eintraege in der Statusleiste anzuzeigen.

* LogSignalEmitter -- reines QObject mit ``log_received(record)``-Signal.
* StatusLogHandler -- ``logging.Handler``-Subclass die jedes Record
  via Komposition (NICHT Vererbung) an den Emitter weiterreicht.

Trennung in 2 Klassen vermeidet den Namenskonflikt zwischen
``logging.Handler.emit(record)`` und ``QObject.signal.emit``.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import logging

from PySide6.QtCore import QObject, Signal


class LogSignalEmitter(QObject):
    """Reines Signal-Objekt ohne logging.Handler-Vererbung.

    Getrennt von StatusLogHandler um den Namenskonflikt zwischen
    logging.Handler.emit(record) und Signal.emit vollständig zu vermeiden.

    Signals:
        log_received(object): Für jeden verarbeiteten LogRecord.
    """

    log_received = Signal(object)


class StatusLogHandler(logging.Handler):
    """Logging-Handler der LogRecords via Komposition an ein Qt-Signal weiterleitet.

    Erbt ausschließlich von logging.Handler — kein QObject, kein emit-Konflikt.

    Args:
        emitter: LogSignalEmitter-Instanz die das Signal besitzt.
    """

    def __init__(self, emitter: LogSignalEmitter) -> None:
        super().__init__()
        self._emitter = emitter

    def emit(self, record: logging.LogRecord) -> None:
        """Leitet den LogRecord als Qt-Signal weiter.

        Args:
            record: Der vom Logging-Framework erzeugte Datensatz.
        """
        self._emitter.log_received.emit(record)
