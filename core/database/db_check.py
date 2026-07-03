"""
db_check — Startup-Check fuer SQLCipher-Verfuegbarkeit.

Wird beim App-Start aufgerufen bevor andere Komponenten
initialisiert werden. Beendet die Anwendung mit einer
verstaendlichen Fehlermeldung wenn SQLCipher fehlt.

Schichtzugehoerigkeit: core/ (framework-agnostisch wo moeglich).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations


def check_sqlcipher_available() -> None:
    """Prueft SQLCipher-Verfuegbarkeit beim App-Start.

    Testet ob sqlcipher3 importierbar ist und eine
    In-Memory-Datenbank erstellt werden kann.

    Raises:
        SystemExit: Falls sqlcipher3 nicht verfuegbar
            oder fehlerhaft ist.
    """
    from core.logger import get_logger  # noqa: PLC0415

    log = get_logger(__name__)

    try:
        import sqlcipher3  # noqa: PLC0415

        conn = sqlcipher3.connect(":memory:")
        conn.execute("PRAGMA key='test'")
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.close()
        log.info("SQLCipher: verfuegbar.")
    except ImportError:
        _show_error_and_exit(
            "sqlcipher3 nicht installiert!\n\nBitte ausfuehren:\npip install sqlcipher3"
        )
    except Exception as exc:
        _show_error_and_exit(
            f"SQLCipher Fehler:\n{exc}\n\nBitte sqlcipher3 neu installieren."
        )


def _show_error_and_exit(msg: str) -> None:
    """Zeigt einen Fehlerdialog und beendet die Anwendung.

    Versucht zuerst einen Qt-Dialog — faellt auf
    Konsolen-Ausgabe zurueck wenn Qt nicht verfuegbar ist.

    Args:
        msg: Fehlermeldung fuer den Nutzer.
    """
    import sys  # noqa: PLC0415

    try:
        from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: PLC0415

        _app = QApplication.instance() or QApplication(sys.argv)  # noqa: F841
        QMessageBox.critical(
            None,
            "FINLAI - Sicherheitskomponente fehlt",
            f"FEHLER: {msg}",
        )
    except Exception:  # noqa: BLE001 -- Letzter Fallback beim App-Start (PySide6/Qt-Init kann beliebig fehlschlagen), darf print nicht blockieren
        print(f"KRITISCH: {msg}")
    sys.exit(1)
