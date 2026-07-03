"""Build-Helfer fuer den NoRisk-PyInstaller-Build.

NoRisk hat (anders als AUTOMATE/TeachMe) keine White-Label-Kunden-Pipeline —
der Build laeuft direkt ueber die Spec:

.venv\\Scripts\\pyinstaller.exe build_specs\\build_norisk.spec --clean --noconfirm

Dieses Modul stellt die von der Spec importierten Helfer bereit. Es lag im
Monorepo im Repo-Root und fehlte nach der Aufloesung im
NoRisk-Repo — die Spec brach mit ``ImportError: is_qt_conflicting_dll``
-Befund). Portiert aus einem Schwester-Build-Helfer im ehemaligen
Monorepo, funktionsgleich.

Autor: Patrick Riederich
"""

from __future__ import annotations


def is_qt_conflicting_dll(name_lower: str, src_lower: str = "") -> bool:
    """Filter fuer DLLs die mit Qt's Loader kollidieren.

    Third-Party-Pakete (cryptography/paramiko/bcrypt/pynacl) bringen teils
    eigene Versionen von OpenSSL-, UCRT- und ICU-DLLs mit. PyInstaller
    buendelt alle Versionen ins gleiche ``_internal/``-Verzeichnis; beim
    App-Start nimmt der Windows-Loader die erste Datei die er findet —
    meist nicht die Qt-kompatible. Symptom: ``DLL load failed while
    importing QtWidgets: Die angegebene Prozedur wurde nicht gefunden.``

    Qt selbst braucht keine der gefilterten DLLs: TLS laeuft unter Windows
    ueber Schannel (``plugins/tls/qschannelbackend.dll``), UCRT kommt ab
    Windows 10 vom System (via Windows Update gepatcht), ICU nutzt der
    Qt-Windows-Build nicht.

    WICHTIG-Review F1): CPythons EIGENE OpenSSL-Kopien aus
    ``<python>/DLLs/`` duerfen NICHT gefiltert werden — ``_ssl.pyd`` haengt
    per PE-Import an ``libcrypto-3.dll``; ohne sie stirbt jeder Python-
    TLS-Pfad (Updater, HIBP, Feeds) mit
    ``ImportError``. Gefiltert werden nur ``site-packages``-Kopien
    (die historische Qt-Kollisionsquelle).

    Aufruf am Ende eines Specs vor ``PYZ``::

        a.binaries = [
            b for b in a.binaries
            if not is_qt_conflicting_dll(b[0].lower, str(b[1]).lower)
]

    Args:
        name_lower: Lowercase-Dateiname der DLL (``b[0].lower``).
        src_lower: Lowercase-Quellpfad der DLL (``b[1]``). Leer = nur
                    Namens-Filter (rueckwaertskompatibel zu den
                    Schwester-Repos, dort ohne OpenSSL-Ausnahme).

    Returns:
        True wenn die DLL aus dem Bundle entfernt werden soll.
    """
    if name_lower.startswith("api-ms-win-"):
        return True
    if name_lower == "ucrtbase.dll":
        return True
    if name_lower.startswith("icudt") or name_lower.startswith("icuuc"):
        return True
    if "qopensslbackend" in name_lower:
        # Qt-TLS laeuft unter Windows ueber Schannel (qschannelbackend.dll).
        # Das optionale OpenSSL-Backend-Plugin wuerde per PE-Import
        # libcrypto-3-x64.dll vom Build-Host-PATH einziehen: Git
        # mingw64) — raus damit, Qt faellt auf Schannel zurueck.
        return True
    if "mingw64" in src_lower:
        # Build-Host-PATH-Verschmutzung (z.B. Git for Windows) nie buendeln.
        return True
    if name_lower.startswith("libcrypto-") or name_lower.startswith("libssl-"):
        # CPython-eigene OpenSSL (aus <python>/DLLs/) bleibt im Bundle;
        # ohne src-Info konservativ filtern (Alt-Verhalten).
        return "site-packages" in src_lower if src_lower else True
    return False
