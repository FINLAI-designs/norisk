"""core/updater.py — Auto-Updater für FINLAI Desktop Apps.

Prüft gegen einen statischen JSON-Endpunkt auf neue Versionen, lädt
das Update-Installer-Paket herunter und startet den neuen Prozess.

Kein GUI-Import — dieser Modul ist vollständig framework-agnostisch
und kann in Unit-Tests ohne PySide6 getestet werden.

STRIDE-Bedrohungsanalyse
-------------------------
Spoofing: TLS (verify=True, fest kodiert) — Server-Identität
                   durch CA-Zertifikat verifiziert.
Tampering: SHA-256-Verifikation des Downloads verhindert
                   nachträgliche Manipulation der Installer-EXE.
                   Der Hash ist Pflichtfeld in latest.json — fehlt er
                   oder ist die Länge falsch, bricht der Download ab
                   (statt fail-open). Zusätzlich re-hashed apply_update
                   die Datei unmittelbar vor subprocess.Popen, um das
                   TOCTOU-Fenster in %TEMP% zu schließen.
Repudiation: Update-Events werden über AuditLogger protokolliert
                   (Aufruf erfolgt im GUI-Layer).
Information Discl: Nur der Hostname wird geloggt, nie die vollständige
                   URL (Query-Strings können Token enthalten).
DoS: 5-Sekunden-Timeout für den Check verhindert
                   Blockierung beim App-Start.
Elevation of Priv: apply_update startet die neue EXE als normaler
                   User-Prozess; kein Privilege-Escalation.

Residual-Risks
--------------
- Der Update-Server selbst wird als vertrauenswürdig angesehen (eigener
  Update-Server hinter Nginx+SSL). Ein kompromittierter Server könnte
  eine manipulierte EXE ausliefern — SHA-256 schützt dagegen nur wenn
  der Hash im JSON-Response nicht ebenfalls kompromittiert ist.
- Die EXE wird in einem temporären Verzeichnis abgelegt. Unter Windows
  ist das Schreiben in %TEMP% für normale User-Prozesse erlaubt —
  kein Privilege-Escalation nötig oder möglich.

Schichtzugehörigkeit: core/ (kein PySide6-Import).

Author: Patrick Riederich
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import requests
from packaging.version import InvalidVersion, Version

from core.config import (
    UPDATE_BASE_URL,
    UPDATE_CHECK_TIMEOUT,
    UPDATE_DOWNLOAD_CHUNK_SIZE,
)

_log = logging.getLogger("finlai.updater")


# ---------------------------------------------------------------------------
# Datenmodell
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UpdateInfo:
    """Metadaten eines verfügbaren Updates.

    Attributes:
        version: Neue Version als SemVer-String (z.B. ``"1.1.0"``).
        url: Download-URL der neuen EXE (muss HTTPS sein).
        sha256: Erwarteter SHA-256-Hash der EXE (lowercase hex).
        release_notes: Kurztext mit Änderungen der neuen Version.
        min_version: Mindestversion die direkt auf ``version`` upgraden
                       kann (für Breaking-Change-Schutz).
        channel: Release-Kanal: ``"stable"``, ``"staging"`` oder
                       ``"dev"``. Nur ``"stable"`` wird vom Client abgeholt.
                       Default ``"stable"`` für Backward-Kompatibilität.
    """

    version: str
    url: str
    sha256: str
    release_notes: str
    min_version: str
    channel: str = "stable"


# ---------------------------------------------------------------------------
# URL-Resolver
# ---------------------------------------------------------------------------


def _resolve_check_url(app_id: str, override_url: str = "") -> str:
    """Gibt die URL für die Update-Prüfung zurück.

    Der Client prüft immer den ``stable``-Kanal. Staging- und Dev-Releases
    landen in separaten Pfaden auf dem Server und werden hier nie abgerufen.

    Args:
        app_id: App-Bezeichner (z.B. ``"automate_kunde1"``).
        override_url: Wenn gesetzt, wird diese URL direkt verwendet.

    Returns:
        Vollständige URL zum ``stable/latest.json``-Endpunkt, oder ein
        leerer String, wenn kein Update-Endpunkt konfiguriert ist
        (Open-Source-Default ohne ``UPDATE_BASE_URL`` und ohne Override).
    """
    if override_url:
        return override_url
    if not UPDATE_BASE_URL:
        return ""
    return f"{UPDATE_BASE_URL}/{app_id}/stable/latest.json"


# ---------------------------------------------------------------------------
# Update-Prüfung
# ---------------------------------------------------------------------------


def check_for_update(
    current_version: str,
    app_id: str,
    *,
    override_url: str = "",
) -> UpdateInfo | None:
    """Prüft ob eine neuere Version auf dem Update-Server verfügbar ist.

    Sendet einen GET-Request an den konfigurierten Update-Endpunkt und
    vergleicht die Server-Version mit ``current_version`` (SemVer).

    Schlägt der Request fehl (Netzwerkfehler, Timeout, ungültiges JSON,
    ungültige Version) wird ``None`` zurückgegeben ohne einen Crash
    auszulösen. Die App startet normal weiter.

    Args:
        current_version: Lokal installierte Version als SemVer-String.
        app_id: App-Bezeichner; bestimmt den Update-Kanal auf
                         dem Server (z.B. ``"automate_kunde1"``).
        override_url: Optionale Override-URL (White-Label: eigener
                         Server). Leer = konfigurierter Default-Endpunkt;
                         ist auch dieser leer (Open-Source-Build), wird der
                         Check ohne Netzwerk-Zugriff übersprungen.

    Returns:
        ``UpdateInfo`` wenn eine neuere Version verfügbar ist, sonst
        ``None``.
    """
    url = _resolve_check_url(app_id, override_url)
    if not url:
        # Kein Update-Endpunkt konfiguriert (Open-Source-Default ohne
        # Override) -> kein Phone-Home, kein Netzwerk-Zugriff.
        _log.debug("Update-Check übersprungen: kein Update-Endpunkt konfiguriert")
        return None
    # Nur Hostname loggen — URL könnte in Zukunft Token enthalten
    try:
        from urllib.parse import urlparse  # noqa: PLC0415

        _log.debug("Update-Check: %s", urlparse(url).hostname)
    except (ValueError, AttributeError):
        pass

    try:
        resp = requests.get(url, timeout=UPDATE_CHECK_TIMEOUT, verify=True)
        resp.raise_for_status()
        data: dict = resp.json()
    except requests.Timeout:
        _log.debug("Update-Check: Timeout nach %ds", UPDATE_CHECK_TIMEOUT)
        return None
    except requests.ConnectionError as exc:
        _log.debug("Update-Check: Netzwerkfehler — %s", exc)
        return None
    except (requests.RequestException, ValueError) as exc:
        _log.warning("Update-Check: unerwarteter Fehler — %s", exc)
        return None

    # SemVer-Vergleich
    try:
        server_ver = data["version"]
        if Version(server_ver) <= Version(current_version):
            _log.debug("Kein Update: Server=%s ≤ Lokal=%s", server_ver, current_version)
            return None
    except KeyError:
        _log.warning("Update-Check: Feld 'version' fehlt in Server-Antwort")
        return None
    except InvalidVersion as exc:
        _log.warning("Update-Check: Ungültige Versionsnummer — %s", exc)
        return None

    # Kanal-Prüfung: nur "stable"-Releases werden an Clients ausgeliefert.
    # Fehlendes Feld → "stable" (Backward-Kompatibilität mit alten Servern).
    channel = data.get("channel", "stable")
    if channel != "stable":
        _log.debug(
            "Update ignoriert: Kanal '%s' ist nicht für Clients freigegeben "
            "(nur 'stable' wird verteilt)",
            channel,
        )
        return None

    _log.info("Update verfügbar: %s → %s", current_version, data.get("version", "?"))
    return UpdateInfo(
        version=server_ver,
        url=data.get("url", ""),
        sha256=data.get("sha256", "").lower(),
        release_notes=data.get("release_notes", ""),
        min_version=data.get("min_version", "0.0.0"),
        channel=channel,
    )


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def download_update(
    update_info: UpdateInfo,
    progress_callback: Callable[[int], None] | None = None,
) -> Path | None:
    """Lädt das Update-Paket herunter und verifiziert den SHA-256-Hash.

    Der Download erfolgt als Streaming-Request (kein vollständiges
    In-Memory-Laden). Die Datei wird in ein temporäres Verzeichnis
    geschrieben. Bei Hash-Mismatch oder Fehler wird die temporäre
    Datei gelöscht und ``None`` zurückgegeben.

    Security:
        - Nur HTTPS-URLs werden akzeptiert (http:// wird abgelehnt).
        - SHA-256 wird während des Streamings berechnet (kein Re-Read).
        - Temp-Datei wird bei Fehler sofort gelöscht.
        - Vollständige URL wird NICHT geloggt.

    Args:
        update_info: Metadaten des Updates (URL, SHA-256).
        progress_callback: Wird mit 0–100 aufgerufen (Prozent).

    Returns:
        Pfad zur heruntergeladenen EXE oder ``None`` bei Fehler.
    """
    if not update_info.url.startswith("https://"):
        _log.error(
            "Download abgelehnt: URL muss HTTPS sein (erhalten: %s…)",
            update_info.url[:30],
        )
        return None

    tmp_dir = Path(tempfile.mkdtemp(prefix="finlai_update_"))
    # Dateiname nur aus dem letzten URL-Segment ableiten (kein Pfad-Traversal)
    raw_name = update_info.url.rstrip("/").split("/")[-1]
    filename = raw_name if raw_name.endswith(".exe") else "update.exe"
    dest = tmp_dir / filename

    try:
        resp = requests.get(
            update_info.url,
            stream=True,
            timeout=300,  # 5 Minuten für den Download
            verify=True,
        )
        resp.raise_for_status()

        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        hasher = hashlib.sha256()

        with dest.open("wb") as fh:
            for chunk in resp.iter_content(chunk_size=UPDATE_DOWNLOAD_CHUNK_SIZE):
                if chunk:
                    fh.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total > 0:
                        pct = min(99, int(downloaded / total * 100))
                        progress_callback(pct)

        # SHA-256-Verifikation — Hash ist Pflicht, fail-closed bei
        # leerem oder ungültigem Feld. Sonst könnte ein kompromittierter
        # Server den Hash weglassen und beliebige EXE ausliefern.
        actual = hasher.hexdigest()
        expected = update_info.sha256
        if not expected or len(expected) != 64:
            _log.error(
                "Update-Manifest ohne gültigen sha256-Hash (len=%d) — "
                "Download abgebrochen.",
                len(expected) if expected else 0,
            )
            _cleanup(dest, tmp_dir)
            return None
        if actual != expected:
            _log.error(
                "SHA-256-Mismatch: erwartet=…%s, erhalten=…%s",
                expected[-8:],
                actual[-8:],
            )
            _cleanup(dest, tmp_dir)
            return None

        if progress_callback:
            progress_callback(100)

        _log.info("Download abgeschlossen: %s (%d Bytes)", filename, downloaded)
        return dest

    except (OSError, RuntimeError, requests.RequestException, ValueError) as exc:
        _log.error("Download fehlgeschlagen: %s", exc)
        _cleanup(dest, tmp_dir)
        return None


def _cleanup(dest: Path, tmp_dir: Path) -> None:
    """Löscht temporäre Download-Dateien.

    Args:
        dest: Heruntergeladene (möglicherweise unvollständige) Datei.
        tmp_dir: Temporäres Verzeichnis.
    """
    try:
        dest.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        tmp_dir.rmdir()
    except OSError:
        pass


def _hash_file(path: Path) -> str:
    """Berechnet den SHA-256-Hex-Digest einer Datei (chunked).

    Wird in:func:`apply_update` zum TOCTOU-Re-Hash verwendet — derselbe
    Algorithmus wie im Download-Loop, damit ein Mismatch wirklich auf
    Manipulation der Datei in %TEMP% zwischen Download und Spawn hinweist.

    Args:
        path: Pfad zur Datei.

    Returns:
        Hex-Digest (lowercase, 64 Zeichen).

    Raises:
        OSError: Wenn die Datei nicht gelesen werden kann.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(UPDATE_DOWNLOAD_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Update anwenden
# ---------------------------------------------------------------------------


def apply_update(
    exe_path: Path,
    old_version: str = "",
    *,
    quit_callback: Callable[[], None] | None = None,
    expected_sha256: str = "",
) -> None:
    """Startet die neue EXE und beendet die aktuelle Instanz.

    Die neue EXE wird mit ``--updated-from {old_version}`` gestartet,
    damit sie nach dem Start einen "Update erfolgreich"-Hinweis zeigen
    kann. Die aktuelle Instanz wird über ``quit_callback`` beendet
    (typischerweise ``QApplication.quit``).

    Wenn ``expected_sha256`` gesetzt ist, wird die EXE unmittelbar vor
    dem Spawn erneut gehasht und gegen diesen Wert geprüft. Das schließt
    das TOCTOU-Fenster zwischen Download-Verifikation und Prozessstart —
    ein lokaler Angreifer (oder Anti-Virus) kann die Datei in %TEMP% nicht
    unbemerkt austauschen.

    Args:
        exe_path: Pfad zur heruntergeladenen und verifizierten EXE.
        old_version: Bisher installierte Version (für ``--updated-from``).
        quit_callback: Wird nach dem Spawn aufgerufen um die aktuelle
                         App zu beenden. Fallback: ``sys.exit(0)``.
        expected_sha256: SHA-256-Hash aus ``UpdateInfo``. Leer = kein
                         Re-Check (Backward-Compat für Tests; Production-
                         Caller sollten den Hash immer durchreichen).
    """
    if not exe_path.exists():
        _log.error("apply_update: EXE nicht gefunden — %s", exe_path.name)
        return

    if expected_sha256:
        try:
            actual = _hash_file(exe_path)
        except OSError as exc:
            _log.error(
                "apply_update: EXE-Re-Hash fehlgeschlagen — %s", exc
            )
            return
        if actual != expected_sha256:
            _log.error(
                "apply_update: SHA-256-Mismatch vor Spawn — "
                "erwartet=…%s, erhalten=…%s. Update abgebrochen.",
                expected_sha256[-8:],
                actual[-8:],
            )
            return

    args = [str(exe_path)]
    if old_version:
        args += ["--updated-from", old_version]

    try:
        _log.info("Starte neue Version: %s", exe_path.name)
        if sys.platform == "win32":
            subprocess.Popen(  # noqa: S603
                args,
                creationflags=subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
        else:
            subprocess.Popen(args, close_fds=True)  # noqa: S603
    except OSError as exc:
        _log.error("apply_update: Prozess konnte nicht gestartet werden — %s", exc)
        return

    # Aktuelle App beenden
    if quit_callback is not None:
        quit_callback()
    else:
        sys.exit(0)
