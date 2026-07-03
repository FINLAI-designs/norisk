"""
patch_upgrade — Winget-Upgrade-Executor und Datenmodell fuer PM-2.x.

 PM-2.x). Aktiver Patch-Pfad: nimmt eine ``winget_id`` aus
einem ``SoftwareItem`` (Bug-Fix-Sprint C-1.5), ruft ``winget upgrade``
synchron auf und liefert ein:class:`UpgradeResult` zurueck. Der Executor
ist GUI-frei und thread-safe (kein Modul-State) — der GUI-Worker
(:mod:`tools.patch_monitor.gui.upgrade_worker`) wraps ihn in einem QThread.

Schicht: application-aequivalent (analog
:mod:`core.patch_winget_module`). Keine PySide6-Imports, kein
``EncryptedDatabase``-Zugriff — Audit-Persistenz erfolgt im
:class:`tools.patch_monitor.data.upgrade_history_repository`-Repository
(Stop-Step B).

**Sicherheit:**

* Subprocess wird als **Liste** aufgerufen (kein ``shell=True``,
  keine f-string-Interpolation), damit Command-Injection ausgeschlossen
  ist auch wenn das Inventar in Zukunft externe Quellen anzapft.
* ``winget_id`` muss durch:func:`_validate_winget_id` laufen (Regex
  ``^[A-Za-z0-9._+\\-]+$``) — sonst:class:`ValidationError`.
* Timeout pro Install: 300 s (Default, ueber Parameter ueberschreibbar).
  Office-Updates brauchen erfahrungsgemaess bis zu 4 Minuten.

**Out-of-Scope dieses Moduls** (Folge-Stop-Steps):

* Batch-Orchestrierung mit Progress-Events → ``patch_upgrade_service.py``
  in Stop-Step B.
* Persistenz der Upgrade-Historie → Repository in Stop-Step B.
* QThread-Wrapping + Live-Log-Stream → ``upgrade_worker.py`` in
  Stop-Step C.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from core.exceptions import ExternalToolError, ValidationError
from core.logger import get_logger
from core.patch_id_utils import is_synthetic_id
from core.patch_strategy import DEFAULT_PATCH_STRATEGY, PatchStrategy
from core.proc import run_hidden

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

#: Default-Timeout fuer einen einzelnen ``winget upgrade``-Aufruf.
#: Office-/Visual-Studio-Updates koennen mehrere Minuten laufen — 5 Minuten
#: sind ein Kompromiss zwischen "User sieht nicht ewig zu" und
#: "kein False-Timeout bei legitimen langen Installs".
DEFAULT_UPGRADE_TIMEOUT_S: Final[int] = 300

#: Regex fuer eine gueltige winget-Produkt-Id. Erlaubt sind Buchstaben,
#: Ziffern, Punkt, Unterstrich, Plus, Minus. Damit sind echte winget-Ids
#: wie ``"Mozilla.Firefox"`` oder ``"Microsoft.VCRedist.2013.x86"``
#: abgedeckt. ARP-Pfade (``"ARP\\Machine\\X64\\..."``) und Backslash-
#: Idiotie scheitern hier hart — diese Items haben in der Praxis
#: ``winget_id=None`` (siehe ``collect_winget_module``-Source-Mapping)
#: und werden vom Service vorab gefiltert.
_WINGET_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._+\-]+$")

#: Regex fuer eine gueltige Microsoft-Store-Id. Store-Ids sind
#: ausschliesslich Grossbuchstaben und Ziffern, ohne Sonderzeichen
#: (z. B. ``"XP8K2L36VP0QMB"`` fuer KeePassXC).:
#: separater Regex statt ``_WINGET_ID_RE`` damit Injection-Schutz und
#: Source-Trennung sauber bleiben (Store-IDs gehen in ``winget upgrade
#: --source msstore``, nicht in den Default-Catalog).
_STORE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z0-9]+$")


# ---------------------------------------------------------------------------
# Datenmodell
# ---------------------------------------------------------------------------


class UpgradeStatus(StrEnum):
    """Outcome eines:class:`WingetUpgradeExecutor.upgrade`-Aufrufs.

    *:attr:`SUCCESS` — winget Exit-Code 0.
    *:attr:`FAILED` — winget Exit-Code != 0 (z. B. Paket nicht
      gefunden, fehlende Admin-Rechte, Download-Fehler).
    *:attr:`TIMEOUT` — Subprocess wurde nach ``timeout_s`` Sekunden
      hart beendet. Der Install-Prozess kann im Hintergrund weiterlaufen
      — der Aufrufer sollte die User-Erwartung entsprechend setzen.
    *:attr:`SKIPPED` — winget_id ist ``None`` oder nicht winget-faehig
      (vom Service vorab gefiltert; der Executor selbst wirft hier
:class:`ValidationError`, dieser Wert ist fuer den Batch-Service
      reserviert).
    """

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class UpgradeRequest:
    """Eine ausgewaehlte Update-Aktion fuer den Batch-Service.

    Wird vom UI (Multi-Select-Tabelle) aus einer
:class:`core.patch_result.PatchScanResult`-Zeile konstruiert.
    Das ``version_from`` / ``version_to``-Paar dient nur dem
    Audit-Trail — der Executor selbst nutzt nur die Package-Id.

    **Package-Identifier (genau einer ist gesetzt):**
        * ``winget_id`` — fuer Catalog-Apps (z. B. ``"Mozilla.Firefox"``).
          Geht ueber ``WingetUpgradeExecutor.upgrade``.
        * ``store_id`` — fuer Microsoft-Store-Apps, z. B.
          ``"XP8K2L36VP0QMB"`` fuer KeePassXC). Geht ueber
          ``WingetUpgradeExecutor.upgrade_msstore``.

    Der Dispatcher in
:class:`tools.patch_monitor.application.batch_upgrade_service.BatchUpgradeService`
    waehlt anhand des nicht-``None``-Felds. Setzen beide Felder ist ein
    Programmierfehler und wird im ``BatchUpgradeService`` defensiv
    geloggt (kein Crash, aber FAILED-Result).

    Attributes:
        winget_id: Catalog-Produkt-Id oder ``None`` bei msstore-Quellen.
        store_id: Microsoft-Store-Identifier oder ``None`` bei
            Catalog-Quellen.
        version_from: Aktuell installierte Version (``None`` wenn
            nicht ermittelbar). Reines Audit-Feld.
        version_to: Verfuegbare Version, die installiert werden
            soll (``None`` wenn nicht ermittelbar). Reines Audit-Feld.
        display_name: User-lesbarer Name fuer Live-Log / Confirm-
            Dialog (z. B. ``"Microsoft Visual C++ 2013 (x64)"``).
    """

    winget_id: str | None
    version_from: str | None
    version_to: str | None
    display_name: str
    store_id: str | None = None

    @property
    def package_id(self) -> str:
        """Liefert die nicht-``None``-Id fuer Audit-Trail + Log-Output.

        Fallback ``"<unknown>"`` wenn beide Felder None sind (sollte nie
        passieren, wird vom Service vorab gefiltert).
        """
        return self.winget_id or self.store_id or "<unknown>"


@dataclass(frozen=True)
class UpgradeResult:
    """Ergebnis eines einzelnen Upgrade-Aufrufs.

    Frozen damit es safe ueber Thread-Grenzen wandert (GUI-Worker →
    Repository → Live-Log). Alle Felder sind nicht-PII (winget_id ist
    Produkt-Identifier, kein User-Daten-Pfad).

    Attributes:
        winget_id: Die Produkt-Id, fuer die das Upgrade lief.
        status: Outcome-Enum (:class:`UpgradeStatus`).
        exit_code: winget Exit-Code, ``None`` bei TIMEOUT/SKIPPED.
        duration_ms: Wandzeit des Subprocess in Millisekunden,
            ``0`` fuer SKIPPED.
        stdout: Letzte ``stdout``-Excerpts (max. 8 KiB, gekuerzt mit
            Marker). Leer wenn nichts gelesen wurde.
        stderr: Letzte ``stderr``-Excerpts (max. 8 KiB, gekuerzt mit
            Marker). Leer wenn nichts gelesen wurde.
        error: Frei-Text-Fehlermeldung wenn ``status != SUCCESS``.
            Enthaelt keine Pfade / User-Daten (Privacy-Filter wie
            Bug-Fix-Sprint C-5).
    """

    winget_id: str
    status: UpgradeStatus
    exit_code: int | None
    duration_ms: int
    stdout: str
    stderr: str
    error: str | None = None

    @property
    def success(self) -> bool:
        """Convenience-Property — ``True`` wenn:attr:`UpgradeStatus.SUCCESS`."""
        return self.status is UpgradeStatus.SUCCESS


# Max. Bytes pro stdout/stderr-Excerpt (Soft-Limit analog
# briefing_history Output-Limit).
_OUTPUT_SOFT_LIMIT_BYTES: Final[int] = 8 * 1024
_OUTPUT_TRUNCATION_MARKER: Final[str] = "\n[... gekuerzt ...]"


# ---------------------------------------------------------------------------
# Winget-Exit-Code → User-lesbare Erklaerung-Smoke 2026-05-12)
# ---------------------------------------------------------------------------
#
# Quelle: Microsoft winget Public API
# https://learn.microsoft.com/en-us/windows/package-manager/winget/returnCodes
#
# Wir mappen nur Codes, deren Bedeutung wir verlaesslich kennen. Unbekannte
# Codes fallen auf die generische "winget Exit-Code <N>"-Variante zurueck —
# der User kann ihn dann googeln statt eine erfundene Erklaerung zu bekommen.

_WINGET_EXIT_HINTS: Final[dict[int, str]] = {
    # 0x8A150001 / 2316632065
    0x8A150001: "interner winget-Fehler",
    # 0x8A150002 / 2316632066
    0x8A150002: "ungueltige winget-Argumente (NoRisk-Bug? Bitte melden)",
    # 0x8A150005 / 2316632069
    0x8A150005: "winget-Subkommando fehlgeschlagen",
    # 0x8A150010 / 2316632080
    0x8A150010: "Installer hat selbst einen Fehler gemeldet",
    # 0x8A150011 / 2316632081
    0x8A150011: "winget kennt das Paket nicht (Manifest fehlt)",
    # 0x8A150043 / 2316632131
    0x8A150043: "bereits aktuell — kein Update verfuegbar",
    # 0x8A150052 / 2316632146
    0x8A150052: "Programm laeuft — bitte schliessen und erneut versuchen",
    # 0x8A15006B / 2316632107
    0x8A15006B: "bereits aktuell oder Installer fuer dein System nicht passend",
    # 0x8A15006F / 2316632111
    0x8A15006F: "Neustart erforderlich — bitte Windows neu starten",
    # 1602 — Standard MSI: User-Cancel
    1602: "Installation vom User abgebrochen",
    # 1603 — Standard MSI: Fatal error
    1603: "fataler Installer-Fehler (oft fehlende Admin-Rechte)",
    # 1605 — Standard MSI: Product not installed
    1605: "Produkt ist nicht installiert (Reinstall noetig?)",
    # 3010 — Standard MSI: Reboot required
    3010: "erfolgreich — Neustart erforderlich",
}


def _format_exit_code_error(exit_code: int) -> str:
    """Baut die ``UpgradeResult.error``-Zeile fuer einen winget-Exit-Code.

    Args:
        exit_code: Der Exit-Code aus dem subprocess.

    Returns:
        ``"winget Exit-Code <N> — <Hinweis>"`` wenn Code bekannt,
        sonst ``"winget Exit-Code <N>"``.
    """
    hint = _WINGET_EXIT_HINTS.get(exit_code)
    if hint:
        return f"winget Exit-Code {exit_code} — {hint}"
    return f"winget Exit-Code {exit_code}"


# ---------------------------------------------------------------------------
# Validierung
# ---------------------------------------------------------------------------


def _validate_winget_id(winget_id: str) -> None:
    """Erzwingt das Regex-Format fuer eine winget-Id.

    Args:
        winget_id: Zu pruefender String.

    Raises:
        ValidationError: Wenn ``winget_id`` leer ist oder einen
            Zeichensatz hat, der nicht zu einer echten winget-Id passt
            (Injection-Schutz).
    """
    if not winget_id:
        raise ValidationError("winget_id ist leer")
    if not _WINGET_ID_RE.match(winget_id):
        # Bewusst keine Anzeige des Inputs im Fehler — Privacy +
        # kein Echo-Pfad fuer Injection-Versuche.
        raise ValidationError("winget_id enthaelt unzulaessige Zeichen")


def _validate_store_id(store_id: str) -> None:
    """Erzwingt das Regex-Format fuer eine Microsoft-Store-Id.

    Args:
        store_id: Zu pruefender String (z. B. ``"XP8K2L36VP0QMB"``).

    Raises:
        ValidationError: Wenn ``store_id`` leer ist oder einen
            Zeichensatz hat, der nicht zu einer Store-Id passt
            (Injection-Schutz, gleiche Konvention wie ``_validate_winget_id``).
    """
    if not store_id:
        raise ValidationError("store_id ist leer")
    if not _STORE_ID_RE.match(store_id):
        raise ValidationError("store_id enthaelt unzulaessige Zeichen")


def _truncate_output(raw: str) -> str:
    """Kuerzt Subprocess-Output auf das Soft-Limit mit Marker.

    Args:
        raw: stdout- oder stderr-Inhalt.

    Returns:
        Bis zu:data:`_OUTPUT_SOFT_LIMIT_BYTES` Bytes inklusive
        Truncation-Marker. Leerer Input wird leer zurueckgegeben.
    """
    if not raw:
        return ""
    encoded = raw.encode("utf-8", errors="replace")
    if len(encoded) <= _OUTPUT_SOFT_LIMIT_BYTES:
        return raw
    truncated = encoded[:_OUTPUT_SOFT_LIMIT_BYTES].decode("utf-8", errors="replace")
    return truncated + _OUTPUT_TRUNCATION_MARKER


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------


class WingetUpgradeExecutor:
    """Synchroner Wrapper um ``winget upgrade``.

    Default-Konstruktion ohne Argumente reicht — Tests injizieren ein
    Subprocess-Surrogat (z. B. ``subprocess_run=mock_run``).

    **Thread-Safety:** Keine Instanz-State-Mutation nach
    ``__init__`` — mehrere Threads duerfen die gleiche Executor-Instanz
    gleichzeitig nutzen.
    """

    def __init__(
        self,
        *,
        subprocess_run=None,  # noqa: ANN001 - Test-Injection-Point
        timeout_s: int = DEFAULT_UPGRADE_TIMEOUT_S,
    ) -> None:
        """Initialisiert den Executor.

        Args:
            subprocess_run: Optionale Subprocess-Funktion (Standard:
:func:`core.proc.run_hidden` — args-Liste, kein Shell,
                CREATE_NO_WINDOW auf Windows). Tests injizieren hier ein
                ``MagicMock`` oder eine Test-Doppelung mit
                deterministischem Verhalten.
            timeout_s: Default-Timeout pro Aufruf in Sekunden. Kann
                pro ``upgrade``-Aufruf ueberschrieben werden.
        """
        self._subprocess_run = subprocess_run or run_hidden
        self._default_timeout_s = timeout_s

    def upgrade(
        self,
        winget_id: str,
        *,
        silent: bool = True,
        timeout_s: int | None = None,
        strategy: PatchStrategy = DEFAULT_PATCH_STRATEGY,
    ) -> UpgradeResult:
        """Fuehrt ``winget upgrade --id <winget_id>`` aus.

        Args:
            winget_id: Produkt-Id (z. B. ``"Mozilla.Firefox"``). Wird
                gegen:data:`_WINGET_ID_RE` validiert.
            silent: Wenn ``True``, ``--silent`` an winget weitergeben
                (kein UI-Prompt, Installer im Hintergrund).
            timeout_s: Optional ein abweichender Timeout in Sekunden.
                Default::attr:`_default_timeout_s`.
            strategy: Patch-Strategie der App.
:attr:`~core.patch_strategy.PatchStrategy.STABLE` =
                Standard-Command;:attr:`~core.patch_strategy.PatchStrategy.LATEST`
                ergaenzt ``--include-unknown`` + ``--include-pinned``;
:attr:`~core.patch_strategy.PatchStrategy.NONE` ist hier ein
                Fehler (siehe ``Raises``).

        Returns:
:class:`UpgradeResult` mit Outcome + Dauer + Output-Excerpts.
            Wirft KEINE Exception fuer den Normalfall (Exit-Code != 0,
            Timeout) — der Caller bekommt immer ein Result-Objekt und
            kann Batch-Loops sauber weiterlaufen lassen.

        Raises:
            ValidationError: Wenn ``winget_id`` eine synthetische
                Registry-/MSIX-Id ist (``regid:``/``msix:`` — winget kennt
                sie nicht), wenn ``winget_id`` das Regex nicht
                durchlaeuft (Injection-Versuch oder Fehl-Konfiguration),
                ODER wenn ``strategy``:attr:`PatchStrategy.NONE` ist —
                fail-closed-Schutz: der Caller (Batch-Service/GUI) muss
                NONE-Apps vorher herausfiltern, der Executor patcht eine
                vom User ausgenommene App niemals (privilegierte Operation).
            ExternalToolError: Wenn ``winget`` selbst nicht gestartet
                werden kann (``FileNotFoundError`` aus dem Subprocess
                — z. B. Non-Windows-Plattform). Andere Exceptions
                werden NICHT durchgereicht.
        """
        # Defense-in-depth: synthetische Ids (Registry-/MSIX-Apps,
        # ``regid:``/``msix:``) duerfen nie an ein winget-Kommando. Der
        # Doppelpunkt scheitert ohnehin an ``_validate_winget_id`` — die
        # explizite Pruefung liefert die praezisere Fehlermeldung.
        if is_synthetic_id(winget_id):
            raise ValidationError(
                "winget_id ist eine synthetische Registry-/MSIX-Id — "
                "nicht via winget installierbar"
            )
        _validate_winget_id(winget_id)
        if strategy is PatchStrategy.NONE:
            raise ValidationError(
                "PatchStrategy.NONE: Upgrade fuer diese App ist deaktiviert"
            )
        return self._run_subprocess(
            package_id=winget_id,
            cmd=self._build_command(winget_id, silent=silent, strategy=strategy),
            silent=silent,
            timeout_s=timeout_s,
            log_prefix="winget upgrade",
        )

    def upgrade_msstore(
        self,
        store_id: str,
        *,
        silent: bool = True,
        timeout_s: int | None = None,
    ) -> UpgradeResult:
        """Fuehrt ``winget upgrade --id <store_id> --source msstore`` aus.

        Pendant zu:meth:`upgrade` fuer Microsoft-Store-Apps. Die Store-Id
        ist kein winget-Catalog-Format (``"XP8K2L36VP0QMB"`` statt
        ``"Mozilla.Firefox"``), darum eigener Regex (:data:`_STORE_ID_RE`)
        und eigener Command-Builder mit ``--source msstore``.

        Args:
            store_id: Microsoft-Store-Identifier (Großbuchstaben + Ziffern).
            silent: ``--silent``-Flag setzen.
            timeout_s: Optionaler abweichender Timeout in Sekunden.

        Returns:
:class:`UpgradeResult` analog zu:meth:`upgrade`.

        Raises:
            ValidationError: Wenn ``store_id`` das Regex nicht durchlaeuft.
            ExternalToolError: Wenn ``winget`` nicht startbar ist.
        """
        _validate_store_id(store_id)
        return self._run_subprocess(
            package_id=store_id,
            cmd=self._build_msstore_command(store_id, silent=silent),
            silent=silent,
            timeout_s=timeout_s,
            log_prefix="winget upgrade msstore",
        )

    def _run_subprocess(
        self,
        *,
        package_id: str,
        cmd: list[str],
        silent: bool,
        timeout_s: int | None,
        log_prefix: str,
    ) -> UpgradeResult:
        """Gemeinsame Subprocess-Run-Logik fuer beide Upgrade-Modi.

        Extrahiert aus:meth:`upgrade` +:meth:`upgrade_msstore` damit
        die Timeout-/Exception-Handhabung nur an einer Stelle lebt.
        """
        if not sys.platform.startswith("win"):
            raise ExternalToolError("winget upgrade nur auf Windows verfuegbar")

        effective_timeout = timeout_s or self._default_timeout_s
        log.info(
            "%s gestartet: id=%s silent=%s timeout=%ds",
            log_prefix,
            package_id,
            silent,
            effective_timeout,
        )

        start = time.monotonic()
        try:
            completed = self._subprocess_run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            log.warning(
                "%s Timeout nach %ds: id=%s",
                log_prefix,
                effective_timeout,
                package_id,
            )
            return UpgradeResult(
                winget_id=package_id,
                status=UpgradeStatus.TIMEOUT,
                exit_code=None,
                duration_ms=duration_ms,
                stdout=_truncate_output(exc.stdout or "")
                if isinstance(exc.stdout, str)
                else "",
                stderr=_truncate_output(exc.stderr or "")
                if isinstance(exc.stderr, str)
                else "",
                error=f"Timeout nach {effective_timeout}s",
            )
        except FileNotFoundError as exc:
            raise ExternalToolError(
                "winget-CLI nicht gefunden — bitte App-Installer oder "
                "Microsoft Store pruefen"
            ) from exc

        duration_ms = int((time.monotonic() - start) * 1000)
        stdout = _truncate_output(completed.stdout or "")
        stderr = _truncate_output(completed.stderr or "")

        if completed.returncode == 0:
            log.info(
                "%s erfolgreich: id=%s duration=%dms",
                log_prefix,
                package_id,
                duration_ms,
            )
            return UpgradeResult(
                winget_id=package_id,
                status=UpgradeStatus.SUCCESS,
                exit_code=0,
                duration_ms=duration_ms,
                stdout=stdout,
                stderr=stderr,
            )

        log.warning(
            "%s fehlgeschlagen: id=%s exit=%d duration=%dms",
            log_prefix,
            package_id,
            completed.returncode,
            duration_ms,
        )
        return UpgradeResult(
            winget_id=package_id,
            status=UpgradeStatus.FAILED,
            exit_code=completed.returncode,
            duration_ms=duration_ms,
            stdout=stdout,
            stderr=stderr,
            error=_format_exit_code_error(completed.returncode),
        )

    @staticmethod
    def _build_command(
        winget_id: str,
        *,
        silent: bool,
        strategy: PatchStrategy = DEFAULT_PATCH_STRATEGY,
    ) -> list[str]:
        """Baut die Subprocess-Command-Liste.

        Keine Shell-Interpolation, alle Argumente einzeln gepackt.

        Args:
            winget_id: Bereits via:func:`_validate_winget_id` geprueft.
            silent: ``--silent``-Flag setzen.
            strategy: Patch-Strategie. Bei
:attr:`~core.patch_strategy.PatchStrategy.LATEST` werden
                ``--include-unknown`` (Apps mit unbekannter installierter
                Version) und ``--include-pinned`` (in winget gepinnte Apps)
                ergaenzt, damit auch diese auf die neueste Version gehen.
:attr:`~core.patch_strategy.PatchStrategy.STABLE` nutzt den
                Standard-Command ohne Zusatz-Flags.

        Returns:
            Argv-Liste fuer:func:`subprocess.run`.
        """
        cmd = [
            "winget",
            "upgrade",
            "--id",
            winget_id,
            "--exact",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ]
        if strategy is PatchStrategy.LATEST:
            cmd.append("--include-unknown")
            cmd.append("--include-pinned")
        if silent:
            cmd.append("--silent")
        return cmd

    @staticmethod
    def _build_msstore_command(store_id: str, *, silent: bool) -> list[str]:
        """Baut den Subprocess-Command fuer Microsoft-Store-Upgrades.

        Unterschied zu:meth:`_build_command`:
            * ``--source msstore`` erzwingt den Store-Catalog (sonst
              wuerde winget den Default-Catalog suchen und nichts finden).
            * **kein** ``--exact`` — Store-Ids sind ohnehin eindeutig und
              ``--exact`` verlangt einen Catalog-Style-Match (Punkt-
              Notation), den Store-Ids nicht haben.
            * ``--accept-source-agreements`` weiter notwendig (User darf
              fuer den msstore-Source nicht jedes Mal bestaetigen).
        """
        cmd = [
            "winget",
            "upgrade",
            "--id",
            store_id,
            "--source",
            "msstore",
            "--accept-source-agreements",
            "--accept-package-agreements",
        ]
        if silent:
            cmd.append("--silent")
        return cmd


__all__ = [
    "DEFAULT_UPGRADE_TIMEOUT_S",
    "UpgradeRequest",
    "UpgradeResult",
    "UpgradeStatus",
    "WingetUpgradeExecutor",
]
