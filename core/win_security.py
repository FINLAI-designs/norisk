"""core.win_security — Windows-Härtung für den elevated Collector F-C-3).

Zwei Schutzmechanismen gegen Privilege-Escalation auf die **elevated** Collector-
Aufgabe (``TASK_RUNLEVEL_HIGHEST``), zusammengefasst als „Security-Gate":

- **E1 — DLL-Suchpfad-Härtung** (:func:`harden_dll_search_path`): entfernt das
  aktuelle Arbeitsverzeichnis und die ``PATH``-Verzeichnisse aus der impliziten
  DLL-Suche (``SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)``),
  damit eine in CWD/PATH platzierte Schad-DLL nicht beim Lazy-Import von
  ``psutil``/``pywintrace``/``win32com`` in den elevated Prozess geladen wird.
- **E2 — Pfad-Vertrauensprüfung** (:func:`assess_install_path_trust`): lehnt es ab,
  ein Collector-Ziel in einem **durch Nicht-Admins beschreibbaren** Pfad in eine
  HIGHEST-Aufgabe einzubrennen (sonst könnte ein unprivilegierter Angreifer die
  Exe/das Skript ersetzen → Code-Ausführung als elevated bei nächstem Logon).
  Defense-in-depth: erst ein billiger Prefix-Vorfilter (nur unter ``%ProgramFiles%``
  & Co. erlaubt), dann die **autoritative** DACL-/Owner-Inspektion der Datei UND
  **jedes Zwischenverzeichnisses** der Kette bis (exklusive) zur geschützten
  System-Wurzel — die Wurzel selbst gilt per Allowlist als OS-geschützt. Die
  Ancestor-Prüfung schließt die *Writable-Ancestor*-Lücke: ein benutzer-
  beschreibbares Zwischenverzeichnis (z. B. ein nicht-elevated unter
  ``%ProgramFiles%`` angelegter Ordner mit CREATOR-OWNER-Rechten) ließe einen
  Angreifer eine Zwischenebene umbenennen/ersetzen und so die elevated Exe kapern.

Restrisiko (Snapshot): die Prüfung ist eine **einmalige Install-Zeit-Momentaufnahme**.
Dauerhafte Sicherheit setzt voraus, dass die ACLs des aufgelösten Ziels und seiner
Vorfahren über die Lebenszeit der Aufgabe admin-only bleiben (eine nachträgliche
ACL-Lockerung durch einen Admin kann der Gate nicht verhindern). Der Scheduler
re-resolved den eingebrannten Pfad bei jedem Logon — da die Ancestor-Prüfung jedes
Verzeichnis der Kette als admin-only verifiziert, kann ein Nicht-Admin keine
Junction/Umleitung in der Kette platzieren (TOCTOU-Fenster geschlossen für den
unterstützten Install-Pfad; siehe F-C-2 Teil 2 für den Frozen-Build-Smoke).

Architektur-Hinweis: Die *reine Entscheidungslogik* (:func:`evaluate_path_trust`)
ist von der *win32-Extraktion* (:func:`_read_path_security`, nur Windows, lazy
pywin32-Import) getrennt — so ist die Trust-Logik mit synthetischen ACE-Listen
plattformunabhängig unit-testbar (Linux-CI ohne pywin32).

Alle Funktionen sind **fail-closed**: ist der Trust nicht positiv feststellbar
(ACL unlesbar, pywin32 fehlt, NULL-DACL), gilt der Pfad als nicht vertrauenswürdig.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from core.logger import get_logger

log = get_logger(__name__)

# ── E1: DLL-Suchpfad-Härtung ────────────────────────────────────────────────
#: Flag für ``SetDefaultDllDirectories``: implizite Suche auf System32, das
#: Anwendungsverzeichnis und explizit via ``AddDllDirectory``/``os.add_dll_directory``
#: hinzugefügte Verzeichnisse beschränken — CWD und ``PATH`` fliegen raus.
_LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000

# ── E2: Trust-Inspektion — Well-Known-SIDs ──────────────────────────────────
_SID_SYSTEM = "S-1-5-18"
_SID_ADMINISTRATORS = "S-1-5-32-544"
#: TrustedInstaller (Besitzer vieler System-/Program-Files-Objekte unter Win10/11).
_SID_TRUSTED_INSTALLER = (
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)
#: CREATOR OWNER — in einer (vererbten) ACE steht das stellvertretend für den
#: tatsächlichen Objekt-Besitzer; Trust hängt damit am aufgelösten Owner.
_SID_CREATOR_OWNER = "S-1-3-0"

#: Prinzipale, deren Schreibrecht KEIN EoP ist (admin-darf-admin-Sachen-ändern).
_TRUSTED_SIDS = frozenset(
    {_SID_SYSTEM, _SID_ADMINISTRATORS, _SID_TRUSTED_INSTALLER}
)

# Datei-/Verzeichnis-Zugriffsbits, die ein Ersetzen der Exe bzw. ein DLL-Platzieren
# im Verzeichnis erlauben (= manipulationsfähig). FILE_WRITE_ATTRIBUTES (0x100)
# ist bewusst NICHT enthalten — es erlaubt kein Ersetzen/Platzieren von Code und
# würde Standard-ACLs (Users) falsch-positiv ablehnen.
_FILE_WRITE_DATA = 0x0002  # = FILE_ADD_FILE (Datei im Verzeichnis anlegen)
_FILE_APPEND_DATA = 0x0004  # = FILE_ADD_SUBDIRECTORY
_FILE_WRITE_EA = 0x0010
_FILE_DELETE_CHILD = 0x0040
_DELETE = 0x00010000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_WRITE = 0x40000000
_GENERIC_ALL = 0x10000000
_TAMPER_MASK = (
    _FILE_WRITE_DATA
    | _FILE_APPEND_DATA
    | _FILE_WRITE_EA
    | _FILE_DELETE_CHILD
    | _DELETE
    | _WRITE_DAC
    | _WRITE_OWNER
    | _GENERIC_WRITE
    | _GENERIC_ALL
)

#: ACE-Typ „Zugriff erlauben" (``ACCESS_ALLOWED_ACE_TYPE``). DENY-ACEs werden
#: bewusst ignoriert: für die fail-closed-Über-Approximation zählt allein, ob ein
#: nicht vertrauenswürdiger Prinzipal ein ALLOW-Schreibrecht hat.
_ACCESS_ALLOWED_ACE_TYPE = 0


def harden_dll_search_path() -> bool:
    """Härtet die DLL-Suchreihenfolge des Prozesses (CWD/PATH entfernen).

    Ruft ``SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)``, sodass
    implizit geladene Abhängigkeits-DLLs nur noch aus System32, dem
    Anwendungsverzeichnis und explizit hinzugefügten Verzeichnissen kommen — nicht
    mehr aus dem (angreifbaren) Arbeitsverzeichnis oder ``PATH``. Muss **vor** dem
    ersten DLL-ladenden Import laufen (im Collector: vor den Lazy-Imports von
    ``psutil``/``pywintrace``/``win32com`` in ``run_collector``).

    Im gepackten Modus (PyInstaller, ``sys.frozen``) werden danach die gebündelten
    DLL-Verzeichnisse (``sys._MEIPASS`` + Exe-Ordner) wieder explizit via
    ``os.add_dll_directory`` aufgenommen, damit die nun restriktive Suche die
    mitgelieferten DLLs weiterhin findet.

    Best-effort: schlägt der WinAPI-Aufruf fehl oder ist die Plattform kein
    Windows, wird das geloggt und ``False`` zurückgegeben (die Härtung ist
    Defense-in-depth — ein Abbruch des Collectors wäre schädlicher als der Lauf
    ohne sie; das verbleibende Restrisiko ist dokumentiert).

    Returns:
        True, wenn die Härtung angewendet wurde; False auf Nicht-Windows oder bei
        fehlgeschlagenem WinAPI-Aufruf.
    """
    if sys.platform != "win32":
        return False
    import ctypes  # noqa: PLC0415 — Windows-spezifisch, lazy für Nicht-Windows-Import

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        set_default_dll_dirs = kernel32.SetDefaultDllDirectories
        set_default_dll_dirs.restype = ctypes.c_bool
        set_default_dll_dirs.argtypes = (ctypes.c_uint32,)
        if not set_default_dll_dirs(_LOAD_LIBRARY_SEARCH_DEFAULT_DIRS):
            err = ctypes.get_last_error()
            log.warning(
                "DLL-Suchpfad-Härtung fehlgeschlagen (WinError %s) — Collector "
                "läuft ohne SetDefaultDllDirectories weiter.",
                err,
            )
            return False
    except (OSError, AttributeError) as exc:
        log.warning("DLL-Suchpfad-Härtung nicht anwendbar: %s", exc)
        return False

    if getattr(sys, "frozen", False):
        for dll_dir in _bundled_dll_dirs():
            try:
                os.add_dll_directory(dll_dir)
            except OSError as exc:
                log.warning("Gebündeltes DLL-Verzeichnis nicht aufnehmbar (%s): %s", dll_dir, exc)
    log.info("DLL-Suchpfad gehärtet (LOAD_LIBRARY_SEARCH_DEFAULT_DIRS).")
    return True


def _bundled_dll_dirs() -> list[str]:
    """Liefert die DLL-Verzeichnisse eines gepackten Builds (``_MEIPASS`` + Exe-Ordner)."""
    dirs: list[str] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(str(meipass))
    exe_dir = os.path.dirname(sys.executable)
    if exe_dir and exe_dir not in dirs:
        dirs.append(exe_dir)
    return dirs


# ── E2: Pfad-Vertrauensprüfung ──────────────────────────────────────────────
@dataclass(frozen=True)
class PathTrustVerdict:
    """Verdikt der Pfad-Vertrauensprüfung für einen Collector-Installationspfad.

    Attributes:
        trusted: True, wenn der Pfad nur von Administratoren/SYSTEM manipulierbar ist.
        reason: Menschenlesbare Begründung (deutsch, Sie-Form-tauglich für die GUI).
        checked_path: Der aufgelöste (realpath) Pfad, der geprüft wurde.
        untrusted_principals: SIDs der nicht vertrauenswürdigen Schreib-Prinzipale
            (leer bei trusted oder wenn die Ablehnung nicht ACE-basiert war).
    """

    trusted: bool
    reason: str
    checked_path: str
    untrusted_principals: tuple[str, ...] = field(default=())


def _trusted_roots() -> list[str]:
    """Liefert die geschützten System-Wurzeln (normcase) aus der Umgebung.

    ``%ProgramFiles%``, ``%ProgramW6432%`` (64-bit auch aus 32-bit-Prozess),
    ``%ProgramFiles(x86)%`` und ``%SystemRoot%``. Nicht gesetzte Variablen
    (z. B. auf Nicht-Windows) werden übersprungen → die Liste kann leer sein.
    """
    roots: list[str] = []
    for env_name in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "SystemRoot"):
        value = os.environ.get(env_name)
        if value:
            normalized = os.path.normcase(os.path.normpath(value))
            if normalized not in roots:
                roots.append(normalized)
    return roots


def _matched_trusted_root(resolved: Path) -> str | None:
    """Liefert die geschützte System-Wurzel, unter der ``resolved`` liegt, sonst ``None``.

    Vergleich case-insensitiv (Windows) und an Verzeichnisgrenzen — ``C:\\Program
    Files Evil`` zählt NICHT als unter ``C:\\Program Files``. Der zurückgegebene
    Wert ist die normalisierte Wurzel (Terminator für den Ancestor-Walk).
    """
    target = os.path.normcase(os.path.normpath(str(resolved)))
    for root in _trusted_roots():
        if target == root or target.startswith(root + os.sep):
            return root
    return None


def _is_under_trusted_root(resolved: Path) -> bool:
    """True, wenn ``resolved`` unter einer der geschützten System-Wurzeln liegt."""
    return _matched_trusted_root(resolved) is not None


def _ancestors_up_to_root(resolved: Path, root: str) -> list[Path]:
    """Verzeichniskette von ``resolved.parent`` aufwärts bis **(exklusive)** ``root``.

    Die geschützte System-Wurzel selbst (``%ProgramFiles%`` & Co.) wird NICHT
    inspiziert: sie gilt per Allowlist als OS-geschützt (Terminator). Das ist
    bewusst — eine DACL-Prüfung der Wurzel würde an gutartigen System-ACEs
    (z. B. vererbtes CREATOR OWNER) falsch-positiv ablehnen und so Nutzer in den
    Override drängen. Geprüft werden nur die (vom Installer angelegten)
    Zwischenverzeichnisse zwischen Datei und Wurzel.

    Args:
        resolved: Der aufgelöste Zielpfad (Datei).
        root: Die normalisierte geschützte System-Wurzel (Terminator, exklusive).

    Returns:
        Liste der zu prüfenden Zwischenverzeichnisse (Eltern-Verzeichnis zuerst,
        dann jede Ebene aufwärts bis unmittelbar unter die Wurzel).
    """
    root_norm = os.path.normcase(os.path.normpath(root))
    chain: list[Path] = []
    current = resolved.parent
    while os.path.normcase(os.path.normpath(str(current))) != root_norm:
        chain.append(current)
        parent = current.parent
        if parent == current:  # Dateisystem-Wurzel ohne Root-Treffer (Sicherheitsnetz)
            break
        current = parent
    return chain


def evaluate_path_trust(
    owner_sid: str, aces: Sequence[tuple[int, str, int]]
) -> tuple[bool, str, tuple[str, ...]]:
    """Entscheidet anhand Owner-SID + ACE-Liste, ob ein Pfad nur Admin-manipulierbar ist.

    Reine Entscheidungslogik (kein win32) — mit synthetischen ACEs unit-testbar.
    Konservativ/fail-closed: jedes ALLOW-Schreibrecht eines nicht vertrauenswürdigen
    Prinzipals macht den Pfad untrusted (DENY-ACEs werden als Über-Approximation
    ignoriert — sie können die Ablehnung nur strenger, nie lockerer machen).

    Args:
        owner_sid: SID-String des Objekt-Besitzers (besitzt implizit ``WRITE_DAC``,
            kann sich also selbst Schreibrechte geben → muss vertrauenswürdig sein).
        aces: Sequenz ``(ace_type, sid_string, access_mask)`` der DACL.

    Returns:
        ``(trusted, reason, untrusted_principals)``.
    """
    if owner_sid not in _TRUSTED_SIDS:
        return (
            False,
            f"Besitzer {owner_sid} ist nicht SYSTEM/Administrator — kann sich "
            "selbst Schreibrechte geben",
            (owner_sid,),
        )
    offenders: list[str] = []
    for ace_type, sid, mask in aces:
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            continue
        if not (mask & _TAMPER_MASK):
            continue
        # CREATOR OWNER erbt den (bereits als vertrauenswürdig bestätigten) Owner.
        effective_sid = owner_sid if sid == _SID_CREATOR_OWNER else sid
        if effective_sid not in _TRUSTED_SIDS:
            offenders.append(sid)
    if offenders:
        joined = ", ".join(offenders)
        return (
            False,
            f"Nicht vertrauenswürdige Prinzipale mit Schreibrecht: {joined}",
            tuple(offenders),
        )
    return (True, "Nur SYSTEM/Administratoren haben Schreibzugriff", ())


def _read_path_security(path: Path) -> tuple[str, list[tuple[int, str, int]] | None]:
    """Liest Owner-SID + DACL-ACEs eines Pfades via pywin32 (nur Windows).

    Args:
        path: Der zu prüfende Pfad (Datei oder Verzeichnis).

    Returns:
        ``(owner_sid_string, aces)``; ``aces`` ist ``None`` bei NULL-DACL
        (= jeder hat Vollzugriff → vom Aufrufer als untrusted zu werten).

    Raises:
        OSError: Wenn die Sicherheitsinformation nicht lesbar ist (Pfad fehlt,
            kein Zugriff). Vom Aufrufer fail-closed zu behandeln.
        ImportError: Wenn pywin32 nicht verfügbar ist.
    """
    import win32security  # noqa: PLC0415 — Windows-spezifisch, lazy

    info = (
        win32security.OWNER_SECURITY_INFORMATION
        | win32security.DACL_SECURITY_INFORMATION
    )
    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, info
    )
    owner_sid = win32security.ConvertSidToStringSid(
        descriptor.GetSecurityDescriptorOwner()
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        return owner_sid, None  # NULL-DACL = Vollzugriff für jeden
    aces: list[tuple[int, str, int]] = []
    for index in range(dacl.GetAceCount()):
        (ace_type, _flags), mask, sid = dacl.GetAce(index)
        aces.append((ace_type, win32security.ConvertSidToStringSid(sid), int(mask)))
    return owner_sid, aces


def _node_trust_verdict(target: Path, resolved: Path) -> PathTrustVerdict | None:
    """Prüft einen einzelnen Pfad-Knoten (Datei oder Verzeichnis) autoritativ.

    Args:
        target: Der konkrete zu prüfende Knoten (Datei oder Vorfahre-Verzeichnis).
        resolved: Der aufgelöste Gesamt-Zielpfad (für ``checked_path`` im Verdikt).

    Returns:
        ``None``, wenn der Knoten vertrauenswürdig ist; sonst ein untrusted
:class:`PathTrustVerdict` (fail-closed bei Lesefehler/NULL-DACL).
    """
    try:
        owner_sid, aces = _read_path_security(target)
    except Exception as exc:  # noqa: BLE001 — Boundary: jeder Lesefehler = fail-closed
        log.warning("ACL von %s nicht prüfbar (fail-closed): %s", target, exc)
        return PathTrustVerdict(
            trusted=False,
            reason=f"ACL von {target} nicht prüfbar: {exc}",
            checked_path=str(resolved),
        )
    if aces is None:
        return PathTrustVerdict(
            trusted=False,
            reason=f"{target}: NULL-DACL (jeder Benutzer hat Vollzugriff)",
            checked_path=str(resolved),
        )
    trusted, reason, offenders = evaluate_path_trust(owner_sid, aces)
    if not trusted:
        return PathTrustVerdict(
            trusted=False,
            reason=f"{target}: {reason}",
            checked_path=str(resolved),
            untrusted_principals=offenders,
        )
    return None


def assess_install_path_trust(path: str | Path) -> PathTrustVerdict:
    """Prüft, ob ein Collector-Installationspfad sicher in eine HIGHEST-Aufgabe gehört.

    Defense-in-depth (Patrick-Entscheid 2026-06-14, Q1 „Beides"):

    1. **Prefix-Vorfilter** — der aufgelöste (realpath) Pfad MUSS unter einer
       geschützten System-Wurzel liegen (``%ProgramFiles%`` & Co.). Verzeichnisse
       im Benutzerprofil/AppData/Temp werden sofort abgelehnt.
    2. **DACL-/Owner-Inspektion** — die Datei UND **jedes Zwischenverzeichnis** bis
       (exklusive) zur geschützten Wurzel werden autoritativ geprüft
       (:func:`evaluate_path_trust`): nur SYSTEM/Administratoren/TrustedInstaller
       dürfen Owner sein bzw. Schreibrechte haben. Die Ancestor-Prüfung schließt
       die Writable-Ancestor-Lücke (ein benutzer-beschreibbares Zwischen-
       verzeichnis wäre sonst ein voller EoP-Pivot).

    Fail-closed: ist die ACL nicht lesbar (pywin32 fehlt, Pfad weg, NULL-DACL),
    gilt der Pfad als nicht vertrauenswürdig.

    Args:
        path: Der zu prüfende Exe-/Skript-/Verzeichnis-Pfad.

    Returns:
        Das:class:`PathTrustVerdict`.
    """
    resolved = Path(os.path.realpath(str(path)))
    root = _matched_trusted_root(resolved)
    if root is None:
        return PathTrustVerdict(
            trusted=False,
            reason=(
                "Pfad liegt nicht unter einem geschützten System-Verzeichnis "
                "(z. B. %ProgramFiles%) — in einem benutzer-beschreibbaren Pfad "
                "könnte ein Angreifer die elevated Collector-Exe ersetzen"
            ),
            checked_path=str(resolved),
        )
    # Datei + jede Verzeichnisebene bis zur Wurzel: ein schreibbares (Zwischen-)
    # Verzeichnis erlaubt Ersetzen/Umbenennen/DLL-Platzieren, eine schreibbare
    # Datei das Überschreiben der Exe.
    for target in (resolved, *_ancestors_up_to_root(resolved, root)):
        verdict = _node_trust_verdict(target, resolved)
        if verdict is not None:
            return verdict
    return PathTrustVerdict(
        trusted=True,
        reason="Pfad und alle Vorfahren bis zur System-Wurzel sind nur Admin-/SYSTEM-beschreibbar",
        checked_path=str(resolved),
    )
