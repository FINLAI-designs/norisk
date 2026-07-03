"""network_monitor.data.blocklist_loader — Parst die lokale blocklist.txt + whitelist.txt.

Format::

    # Kommentar
    1.2.3.4 # Optional: Grund nach Hash
    10.0.0.0/8 # CIDR erlaubt
    2001:db8::/32 # IPv6-CIDR erlaubt

Leer- und Kommentarzeilen werden ignoriert. Nicht-parsebare Zeilen werden
geloggt, brechen aber den Ladevorgang nicht ab (resilient gegen kaputte
Einträge).

Die ``whitelist.txt`` F-D) nutzt dasselbe Format; ihre Netze heben einen
Blocklist-/Feed-Treffer wieder auf (manueller Override gegen False-Positives).

Die Whitelist ist **nutzer-editierbar** F-D-GUI) und liegt daher im
schreibbaren Profil-Ordner ``~/.finlai/network_monitor/whitelist.txt``
(:func:`user_whitelist_path`) — der im signierten Frozen-Build read-only
Tool-Ordner taugt nicht zum Schreiben. Existiert noch keine nutzer-eigene
Datei, liest:func:`load_whitelist` die mitgelieferte Seed-Datei
(:func:`_seed_whitelist_path`) als Vorlage.:func:`save_whitelist` schreibt
immer ins Profil (atomar).

Author: Patrick Riederich
Version: 1.2 F-D-GUI — nutzer-editierbare Whitelist im Profil + Writer)
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

from core.finlai_paths import finlai_dir
from core.logger import get_logger
from tools.network_monitor.domain.models import Network

_log = get_logger(__name__)

_DEFAULT_REASON = "In lokaler Blocklist"

#: Header der nutzer-editierbaren Whitelist-Datei (eine Regel pro Zeile darunter).
_WHITELIST_HEADER = (
    "# Netzwerkmonitor — Manuelle Whitelist (Override, T-340 F-D)\n"
    "# Netze hier heben einen Blocklist-/Feed-Treffer wieder auf "
    "(gegen False-Positives).\n"
    "# Verwaltet über NoRisk Pro › Netzwerkmonitor › Bedrohungslisten.\n"
    "# Eine Regel pro Zeile. IPv4/IPv6 plain oder CIDR.\n"
)


def _default_blocklist_path() -> Path:
    """Pfad zu ``data/blocklist.txt`` im Tool-Ordner (Dev- und Frozen-Mode)."""
    return Path(__file__).parent / "blocklist.txt"


def _seed_whitelist_path() -> Path:
    """Mitgelieferte Whitelist-Vorlage im Tool-Ordner (read-only im Frozen-Build)."""
    return Path(__file__).parent / "whitelist.txt"


def user_whitelist_path() -> Path:
    """Pfad zur nutzer-editierbaren Whitelist im schreibbaren Profil-Ordner.

    ``~/.finlai/network_monitor/whitelist.txt`` (FINLAI_HOME-/Override-aware über
:func:`core.finlai_paths.finlai_dir`). Legt das Verzeichnis NICHT an — das
    macht:func:`save_whitelist` beim Schreiben.

    Returns:
        Profil-Pfad der nutzer-eigenen Whitelist.
    """
    return finlai_dir() / "network_monitor" / "whitelist.txt"


def _default_whitelist_path() -> Path:
    """Default-Whitelist-Pfad: die nutzer-editierbare Profil-Datei."""
    return user_whitelist_path()


def load_blocklist(
    path: Path | None = None,
) -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    """Lädt und parst die Blocklist-Datei.

    Args:
        path: Optionaler Pfad. Wenn ``None``, wird die tool-interne
            ``data/blocklist.txt`` verwendet.

    Returns:
        Liste aus (Netzwerk, Grund)-Tupeln. Plain IPs werden als ``/32``
        (IPv4) bzw. ``/128`` (IPv6) interpretiert. Bei fehlender Datei
        oder Lesefehler wird eine leere Liste zurückgegeben.
    """
    target = path or _default_blocklist_path()
    if not target.exists():
        _log.debug("Blocklist-Datei nicht gefunden: %s", target)
        return []

    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        _log.warning("Blocklist-Datei konnte nicht gelesen werden: %s", exc)
        return []

    entries: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        parsed = _parse_line(line, lineno)
        if parsed is not None:
            entries.append(parsed)
    return entries


def load_whitelist(path: Path | None = None) -> list[Network]:
    """Lädt die manuelle Whitelist (Override gegen Blocklist-/Feed-Treffer).

    Whitelist-Netze heben im:class:`ThreatChecker` einen Match wieder auf — so
    kann der Nutzer eigene/falsch-positive Bereiche dauerhaft entschärfen, ohne
    den (ggf. automatisch befüllten) Feed-Cache anzufassen.

    Args:
        path: Optionaler Pfad. ``None`` nutzt die nutzer-editierbare Profil-Datei
            (:func:`user_whitelist_path`); existiert diese noch nicht, wird die
            mitgelieferte Seed-Vorlage gelesen. Ein **expliziter** Pfad wird
            ohne Seed-Fallback genau so geladen (Tests).

    Returns:
        Liste der geparsten Netze (ohne Grund). Fehlende Datei / Lesefehler /
        nicht-parsebare Zeilen ergeben (Teil-)Leere — nie eine Exception.
    """
    target = path or _default_whitelist_path()
    if path is None and not target.exists():
        # Frische Installation: noch keine Profil-Datei → Seed-Vorlage lesen.
        target = _seed_whitelist_path()
    if not target.exists():
        _log.debug("Whitelist-Datei nicht gefunden: %s", target)
        return []

    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        _log.warning("Whitelist-Datei konnte nicht gelesen werden: %s", exc)
        return []

    networks: list[Network] = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        parsed = _parse_line(line, lineno)
        if parsed is not None:
            networks.append(parsed[0])
    return networks


def save_whitelist(networks: list[Network], path: Path | None = None) -> Path:
    """Schreibt die Whitelist atomar in die Profil-Datei (nutzer-editierbar).

    Schreibt einen Kommentar-Header gefolgt von einer Netz-Regel je Zeile (in der
    kanonischen ``str(network)``-Form, z. B. ``10.0.0.0/8``). Das Verzeichnis wird
    bei Bedarf angelegt; geschrieben wird über eine ``.tmp``-Datei + ``replace``,
    damit ein abgebrochener Schreibvorgang die Bestandsdatei nie halb überschreibt.

    Args:
        networks: Zu speichernde Netze (Reihenfolge bleibt erhalten).
        path: Optionaler Zielpfad. ``None`` nutzt:func:`user_whitelist_path`.

    Returns:
        Den tatsächlich geschriebenen Pfad.

    Raises:
        OSError: Wenn das Verzeichnis nicht angelegt oder nicht geschrieben
            werden kann (vom Aufrufer in der GUI-Schicht behandelt).
    """
    target = path or user_whitelist_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{network}\n" for network in networks)
    text = _WHITELIST_HEADER + body
    tmp = target.with_name(target.name + ".tmp")
    # In die.tmp schreiben + auf Platte zwingen (fsync) BEVOR atomar ersetzt wird:
    # ohne flush+fsync könnte ein Crash zwischen write und replace eine verkürzte
    # Datei hinterlassen-Härtung).
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(target)
    _log.info("Whitelist gespeichert: %d Netze → %s", len(networks), target)
    return target


def parse_network_token(token: str, *, strict: bool = False) -> Network | None:
    """Parst ein **einzelnes** Token streng als IP-Netz (sonst ``None``).

    Gemeinsamer Low-Level-Parser für Blocklist UND Threat-Feeds F-D,
    DRY): toleriert plain IPv4/IPv6, CIDR, ``IPv4:Port`` und bracket-Notation
    ``[IPv6]:Port``. Strikt über:mod:`ipaddress` — alles, was nicht eindeutig
    als Netz parst, ergibt ``None`` (kein fail-open).

    Args:
        token: Bereits von Whitespace/Quotes befreites Einzel-Token.
        strict: Wird an:func:`ipaddress.ip_network` durchgereicht. Default
            ``False`` (tolerant — gesetzte Host-Bits werden zum Netz erweitert,
            z. B. ``1.2.3.4/24`` → ``1.2.3.0/24``; passend für maschinell
            erzeugte Feeds/Blocklist). ``True`` lehnt gesetzte Host-Bits ab
            (``None``) — für nutzer-eingegebene Tokens, damit eine versehentliche
            stille Bereichs-Verbreiterung auffällt, Whitelist-Add).

    Returns:
        Das geparste Netz oder ``None``.
    """
    if not token:
        return None

    # [IPv6]:Port → Inhalt der Klammern
    if token.startswith("["):
        end = token.find("]")
        if end > 1:
            token = token[1:end]
    # IPv4:Port (genau ein ':' und der Host-Teil parst als IPv4) → Port abtrennen.
    # IPv6 (mehrere ':') und CIDR (kein ':') bleiben unangetastet.
    elif token.count(":") == 1:
        host = token.rsplit(":", 1)[0]
        try:
            ipaddress.IPv4Address(host)
            token = host
        except ValueError:
            pass

    try:
        return ipaddress.ip_network(token, strict=strict)
    except ValueError:
        return None


def _parse_line(
    line: str, lineno: int
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str] | None:
    """Parst eine einzelne Blocklist-Zeile.

    Args:
        line: Rohzeile (inkl. möglicher Whitespace/Kommentare).
        lineno: Zeilennummer für Log-Ausgaben.

    Returns:
        (Netzwerk, Grund) oder ``None`` bei Leer-/Kommentar-/Fehlerzeile.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # Optionalen Inline-Kommentar abtrennen
    reason = _DEFAULT_REASON
    if "#" in stripped:
        spec, _, comment = stripped.partition("#")
        spec = spec.strip()
        trimmed_comment = comment.strip()
        if trimmed_comment:
            reason = trimmed_comment
    else:
        spec = stripped

    if not spec:
        return None

    network = parse_network_token(spec)
    if network is None:
        _log.warning("Blocklist Zeile %d ungültig: %s", lineno, spec)
        return None

    return (network, reason)
