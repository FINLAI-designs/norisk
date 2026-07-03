"""
techstack_sync_service — Tech-Stack aus System-Scan + Patch-Monitor ableiten.

Cross-Tool-Brücke: liest installierte Software aus dem
``system_scanner`` (``InstalledSoftware``) und das Patch-Inventar aus dem
``patch_monitor`` (``InventoryEntry`` inkl. ``cpe_string``), führt beide
Quellen zu deduplizierten:class:`TechStackKandidat`-Vorschlägen zusammen
und übernimmt dabei die CPE-Strings. Zusätzlich löst er für die CPEs des
Tech-Stacks die im Patch-Monitor bereits **lokal gematchten** CVEs auf
(``cve_matches``) und adaptiert sie auf das cyber_dashboard-eigene
:class:`CveEintrag` — so liefert die Stack-CVE-Suche Treffer auch ohne
NVD-API-Key.

Architektur: Der Service kennt nur die zwei **Quellen** (kein Wissen über
den Bestands-Stack — das orchestriert der ``DashboardService``). Cross-Tool-
Zugriff folgt dem etablierten Muster aus
``tools/supply_chain_monitor/application/patch_monitor_linker.py``: lazy
Import + Duck-Typing + defensives ``except`` (fremde DB darf uns nie crashen).

Schichtzugehörigkeit: application/ — orchestriert, importiert kein gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.logger import get_logger
from core.security.severity import from_cvss
from tools.cyber_dashboard.domain.models import (
    CveEintrag,
    TechStackEintrag,
    TechStackKandidat,
)

log = get_logger(__name__)

# Anzeige-Labels der Sync-Quellen (Regel 1 — keine Magic-Strings im Code).
QUELLE_SCAN = "System-Scan"
QUELLE_PATCH = "Patch-Monitor"

# Fallback-Datum für adaptierte CVEs, falls ein Patch-Monitor-Match wider
# Erwarten kein ``fetched_at`` liefert. ``CveEintrag`` verlangt ein
# ``datetime`` — der Wert ist in der Stack-Tabelle nicht sichtbar und dient
# nur als deterministischer Platzhalter (kein ``now`` → testbar).
_UNBEKANNT_DATUM = datetime(1970, 1, 1, tzinfo=UTC)

# Defensive Schranken gegen ein aufgeblähtes/manipuliertes Inventar: ein
# Linux-Host hat real schnell mehrere Tausend Pakete, und der Kuratierungs-
# Dialog baut ein Widget pro Kandidat → ohne Cap friert der GUI-Thread ein.
# Konsistent mit ``dashboard_service._MAX_STACK_NAMES``/``_MAX_STACK_NAME_LEN``.
_MAX_KANDIDATEN = 500
_MAX_FELD_LEN = 128
_MAX_CPE_LEN = 256


def _lazy_scan_repository() -> object | None:
    """Versucht das System-Scanner-Repo zu importieren — bei Fehler ``None``."""
    try:
        from tools.system_scanner.data.scanner_repository import (  # noqa: PLC0415
            ScanRepository,
        )

        return ScanRepository()
    except Exception as exc:  # noqa: BLE001 — ImportError + DB-Init-Fehler beide OK
        log.info(
            "TechStackSync: System-Scanner-Repo nicht verfügbar (%s) — "
            "Scan-Quelle bleibt leer.",
            type(exc).__name__,
        )
        return None


def _lazy_patch_repository() -> object | None:
    """Versucht das Patch-Monitor-Repo zu importieren — bei Fehler ``None``."""
    try:
        from tools.patch_monitor.data.patch_inventory_repository import (  # noqa: PLC0415
            PatchInventoryRepository,
        )

        return PatchInventoryRepository()
    except Exception as exc:  # noqa: BLE001 — ImportError + DB-Init-Fehler beide OK
        log.info(
            "TechStackSync: Patch-Monitor-Repo nicht verfügbar (%s) — "
            "Patch-Quelle + CPE bleiben leer.",
            type(exc).__name__,
        )
        return None


def _cve_match_zu_eintrag(match: object, produktname: str) -> CveEintrag:
    """Adaptiert eine Patch-Monitor-``CveMatchEntry`` auf einen ``CveEintrag``.

    Die zwei Tools nutzen unterschiedliche CVE-Modelle: der Patch-Monitor
    speichert nur das Nötigste (CPE/CVSS/Exploit/EOL/Zeitstempel), das
    cyber_dashboard-``CveEintrag`` erwartet zusätzlich Beschreibung,
    Schweregrad-Label und NVD-URL. Die fehlenden Felder werden abgeleitet
    bzw. mit klaren Defaults gefüllt.

    Args:
        match: Duck-typed ``CveMatchEntry`` (Attribute ``cve_id``,
            ``cvss_score``, ``exploit_available``, ``fetched_at``).
        produktname: Anzeigename des Tech-Stack-Eintrags, dem die CVE
            zugeordnet ist (für ``betroffene_produkte`` + Beschreibung).

    Returns:
        Ein ``CveEintrag`` mit Schweregrad aus dem CVSS-Band und NVD-URL.
    """
    cve_id = str(getattr(match, "cve_id", "") or "")
    roh_score = getattr(match, "cvss_score", None)
    cvss = float(roh_score) if roh_score is not None else 0.0
    fetched = getattr(match, "fetched_at", None)
    if not isinstance(fetched, datetime):
        fetched = _UNBEKANNT_DATUM

    exploit = bool(getattr(match, "exploit_available", False))
    beschreibung = f"Aus dem Patch-Monitor erkannt (Produkt: {produktname})."
    if exploit:
        beschreibung = f"[Exploit verfügbar] {beschreibung}"

    return CveEintrag(
        cve_id=cve_id,
        beschreibung=beschreibung,
        # ``Severity.name`` ist das Uppercase-Label, das ``CveEintrag`` und
        # die Severity-Farben der GUI erwarten (z.B. "HIGH").
        schweregrad=from_cvss(roh_score).name,
        cvss_score=cvss,
        veroeffentlicht=fetched,
        geaendert=fetched,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        patch_verfuegbar=False,
        cisa_kev=False,
        betroffene_produkte=[produktname] if produktname else [],
    )


class TechStackSyncService:
    """Leitet Tech-Stack-Vorschläge aus System-Scan + Patch-Monitor ab.

    Args:
        scan_repo: System-Scanner-Repository (Duck-Typing: ``load_latest``).
            ``None`` → lazy-default; bleibt ``None`` wenn das Tool/die DB
            nicht verfügbar ist (Scan-Quelle dann leer).
        patch_repo: Patch-Monitor-Repository (Duck-Typing: ``list_inventory``,
            ``list_cve_matches_for_cpe``). ``None`` → lazy-default.
    """

    def __init__(
        self,
        scan_repo: object | None = None,
        patch_repo: object | None = None,
    ) -> None:
        self._scan_repo = scan_repo if scan_repo is not None else _lazy_scan_repository()
        self._patch_repo = (
            patch_repo if patch_repo is not None else _lazy_patch_repository()
        )

    # ------------------------------------------------------------------
    # Sync: Kandidaten ableiten
    # ------------------------------------------------------------------

    def ermittle_kandidaten(self) -> list[TechStackKandidat]:
        """Ermittelt deduplizierte Tech-Stack-Vorschläge aus beiden Quellen.

        Dedup-Schlüssel ist der normalisierte Produktname (lower/strip).
        Treffer in beiden Quellen werden zusammengeführt: die Version aus
        dem Patch-Monitor (``installed_version``) hat Vorrang, der CPE-String
        wird aus dem Patch-Monitor übernommen, die Quellen-Labels werden
        gesammelt.

        Returns:
            Nach Name sortierte Liste von:class:`TechStackKandidat`. Leer
            wenn keine Scan-/Inventardaten vorliegen.
        """
        akku: dict[str, dict[str, object]] = {}

        for sw in self._read_scan_software():
            self._akkumuliere(
                akku,
                name=str(getattr(sw, "name", "") or ""),
                version=str(getattr(sw, "version", "") or ""),
                cpe="",
                quelle=QUELLE_SCAN,
            )

        for inv in self._read_inventory():
            self._akkumuliere(
                akku,
                name=str(getattr(inv, "name", "") or ""),
                version=str(getattr(inv, "installed_version", "") or ""),
                cpe=str(getattr(inv, "cpe_string", "") or ""),
                quelle=QUELLE_PATCH,
            )

        kandidaten: list[TechStackKandidat] = []
        for key in sorted(akku):
            e = akku[key]
            eintrag = TechStackEintrag(
                name=str(e["name"]),
                version=str(e["version"]),
                kategorie="",
                aktiv=True,
                cpe=str(e["cpe"]),
            )
            quellen = tuple(e["quellen"])  # type: ignore[arg-type]
            kandidaten.append(TechStackKandidat(eintrag=eintrag, quellen=quellen))

        if len(kandidaten) > _MAX_KANDIDATEN:
            log.warning(
                "TechStackSync: %d Kandidaten gefunden, auf %d gekürzt "
                "(Anzeige-/Performance-Schutz).",
                len(kandidaten),
                _MAX_KANDIDATEN,
            )
            kandidaten = kandidaten[:_MAX_KANDIDATEN]
        return kandidaten

    @staticmethod
    def _akkumuliere(
        akku: dict[str, dict[str, object]],
        *,
        name: str,
        version: str,
        cpe: str,
        quelle: str,
    ) -> None:
        """Führt einen Quell-Treffer in den Dedup-Akkumulator ein.

        Version: Patch-Monitor-Wert hat Vorrang, sonst wird ein leeres Feld
        gefüllt. CPE: wird gesetzt, sobald eine Quelle einen liefert.
        """
        name = name.strip()[:_MAX_FELD_LEN]
        key = name.lower()
        if not key:
            return
        version = version.strip()[:_MAX_FELD_LEN]
        cpe = cpe.strip()[:_MAX_CPE_LEN]
        if key not in akku:
            akku[key] = {
                "name": name,
                "version": version,
                "cpe": cpe,
                "quellen": [quelle],
            }
            return

        eintrag = akku[key]
        quellen: list[str] = eintrag["quellen"]  # type: ignore[assignment]
        if quelle not in quellen:
            quellen.append(quelle)
        # Patch-Monitor-Version überschreibt; Scan füllt nur ein leeres Feld.
        if version and (quelle == QUELLE_PATCH or not eintrag["version"]):
            eintrag["version"] = version
        if cpe and not eintrag["cpe"]:
            eintrag["cpe"] = cpe

    # ------------------------------------------------------------------
    # CPE → CVE (lokale Patch-Monitor-Treffer)
    # ------------------------------------------------------------------

    def cves_fuer_cpes(
        self, cpe_namen: list[tuple[str, str]]
    ) -> list[CveEintrag]:
        """Löst CVEs für die gegebenen CPEs aus dem Patch-Monitor auf.

        Liest die im Patch-Monitor bereits persistierten ``cve_matches``
        (kein Netzwerk, kein NVD-API-Key nötig) und adaptiert sie auf
        ``CveEintrag``. Dedupliziert über die CVE-ID (erster Treffer gewinnt).

        Args:
            cpe_namen: Liste von ``(cpe_string, produktname)``-Tupeln der
                aktiven Tech-Stack-Einträge mit CPE.

        Returns:
            Adaptierte, deduplizierte CVE-Einträge. Leer wenn kein
            Patch-Monitor-Repo verfügbar ist.
        """
        if self._patch_repo is None:
            return []
        get_cves = getattr(self._patch_repo, "list_cve_matches_for_cpe", None)
        if not callable(get_cves):
            return []

        eintraege: list[CveEintrag] = []
        gesehen: set[str] = set()
        for cpe, produktname in cpe_namen:
            if not cpe:
                continue
            try:
                matches = list(get_cves(cpe))
            except Exception as exc:  # noqa: BLE001 — Patch-DB darf uns nicht crashen
                log.warning(
                    "TechStackSync: list_cve_matches_for_cpe(%r) fehlgeschlagen: %s",
                    cpe,
                    type(exc).__name__,
                )
                continue
            for m in matches:
                cve_id = str(getattr(m, "cve_id", "") or "")
                if not cve_id or cve_id in gesehen:
                    continue
                try:
                    eintrag = _cve_match_zu_eintrag(m, produktname)
                except (ValueError, TypeError) as exc:
                    # Ein einzelner korrupter Match (z.B. nicht-float cvss_score)
                    # darf nicht die gesamte CPE-Auflösung killen.
                    log.warning(
                        "TechStackSync: CVE-Match %s nicht adaptierbar: %s",
                        cve_id,
                        type(exc).__name__,
                    )
                    continue
                gesehen.add(cve_id)
                eintraege.append(eintrag)
        return eintraege

    # ------------------------------------------------------------------
    # Defensive Quell-Reads (Duck-Typing wie patch_monitor_linker)
    # ------------------------------------------------------------------

    def _read_scan_software(self) -> list:
        """Liefert ``InstalledSoftware`` des letzten Scans oder leere Liste."""
        if self._scan_repo is None:
            return []
        load_latest = getattr(self._scan_repo, "load_latest", None)
        if not callable(load_latest):
            return []
        try:
            result = load_latest()
        except Exception as exc:  # noqa: BLE001 — Scanner-DB darf uns nicht crashen
            log.warning(
                "TechStackSync: load_latest fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return []
        if result is None:
            return []
        software = getattr(result, "software_list", None)
        return list(software) if software else []

    def _read_inventory(self) -> list:
        """Liefert alle ``InventoryEntry``-Objekte oder leere Liste."""
        if self._patch_repo is None:
            return []
        list_inventory = getattr(self._patch_repo, "list_inventory", None)
        if not callable(list_inventory):
            return []
        try:
            return list(list_inventory())
        except Exception as exc:  # noqa: BLE001 — Patch-DB darf uns nicht crashen
            log.warning(
                "TechStackSync: list_inventory fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return []
