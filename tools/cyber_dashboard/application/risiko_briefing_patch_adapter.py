"""Adapter: Patch-Monitor-Treffer -> AffectedCveItem /, Phase 3).

Implementiert den ``AffectedCveQuelle``-Port des
:class:`~tools.cyber_dashboard.application.risiko_briefing_service.RisikoBriefingService`
auf Basis der Patch-Monitor-Daten. Aggregiert die pro (App, CVE)-Paar gelieferten
``AffectedCveRow``-Zeilen zu **einem**:class:`AffectedCveItem` je CVE-ID (mit der
Liste der betroffenen Apps) und markiert sie als Konfidenz ``BESTAETIGT``
(CPE-genau, echtes winget-Inventar).

Die Quelle wird **duck-typed** uebergeben (jedes Objekt mit
``lade_betroffene_cves`` + ``anzahl_apps_ohne_cpe`` — i. d. R. der
``PatchInventoryService``). So braucht ``cyber_dashboard`` keinen statischen
``patch_monitor``-Import; die konkrete Verdrahtung passiert im Composition-Root
``tool.py`` Entscheidung 6).
"""

from __future__ import annotations

from typing import Protocol

from tools.cyber_dashboard.domain.risiko_briefing import AffectedCveItem, Konfidenz


class _AffectedRow(Protocol):
    cve_id: str
    cvss_score: float | None
    exploit_available: bool
    eol: bool
    app_name: str
    is_update_available: bool


class _AffectedCveSource(Protocol):
    def lade_betroffene_cves(
        self, *, min_cvss: float = 0.0, limit: int = 200
    ) -> list[_AffectedRow]: ...

    def anzahl_apps_ohne_cpe(self) -> int: ...


class PatchAffectedCveQuelle:
    """``AffectedCveQuelle``-Implementierung auf Basis des Patch-Monitors."""

    #: Zeilen-Budget pro CVE-Anfrage (mehrere Apps pro CVE -> mehr Zeilen
    #: als distinkte CVEs). Wird am ``limit`` der distinkten CVEs gekappt.
    _ROW_BUDGET: int = 400

    def __init__(self, source: _AffectedCveSource) -> None:
        self._source = source

    def lade_betroffene_cves(
        self, *, min_cvss: float = 0.0, limit: int = 50
    ) -> list[AffectedCveItem]:
        """Liefert bis zu ``limit`` distinkte betroffene CVEs (cvss-absteigend).

        Die Patch-Monitor-Zeilen sind bereits nach ``cvss_score DESC,
        exploit_available DESC`` sortiert; die erste Begegnung pro CVE-ID
        bestimmt damit die Reihenfolge.
        """
        rows = self._source.lade_betroffene_cves(
            min_cvss=min_cvss, limit=self._ROW_BUDGET
        )
        reihenfolge: list[str] = []
        apps_je_cve: dict[str, list[str]] = {}
        update_je_cve: dict[str, bool] = {}
        basis: dict[str, _AffectedRow] = {}
        for row in rows:
            cid = row.cve_id
            if cid not in basis:
                if len(reihenfolge) >= limit:
                    continue  # CVE-Budget erschoepft — weitere CVE-IDs ignorieren
                reihenfolge.append(cid)
                basis[cid] = row
                apps_je_cve[cid] = []
                update_je_cve[cid] = False
            if row.app_name and row.app_name not in apps_je_cve[cid]:
                apps_je_cve[cid].append(row.app_name)
            update_je_cve[cid] = update_je_cve[cid] or bool(row.is_update_available)

        return [
            AffectedCveItem(
                cve_id=cid,
                cvss_score=basis[cid].cvss_score,
                exploit_available=bool(basis[cid].exploit_available),
                eol=bool(basis[cid].eol),
                konfidenz=Konfidenz.BESTAETIGT,
                affected_apps=tuple(apps_je_cve[cid]),
                update_available=update_je_cve[cid],
            )
            for cid in reihenfolge
        ]

    def anzahl_apps_ohne_cpe(self) -> int:
        return self._source.anzahl_apps_ohne_cpe()
