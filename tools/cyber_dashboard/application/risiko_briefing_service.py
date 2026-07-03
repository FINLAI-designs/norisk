"""RisikoBriefingService + RisikoPunkt-Engine /, Tab 1).

Fuehrt die Quellen Patch-Monitor (betroffene CVEs + Backlog), Security-Score
(Hardening, gemessen), Security-Audit (Selbsteinschaetzung + BSI-Risiken) und
gemessene Eckwerte zu einem:class:`RiskBriefingSnapshot` zusammen und leitet
daraus deterministisch die **wichtigen Punkte** mit ihrer **Folge bei
Nichtbeachtung** ab (Patrick-Leitsatz 2026-06-29).

Designprinzipien:
* **Fakten deterministisch, Erklaerung grounded.** Die Regeln unten waehlen
  Befunde rein aus den Daten; die Risiko-Texte sind Templates. Eine optionale
  LLM-Veredelung (umformulieren, nie erfinden) folgt in einer spaeteren Phase.
* **Kein Cross-Tool-Import.** Der Service kennt nur die eigenen Primitiv-DTOs
  (``domain/risiko_briefing``) und einen Port. Die Uebersetzung der Fremd-Typen
  (HardeningScoreResult, CustomerAuditResult, AffectedCveRow, AuditPrefill)
  passiert im Composition-Root ``tool.py`` Entscheidung 6).
* **SELF-Gate fail-closed.** Liefert ein Loader ``None`` (z. B. weil
  gerade ein CUSTOMER-Audit aktiv ist), fallen die zugehoerigen Punkte still
  weg — es fliessen NIE Fremd-Mandanten-Daten in das eigene Briefing.
* **Mess-Fehlschlag neutral.** ``bool | None``-Eckwerte loesen nur bei
  explizitem ``False`` einen Punkt aus; ``None`` (ungeprueft) bleibt neutral.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol

from tools.cyber_dashboard.domain.risiko_briefing import (
    AffectedCveItem,
    AuditScoreInfo,
    HardeningInfo,
    MeasuredFacts,
    PatchBacklogInfo,
    Prioritaet,
    RisikoPunkt,
    RiskBriefingSnapshot,
)

#: Ab diesem CVSS-Wert gilt ein bestaetigter CVE als hoch-relevant.
_HIGH_CVSS: float = 7.0
#: Risiko-Level-Labels, die einen organisatorischen Punkt ausloesen.
_KRITISCHE_RISIKO_LEVEL = frozenset({"hoch", "sehr hoch"})


class AffectedCveQuelle(Protocol):
    """Port: liefert die lokal betroffenen CVEs (Patch-Monitor-Adapter, Phase 3)."""

    def lade_betroffene_cves(
        self, *, min_cvss: float = 0.0, limit: int = 50
    ) -> Sequence[AffectedCveItem]: ...

    def anzahl_apps_ohne_cpe(self) -> int: ...


# Loader liefern ``None``, wenn die Daten fehlen oder (SELF-Gate) nicht
# freigegeben sind — der zugehoerige Punkt entfaellt dann still.
_PatchBacklogLoader = Callable[[], PatchBacklogInfo | None]
_HardeningLoader = Callable[[], HardeningInfo | None]
_AuditLoader = Callable[[], AuditScoreInfo | None]
_MeasuredLoader = Callable[[], MeasuredFacts | None]


# ---------------------------------------------------------------------------
# RisikoPunkt-Engine — eine Regel pro Befund-Typ, deterministisch
# ---------------------------------------------------------------------------


def _regel_aktiv_ausgenutzt(
    cves: Sequence[AffectedCveItem],
) -> RisikoPunkt | None:
    kev = [c for c in cves if c.exploit_available]
    if not kev:
        return None
    apps = tuple(dict.fromkeys(a for c in kev for a in c.affected_apps))
    return RisikoPunkt(
        titel="Aktiv ausgenutzte Schwachstelle betrifft Ihr System",
        kategorie="CVE",
        prioritaet=Prioritaet.KRITISCH,
        befund=(
            f"{len(kev)} Schwachstelle(n) auf installierter Software werden "
            "laut CISA bereits aktiv ausgenutzt."
        ),
        risiko_bei_nichtbeachtung=(
            "Angreifer nutzen diese Luecke nachweislich schon aus. Ohne sofortiges "
            "Update ist eine Kompromittierung unmittelbar moeglich; fuer aktiv "
            "ausgenutzte Schwachstellen gilt eine behoerdliche Behebungsfrist."
        ),
        empfohlene_massnahme=(
            "Betroffene Software umgehend patchen (Patch-Monitor) oder vom Netz nehmen."
        ),
        quelle="Patch-Monitor / CISA-KEV",
        evidenz=apps[:8] or tuple(c.cve_id for c in kev[:8]),
    )


def _regel_kritische_cves(
    cves: Sequence[AffectedCveItem],
) -> RisikoPunkt | None:
    # Hoch-relevante, bestaetigte CVEs OHNE KEV (KEV deckt _regel_aktiv_ausgenutzt).
    hoch = [
        c
        for c in cves
        if not c.exploit_available
        and c.cvss_score is not None
        and c.cvss_score >= _HIGH_CVSS
    ]
    if not hoch:
        return None
    mit_patch = sum(1 for c in hoch if c.update_available)
    apps = tuple(dict.fromkeys(a for c in hoch for a in c.affected_apps))
    return RisikoPunkt(
        titel="Schwerwiegende Schwachstellen auf installierter Software",
        kategorie="CVE",
        prioritaet=Prioritaet.HOCH,
        befund=(
            f"{len(hoch)} Schwachstelle(n) mit hohem Schweregrad (CVSS >= "
            f"{_HIGH_CVSS:.0f}) betreffen installierte Software; fuer {mit_patch} "
            "davon ist bereits ein Update verfuegbar."
        ),
        risiko_bei_nichtbeachtung=(
            "Schwerwiegende, oeffentlich bekannte Luecken laden zu gezielten "
            "Angriffen ein. Je laenger sie offen bleiben, desto wahrscheinlicher "
            "wird die Ausnutzung."
        ),
        empfohlene_massnahme="Verfuegbare Updates einspielen, fehlende Patches beobachten.",
        quelle="Patch-Monitor",
        evidenz=apps[:8],
    )


def _regel_eol(
    cves: Sequence[AffectedCveItem],
    patch_backlog: PatchBacklogInfo | None,
) -> RisikoPunkt | None:
    eol_apps = tuple(dict.fromkeys(a for c in cves if c.eol for a in c.affected_apps))
    anzahl = patch_backlog.eol_without_patch if patch_backlog else 0
    if not eol_apps and anzahl <= 0:
        return None
    # EINE Quelle waehlen (kein max ueber inkommensurable Zaehler): die
    # Patch-Monitor-Zahl (eol_no_patch-Recommendation) ist autoritativ; nur wenn
    # sie fehlt, auf die Zahl der CVE-EOL-markierten Apps zurueckfallen.
    anzahl_eol = anzahl if anzahl > 0 else len(eol_apps)
    return RisikoPunkt(
        titel="Software ohne Sicherheitsupdates (End-of-Life) im Einsatz",
        kategorie="Patch",
        prioritaet=Prioritaet.HOCH,
        befund=(
            f"{anzahl_eol} Produkt(e) haben das Support-Ende "
            "erreicht und erhalten keine Sicherheitsupdates mehr."
        ),
        risiko_bei_nichtbeachtung=(
            "Neu entdeckte Luecken in End-of-Life-Software werden vom Hersteller "
            "nicht mehr geschlossen — das System bleibt dauerhaft angreifbar."
        ),
        empfohlene_massnahme="Auf eine unterstuetzte Version/Alternative wechseln.",
        quelle="Patch-Monitor",
        evidenz=eol_apps[:8],
    )


def _regel_offene_updates(
    patch_backlog: PatchBacklogInfo | None,
) -> RisikoPunkt | None:
    if not patch_backlog or patch_backlog.open_updates <= 0:
        return None
    return RisikoPunkt(
        titel="Verfuegbare Updates noch nicht eingespielt",
        kategorie="Patch",
        prioritaet=Prioritaet.MITTEL,
        befund=f"{patch_backlog.open_updates} installierte Programme haben ein Update offen.",
        risiko_bei_nichtbeachtung=(
            "Updates schliessen meist bekannte Sicherheitsluecken. Offene Updates "
            "halten diese Luecken unnoetig lange angreifbar."
        ),
        empfohlene_massnahme="Updates ueber den Patch-Monitor einspielen.",
        quelle="Patch-Monitor",
    )


def _regel_festplattenverschluesselung(
    measured: MeasuredFacts | None,
) -> RisikoPunkt | None:
    if not measured or measured.disk_encryption_active is not False:
        return None
    return RisikoPunkt(
        titel="Festplattenverschluesselung nicht aktiv",
        kategorie="Haertung",
        prioritaet=Prioritaet.HOCH,
        befund="Die Datentraegerverschluesselung (z. B. BitLocker) ist nicht aktiv.",
        risiko_bei_nichtbeachtung=(
            "Bei Verlust oder Diebstahl des Geraets sind alle Daten im Klartext "
            "lesbar. Das ist regelmaessig ein meldepflichtiger DSGVO-Vorfall."
        ),
        empfohlene_massnahme="Geraeteverschluesselung aktivieren und Wiederherstellungsschluessel sichern.",
        quelle="Security-Audit",
    )


def _regel_rdp(measured: MeasuredFacts | None) -> RisikoPunkt | None:
    if not measured or measured.rdp_exposed is not True:
        return None
    return RisikoPunkt(
        titel="Fernzugriff (RDP) exponiert",
        kategorie="Haertung",
        prioritaet=Prioritaet.HOCH,
        befund="Ein Remote-Desktop-Zugang (RDP) ist erreichbar.",
        risiko_bei_nichtbeachtung=(
            "Exponiertes RDP ist eines der haeufigsten Einfallstore fuer "
            "Brute-Force-Angriffe und Ransomware."
        ),
        empfohlene_massnahme="RDP per VPN/Firewall absichern oder deaktivieren, MFA erzwingen.",
        quelle="Security-Audit",
    )


def _regel_mfa(measured: MeasuredFacts | None) -> RisikoPunkt | None:
    if not measured or measured.mfa_active is not False:
        return None
    return RisikoPunkt(
        titel="Mehr-Faktor-Authentifizierung (MFA) fehlt",
        kategorie="Organisatorisch",
        prioritaet=Prioritaet.HOCH,
        befund="Fuer den Zugang wird keine Mehr-Faktor-Authentifizierung verwendet.",
        risiko_bei_nichtbeachtung=(
            "Wird ein Passwort durch Phishing erbeutet, steht der Zugang offen. "
            "MFA verhindert die Account-Uebernahme in genau diesem Fall."
        ),
        empfohlene_massnahme="MFA fuer alle Zugaenge aktivieren.",
        quelle="Security-Audit",
    )


def _regel_backup(measured: MeasuredFacts | None) -> RisikoPunkt | None:
    if not measured or measured.backup_documented is not False:
        return None
    return RisikoPunkt(
        titel="Kein dokumentiertes Backup",
        kategorie="Organisatorisch",
        prioritaet=Prioritaet.KRITISCH,
        befund="Es ist keine funktionierende Datensicherung dokumentiert.",
        risiko_bei_nichtbeachtung=(
            "Bei Ransomware oder Hardware-Ausfall droht der vollstaendige, "
            "unwiederbringliche Datenverlust."
        ),
        empfohlene_massnahme="Backup nach 3-2-1-Regel einrichten und Wiederherstellung testen.",
        quelle="Security-Audit",
    )


def _regel_firewall(measured: MeasuredFacts | None) -> RisikoPunkt | None:
    if not measured or measured.firewall_active is not False:
        return None
    return RisikoPunkt(
        titel="Firewall nicht aktiv",
        kategorie="Haertung",
        prioritaet=Prioritaet.MITTEL,
        befund="Die System-Firewall ist nicht aktiv.",
        risiko_bei_nichtbeachtung=(
            "Ohne Firewall sind offene Dienste direkt aus dem Netz erreichbar — "
            "die Angriffsflaeche steigt deutlich."
        ),
        empfohlene_massnahme="Firewall aktivieren und eingehende Verbindungen restriktiv halten.",
        quelle="Security-Audit",
    )


def _regel_bsi_risiken(audit: AuditScoreInfo | None) -> list[RisikoPunkt]:
    # Speist sich aus ``AuditScoreInfo.top_risks`` (BSI-200-3-Matrix des SELF-
    # Audits, via customer_audit/self_audit_query.lade_top_risiken). Nur die
    # hohen Stufen (hoch/sehr hoch) erzeugen einen Punkt.
    if not audit:
        return []
    punkte: list[RisikoPunkt] = []
    for titel, level_label in audit.top_risks:
        if level_label.lower() not in _KRITISCHE_RISIKO_LEVEL:
            continue
        punkte.append(
            RisikoPunkt(
                titel=f"Hohes organisatorisches Risiko: {titel}",
                kategorie="Organisatorisch",
                prioritaet=Prioritaet.HOCH,
                befund=f"Ihr Security-Audit bewertet '{titel}' als Risiko '{level_label}'.",
                risiko_bei_nichtbeachtung=(
                    "Dieses Risiko wurde in der BSI-200-3-Bewertung als hoch "
                    "eingestuft — ohne Massnahme bleibt die Eintrittswahrscheinlichkeit "
                    "bzw. die Schadenshoehe unveraendert hoch."
                ),
                empfohlene_massnahme="Im Security-Audit die zugehoerige Massnahme planen und umsetzen.",
                quelle="Security-Audit (BSI 200-3)",
            )
        )
        if len(punkte) >= 3:
            break
    return punkte


def _regel_haertung_luecken(
    hardening: HardeningInfo | None,
) -> RisikoPunkt | None:
    if not hardening or not hardening.missing_categories:
        return None
    kategorien = ", ".join(hardening.missing_categories)
    return RisikoPunkt(
        titel="Haertungs-Bereiche ohne Messdaten",
        kategorie="Haertung",
        prioritaet=Prioritaet.NIEDRIG,
        befund=f"Fuer folgende Bereiche liegen keine Messdaten vor: {kategorien}.",
        risiko_bei_nichtbeachtung=(
            "Ohne Messung ist unbekannt, ob diese Bereiche abgesichert sind — "
            "der Hardening-Score bildet die Lage dort nicht ab."
        ),
        empfohlene_massnahme="Die fehlenden Scans/Checks ausfuehren, um die Luecke zu schliessen.",
        quelle="Messung (Hardening)",
    )


def baue_risiko_punkte(
    cves: Sequence[AffectedCveItem],
    patch_backlog: PatchBacklogInfo | None = None,
    hardening: HardeningInfo | None = None,
    audit: AuditScoreInfo | None = None,
    measured: MeasuredFacts | None = None,
) -> tuple[RisikoPunkt, ...]:
    """Leitet die wichtigen Punkte deterministisch aus den Quelldaten ab.

    Reihenfolge: nach:attr:`Prioritaet.rang` (kritisch zuerst), innerhalb
    gleicher Prioritaet stabil in Regel-Reihenfolge.
    """
    punkte: list[RisikoPunkt] = []
    for regel in (
        _regel_aktiv_ausgenutzt,
        _regel_kritische_cves,
    ):
        if (p := regel(cves)) is not None:
            punkte.append(p)
    if (p := _regel_eol(cves, patch_backlog)) is not None:
        punkte.append(p)
    if (p := _regel_offene_updates(patch_backlog)) is not None:
        punkte.append(p)
    for regel_m in (
        _regel_backup,
        _regel_festplattenverschluesselung,
        _regel_rdp,
        _regel_mfa,
        _regel_firewall,
    ):
        if (p := regel_m(measured)) is not None:
            punkte.append(p)
    punkte.extend(_regel_bsi_risiken(audit))
    if (p := _regel_haertung_luecken(hardening)) is not None:
        punkte.append(p)

    punkte.sort(key=lambda rp: rp.prioritaet.rang)
    return tuple(punkte)


class RisikoBriefingService:
    """Baut den:class:`RiskBriefingSnapshot` fuer Tab 1 (transient).

    Alle Quellen kommen per Dependency Injection: der CVE-Port und vier
    optionale Loader. Fehlende/gesperrte Quellen (Loader liefert ``None``)
    reduzieren das Bild still, ohne zu brechen (fail-soft) — ein CUSTOMER-Audit
    liefert ueber den SELF-gegateten Audit-Loader ``None`` und damit keine
    Audit-/BSI-Punkte fail-closed).
    """

    def __init__(
        self,
        cve_quelle: AffectedCveQuelle,
        *,
        patch_backlog_loader: _PatchBacklogLoader | None = None,
        hardening_loader: _HardeningLoader | None = None,
        audit_loader: _AuditLoader | None = None,
        measured_loader: _MeasuredLoader | None = None,
    ) -> None:
        self._cve_quelle = cve_quelle
        self._patch_backlog_loader = patch_backlog_loader
        self._hardening_loader = hardening_loader
        self._audit_loader = audit_loader
        self._measured_loader = measured_loader

    def build_snapshot(self, *, max_cves: int = 50) -> RiskBriefingSnapshot:
        """Sammelt alle Quellen und leitet die Risiko-Punkte ab.

        Args:
            max_cves: Obergrenze der gelisteten betroffenen CVEs.
        """
        cves = tuple(self._cve_quelle.lade_betroffene_cves(limit=max_cves))
        apps_without_cpe = self._cve_quelle.anzahl_apps_ohne_cpe()

        patch_backlog = (
            self._patch_backlog_loader() if self._patch_backlog_loader else None
        )
        hardening = self._hardening_loader() if self._hardening_loader else None
        audit = self._audit_loader() if self._audit_loader else None
        measured = self._measured_loader() if self._measured_loader else None

        punkte = baue_risiko_punkte(cves, patch_backlog, hardening, audit, measured)

        return RiskBriefingSnapshot(
            risiko_punkte=punkte,
            affected_cves=cves,
            patch_backlog=patch_backlog,
            hardening=hardening,
            audit=audit,
            apps_without_cpe=apps_without_cpe,
        )
