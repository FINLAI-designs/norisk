"""Tests fuer die RisikoPunkt-Engine + RisikoBriefingService.

Deckt:
* jede Regel des deterministischen Katalogs (feuert / feuert nicht)
* Mess-Eckwerte neutral bei ``None`` (nur explizites ``False``/``True`` wirkt)
* Sortierung nach Prioritaet
* Snapshot-Aufbau + SELF-Gate (audit_loader ``None`` -> keine BSI-Punkte)
* Konfidenz-Buckets (bestaetigt / moeglich)
*/039-Invariante: KEIN aggregiertes Gesamt-Score-Feld
"""

from __future__ import annotations

from collections.abc import Sequence

from tools.cyber_dashboard.application.risiko_briefing_service import (
    RisikoBriefingService,
    baue_risiko_punkte,
)
from tools.cyber_dashboard.domain.risiko_briefing import (
    AffectedCveItem,
    AuditScoreInfo,
    HardeningInfo,
    Konfidenz,
    MeasuredFacts,
    PatchBacklogInfo,
    Prioritaet,
    RiskBriefingSnapshot,
)


def _cve(
    cve_id: str = "CVE-2024-1",
    cvss: float | None = 8.0,
    *,
    exploit: bool = False,
    eol: bool = False,
    konf: Konfidenz = Konfidenz.BESTAETIGT,
    apps: tuple[str, ...] = ("Beispiel-App",),
    update: bool = False,
) -> AffectedCveItem:
    return AffectedCveItem(
        cve_id=cve_id,
        cvss_score=cvss,
        exploit_available=exploit,
        eol=eol,
        konfidenz=konf,
        affected_apps=apps,
        update_available=update,
    )


class _FakeQuelle:
    def __init__(
        self, cves: Sequence[AffectedCveItem] = (), apps_without: int = 0
    ) -> None:
        self._cves = list(cves)
        self._apps_without = apps_without

    def lade_betroffene_cves(
        self, *, min_cvss: float = 0.0, limit: int = 50
    ) -> Sequence[AffectedCveItem]:
        return self._cves[:limit]

    def anzahl_apps_ohne_cpe(self) -> int:
        return self._apps_without


def _titel(punkte: tuple) -> list[str]:
    return [p.titel for p in punkte]


# ---------------------------------------------------------------------------
# Engine — einzelne Regeln
# ---------------------------------------------------------------------------


class TestRegeln:
    def test_kev_loest_kritischen_punkt(self) -> None:
        punkte = baue_risiko_punkte([_cve(exploit=True)])
        assert len(punkte) == 1
        assert punkte[0].prioritaet is Prioritaet.KRITISCH
        assert punkte[0].kategorie == "CVE"
        assert "aktiv ausgenutzt" in punkte[0].titel.lower()

    def test_kev_nicht_ohne_exploit(self) -> None:
        punkte = baue_risiko_punkte([_cve(exploit=False, cvss=5.0)])
        assert not any("aktiv ausgenutzt" in p.titel.lower() for p in punkte)

    def test_hohe_cvss_loest_hoch_punkt(self) -> None:
        punkte = baue_risiko_punkte([_cve(cvss=9.1, exploit=False)])
        assert [p.prioritaet for p in punkte] == [Prioritaet.HOCH]
        assert "Schwerwiegende" in punkte[0].titel

    def test_kev_und_hochcvss_getrennt_nicht_doppelt(self) -> None:
        # Ein KEV-CVE darf NICHT zusaetzlich im "schwerwiegend"-Punkt zaehlen.
        punkte = baue_risiko_punkte([_cve(cvss=9.5, exploit=True)])
        titel = _titel(punkte)
        assert any("aktiv ausgenutzt" in t.lower() for t in titel)
        assert not any("Schwerwiegende" in t for t in titel)

    def test_niedrige_cvss_keine_cve_punkte(self) -> None:
        assert baue_risiko_punkte([_cve(cvss=4.0, exploit=False)]) == ()

    def test_eol_aus_cve(self) -> None:
        punkte = baue_risiko_punkte([_cve(eol=True, cvss=3.0)])
        assert any("End-of-Life" in p.titel for p in punkte)

    def test_eol_aus_backlog(self) -> None:
        backlog = PatchBacklogInfo(
            open_updates=0, eol_without_patch=2, last_scan_at=None
        )
        punkte = baue_risiko_punkte([], backlog)
        assert any("End-of-Life" in p.titel for p in punkte)

    def test_eol_nutzt_backlog_zahl_nicht_max(self) -> None:
        # Review-Fix: kein max ueber inkommensurable Zaehler — die
        # Patch-Monitor-Zahl (2) ist autoritativ, nicht die CVE-EOL-App-Zahl (1).
        backlog = PatchBacklogInfo(
            open_updates=0, eol_without_patch=2, last_scan_at=None
        )
        punkte = baue_risiko_punkte([_cve(eol=True, apps=("AppX",))], backlog)
        eintrag = next(p for p in punkte if "End-of-Life" in p.titel)
        assert "2 Produkt" in eintrag.befund

    def test_offene_updates(self) -> None:
        backlog = PatchBacklogInfo(
            open_updates=3, eol_without_patch=0, last_scan_at=None
        )
        punkte = baue_risiko_punkte([], backlog)
        eintrag = next(p for p in punkte if "Updates noch nicht" in p.titel)
        assert eintrag.prioritaet is Prioritaet.MITTEL
        assert "3" in eintrag.befund

    def test_festplatte_nur_bei_false(self) -> None:
        assert baue_risiko_punkte(
            [], measured=MeasuredFacts(disk_encryption_active=False)
        )
        # None (ungeprueft) und True (aktiv) loesen NICHTS aus
        assert (
            baue_risiko_punkte([], measured=MeasuredFacts(disk_encryption_active=None))
            == ()
        )
        assert (
            baue_risiko_punkte([], measured=MeasuredFacts(disk_encryption_active=True))
            == ()
        )

    def test_rdp_nur_bei_true(self) -> None:
        assert baue_risiko_punkte([], measured=MeasuredFacts(rdp_exposed=True))
        assert baue_risiko_punkte([], measured=MeasuredFacts(rdp_exposed=None)) == ()
        assert baue_risiko_punkte([], measured=MeasuredFacts(rdp_exposed=False)) == ()

    def test_mfa_nur_bei_false(self) -> None:
        punkte = baue_risiko_punkte([], measured=MeasuredFacts(mfa_active=False))
        assert any("MFA" in p.titel for p in punkte)

    def test_backup_ist_kritisch(self) -> None:
        punkte = baue_risiko_punkte([], measured=MeasuredFacts(backup_documented=False))
        eintrag = next(p for p in punkte if "Backup" in p.titel)
        assert eintrag.prioritaet is Prioritaet.KRITISCH

    def test_firewall_mittel(self) -> None:
        punkte = baue_risiko_punkte([], measured=MeasuredFacts(firewall_active=False))
        eintrag = next(p for p in punkte if "Firewall" in p.titel)
        assert eintrag.prioritaet is Prioritaet.MITTEL

    def test_bsi_nur_hohe_level(self) -> None:
        audit = AuditScoreInfo(
            score=60.0,
            top_risks=(
                ("Ransomware", "sehr hoch"),
                ("Phishing", "hoch"),
                ("Kleinkram", "gering"),
                ("Mittelding", "mittel"),
            ),
        )
        punkte = baue_risiko_punkte([], audit=audit)
        bsi = [p for p in punkte if p.kategorie == "Organisatorisch"]
        assert len(bsi) == 2  # nur hoch + sehr hoch
        assert all("gering" not in p.befund and "mittel" not in p.befund for p in bsi)

    def test_bsi_deckelt_bei_drei(self) -> None:
        audit = AuditScoreInfo(
            score=10.0,
            top_risks=tuple((f"R{i}", "hoch") for i in range(6)),
        )
        bsi = [
            p
            for p in baue_risiko_punkte([], audit=audit)
            if p.kategorie == "Organisatorisch"
        ]
        assert len(bsi) == 3

    def test_haertungsluecken(self) -> None:
        hardening = HardeningInfo(
            score=70.0,
            stage_label="Moderate",
            missing_categories=("Netzwerk", "Identitaet"),
        )
        punkte = baue_risiko_punkte([], hardening=hardening)
        eintrag = next(p for p in punkte if "Haertungs-Bereiche" in p.titel)
        assert "Netzwerk" in eintrag.befund

    def test_keine_daten_keine_punkte(self) -> None:
        assert baue_risiko_punkte([]) == ()

    def test_sortierung_nach_prioritaet(self) -> None:
        punkte = baue_risiko_punkte(
            [_cve(exploit=True)],  # KRITISCH
            PatchBacklogInfo(
                open_updates=2, eol_without_patch=0, last_scan_at=None
            ),  # MITTEL
            HardeningInfo(
                score=1.0, stage_label="x", missing_categories=("Netz",)
            ),  # NIEDRIG
            measured=MeasuredFacts(rdp_exposed=True),  # HOCH
        )
        raenge = [p.prioritaet.rang for p in punkte]
        assert raenge == sorted(raenge)
        assert punkte[0].prioritaet is Prioritaet.KRITISCH
        assert punkte[-1].prioritaet is Prioritaet.NIEDRIG


# ---------------------------------------------------------------------------
# Service — Snapshot-Aufbau + SELF-Gate
# ---------------------------------------------------------------------------


class TestService:
    def test_build_snapshot_basis(self) -> None:
        svc = RisikoBriefingService(
            _FakeQuelle([_cve(exploit=True)], apps_without=4),
            patch_backlog_loader=lambda: PatchBacklogInfo(2, 0, None),
            measured_loader=lambda: MeasuredFacts(backup_documented=False),
        )
        snap = svc.build_snapshot()
        assert isinstance(snap, RiskBriefingSnapshot)
        assert snap.apps_without_cpe == 4
        assert len(snap.affected_cves) == 1
        assert snap.patch_backlog == PatchBacklogInfo(2, 0, None)
        titel = _titel(snap.risiko_punkte)
        assert any("aktiv ausgenutzt" in t.lower() for t in titel)
        assert any("Backup" in t for t in titel)

    def test_self_gate_audit_none_keine_bsi_punkte(self) -> None:
        # CUSTOMER-Kontext: audit_loader liefert None (fail-closed) -> keine BSI-Punkte.
        svc = RisikoBriefingService(
            _FakeQuelle([_cve(exploit=True)]),
            audit_loader=lambda: None,
        )
        snap = svc.build_snapshot()
        assert snap.audit is None
        assert all(p.kategorie != "Organisatorisch" for p in snap.risiko_punkte)

    def test_audit_vorhanden_liefert_bsi_punkt(self) -> None:
        svc = RisikoBriefingService(
            _FakeQuelle([]),
            audit_loader=lambda: AuditScoreInfo(50.0, (("Ransomware", "sehr hoch"),)),
        )
        snap = svc.build_snapshot()
        assert snap.audit is not None
        assert any(p.kategorie == "Organisatorisch" for p in snap.risiko_punkte)

    def test_measured_none_keine_mess_punkte(self) -> None:
        svc = RisikoBriefingService(_FakeQuelle([]), measured_loader=lambda: None)
        snap = svc.build_snapshot()
        assert snap.risiko_punkte == ()

    def test_konfidenz_buckets(self) -> None:
        svc = RisikoBriefingService(
            _FakeQuelle(
                [
                    _cve(cve_id="A", konf=Konfidenz.BESTAETIGT),
                    _cve(cve_id="B", konf=Konfidenz.MOEGLICH),
                ]
            )
        )
        snap = svc.build_snapshot()
        assert [c.cve_id for c in snap.bestaetigte_cves] == ["A"]
        assert [c.cve_id for c in snap.moegliche_cves] == ["B"]


# ---------------------------------------------------------------------------
#/039-Invariante: kein Misch-Score
# ---------------------------------------------------------------------------


class TestKeinMischScore:
    def test_snapshot_hat_kein_aggregiertes_score_feld(self) -> None:
        svc = RisikoBriefingService(
            _FakeQuelle([]),
            hardening_loader=lambda: HardeningInfo(72.0, "Moderate"),
            audit_loader=lambda: AuditScoreInfo(60.0),
        )
        snap = svc.build_snapshot()
        # Beide Dimensionen getrennt erreichbar...
        assert snap.hardening is not None and snap.hardening.score == 72.0
        assert snap.audit is not None and snap.audit.score == 60.0
        #... aber KEIN gemeinsames/gemitteltes Feld auf dem Snapshot.
        for verboten in (
            "gesamt_score",
            "overall_score",
            "score",
            "durchschnitt",
            "gemittelt",
        ):
            assert not hasattr(snap, verboten)
