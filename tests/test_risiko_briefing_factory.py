"""Tests fuer die Uebersetzungs-Helfer + Loader der RisikoBriefing-Factory 3b).

Die Cross-Tool-Loader selbst (lazy reale Services) sind Integration; hier werden
die reinen Helfer + der duck-typed Patch-Backlog-Loader ohne DB geprueft.
"""

from __future__ import annotations

from types import SimpleNamespace

from tools.customer_audit.domain.entities import AuditMode
from tools.cyber_dashboard.application.risiko_briefing_factory import (
    _audit_info_from_result,
    _build_patch_backlog_loader,
    _hardening_info_from_result,
    _ja,
    _kategorie_label,
    _measured_facts_from_audit,
)
from tools.cyber_dashboard.domain.risiko_briefing import PatchBacklogInfo


def test_kategorie_label_mapping() -> None:
    assert _kategorie_label("network") == "Netzwerk"
    assert _kategorie_label("cve_patch") == "Schwachstellen/Patches"
    # unbekannte Kategorie faellt auf den Rohwert zurueck
    assert _kategorie_label("irgendwas") == "irgendwas"


class _Stage:
    label = "Moderate"


class _Result:
    overall_score = 72.5
    stage = _Stage()
    category_scores = (object(),)
    missing_categories = ("network", "password")


def test_hardening_info_from_result() -> None:
    info = _hardening_info_from_result(_Result())
    assert info is not None
    assert info.score == 72.5
    assert info.stage_label == "Moderate"
    assert info.missing_categories == ("Netzwerk", "Identitaet/Passwoerter")


def test_hardening_none_bei_leer_oder_none() -> None:
    class _Empty:
        category_scores = ()

    assert _hardening_info_from_result(_Empty()) is None
    assert _hardening_info_from_result(None) is None


def test_audit_info_from_result() -> None:
    assert _audit_info_from_result(None) is None
    info = _audit_info_from_result(SimpleNamespace(overall_score=60.0))
    assert info is not None
    assert info.score == 60.0
    assert info.top_risks == ()  # Default ohne Risiko-Daten


def test_audit_info_from_result_mit_top_risks() -> None:
    info = _audit_info_from_result(
        SimpleNamespace(overall_score=50.0), (("Ransomware", "hoch"),)
    )
    assert info is not None
    assert info.top_risks == (("Ransomware", "hoch"),)


def test_geteilter_audit_provider_laedt_nur_einmal(monkeypatch) -> None:
    # Perf (Phase 5): Score- + Measured-Loader teilen EINEN Audit-Load pro Refresh.
    from tools.cyber_dashboard.application import risiko_briefing_factory as f

    calls = {"n": 0}

    def _fake_load() -> object:
        calls["n"] += 1
        return SimpleNamespace(
            audit_mode=AuditMode.SELF,
            overall_score=50.0,
            audit_id="a1",
            infrastructure_data=None,
            organizational_data=None,
            phishing_data=None,
        )

    monkeypatch.setattr(f, "_lade_top_risiken", lambda audit_id: ())
    provider = f._memoize_kurz(_fake_load, ttl_s=100.0)
    audit_loader = f._build_self_audit_loader(provider)
    measured_loader = f._build_measured_loader(provider)

    audit_loader()
    measured_loader()
    assert calls["n"] == 1  # geteilt statt doppelt geladen


class _FakePatch:
    def __init__(self, offen: int, eol: int) -> None:
        self._offen = offen
        self._eol = eol

    def offene_und_eol_counts(self) -> tuple[int, int]:
        return (self._offen, self._eol)

    def letzter_vollscan(self):  # noqa: ANN201 - Testdouble
        return None


def test_patch_backlog_loader() -> None:
    info = _build_patch_backlog_loader(_FakePatch(3, 1))()
    assert info == PatchBacklogInfo(
        open_updates=3, eol_without_patch=1, last_scan_at=None
    )


def test_patch_backlog_loader_none_bei_leer() -> None:
    assert _build_patch_backlog_loader(_FakePatch(0, 0))() is None


def test_patch_backlog_loader_fail_soft() -> None:
    class _Boom:
        def offene_und_eol_counts(self):  # noqa: ANN202
            raise RuntimeError("db kaputt")

        def letzter_vollscan(self):  # noqa: ANN202
            return None

    assert _build_patch_backlog_loader(_Boom())() is None


# ---------------------------------------------------------------------------
# Measured-Eckwerte aus dem SELF-Audit (Patrick-Entscheid 2026-06-29)
# ---------------------------------------------------------------------------


def test_ja_konservativ() -> None:
    assert _ja("Ja") is True
    assert _ja("aktiv") is True
    assert _ja("Nein") is False
    assert _ja("inaktiv") is False
    # Mehrdeutig -> neutral (kein False-Positive)
    assert _ja("teilweise") is None
    assert _ja("unbekannt") is None
    assert _ja("") is None
    assert _ja(None) is None


def _audit(
    *,
    audit_mode: AuditMode = AuditMode.SELF,
    firewall_status: str = "",
    verschluesselung: tuple[str, ...] = (),
    remote_access_tools: tuple[str, ...] = (),
    mfa: str = "",
    backup: str = "",
) -> SimpleNamespace:
    return SimpleNamespace(
        audit_mode=audit_mode,
        infrastructure_data=SimpleNamespace(
            firewall_status=firewall_status,
            verschluesselung=list(verschluesselung),
            remote_access_tools=list(remote_access_tools),
        ),
        organizational_data=SimpleNamespace(backup_strategie=backup),
        phishing_data=SimpleNamespace(mfa_aktiv=mfa),
    )


def test_measured_none_bei_result_none() -> None:
    assert _measured_facts_from_audit(None) is None


def test_measured_leere_verschluesselung_ist_false() -> None:
    # FIX (Review P1): leere Verschluesselungs-Liste in einem SELF-Audit =
    # "keine Verschluesselung deklariert" -> disk=False (Regel feuert jetzt).
    facts = _measured_facts_from_audit(_audit())
    assert facts is not None
    assert facts.disk_encryption_active is False


def test_measured_customer_mode_fail_closed() -> None:
    # CUSTOMER-Audit darf NIE ins eigene Risikobild.
    audit = _audit(audit_mode=AuditMode.CUSTOMER, mfa="Nein", firewall_status="inaktiv")
    assert _measured_facts_from_audit(audit) is None


def test_measured_klare_negativsignale() -> None:
    facts = _measured_facts_from_audit(
        _audit(firewall_status="inaktiv", mfa="Nein", backup="Nein")
    )
    assert facts is not None
    assert facts.firewall_active is False
    assert facts.mfa_active is False
    assert facts.backup_documented is False


def test_measured_positiv_und_neutral() -> None:
    facts = _measured_facts_from_audit(
        _audit(
            firewall_status="aktiv",
            verschluesselung=("BitLocker",),
            mfa="Ja",
        )
    )
    assert facts is not None
    assert facts.firewall_active is True
    assert facts.disk_encryption_active is True  # nicht-leere Liste
    assert facts.mfa_active is True
    # leere Remote-Liste / kein Backup-Wert -> neutral
    assert facts.rdp_exposed is None
    assert facts.backup_documented is None


def test_measured_rdp_erkennung() -> None:
    mit = _measured_facts_from_audit(_audit(remote_access_tools=("AnyDesk", "RDP")))
    assert mit is not None and mit.rdp_exposed is True
    # nur Nicht-RDP-Tools -> rdp neutral (nicht False)
    ohne = _measured_facts_from_audit(_audit(remote_access_tools=("AnyDesk",)))
    assert ohne is not None and ohne.rdp_exposed is None
