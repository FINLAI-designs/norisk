"""
test_customer_assessment — Unit-Tests für das Kunden-Assessment-Tool.

Testet Domain-Logik, Scoring, Empfehlungen, Use Cases und Repository
ohne GUI-Abhängigkeiten.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tools.customer_audit.domain.entities import (
    CategoryScore,
    CustomerAuditResult,
    CustomerData,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    sanitize_text,
)
from tools.customer_audit.domain.recommendation_engine import (
    PRIO_KRITISCH,
    PRIO_MITTEL,
    generate_recommendations,
    recommendations_as_strings,
)
from tools.customer_audit.domain.scoring_service import (
    build_category_scores,
    calculate_infrastructure_score,
    calculate_network_score,
    calculate_organizational_score,
    calculate_overall_score,
    score_to_risk_level,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_SENTINEL = object()


def _make_infra(
    av_status="aktiv",
    fw_status="aktiv",
    verschluesselung=_SENTINEL,
    remote_tools=_SENTINEL,
) -> InfrastructureData:
    return InfrastructureData(
        antivirus_name="TestAV",
        antivirus_status=av_status,
        firewall_name="TestFW",
        firewall_status=fw_status,
        verschluesselung=["BitLocker"]
        if verschluesselung is _SENTINEL
        else verschluesselung,
        remote_access_tools=["RDP"] if remote_tools is _SENTINEL else remote_tools,
    )


def _make_org_all_ja() -> OrganizationalData:
    return OrganizationalData(
        zugangskontrollen="Ja",
        backup_strategie="Ja",
        update_management="Ja",
        mitarbeitersensibilisierung="Ja",
        incident_response_plan="Ja",
        dsgvo_konformitaet="Ja",
        avv_key_separate_storage="Ja",
    )


def _make_org_all_nein() -> OrganizationalData:
    return OrganizationalData(
        zugangskontrollen="Nein",
        backup_strategie="Nein",
        update_management="Nein",
        mitarbeitersensibilisierung="Nein",
        incident_response_plan="Nein",
        dsgvo_konformitaet="Nein",
    )


def _make_network(
    segmentierung="Ja",
    wlan="WPA3",
    ports="Ja",
    ids="Ja",
    pentest="2025",
) -> NetworkData:
    return NetworkData(
        netzwerksegmentierung=segmentierung,
        wlan_sicherheit=wlan,
        offene_ports_bekannt=ports,
        ids_ips_vorhanden=ids,
        letzter_pentest=pentest,
    )


def _make_customer_data(firma="TestFirma") -> CustomerData:
    return CustomerData(
        firmenname=firma,
        ansprechpartner_name="Max Mustermann",
        ansprechpartner_email="max@firma.de",
        ansprechpartner_telefon="+43 1 234",
        branche="IT",
        unternehmensgroesse="11-50",
        erstellungsdatum="2026-04-06",
    )


# ---------------------------------------------------------------------------
# Tests: sanitize_text
# ---------------------------------------------------------------------------


class TestSanitizeText:
    """/: sanitize_text begrenzt nur noch Input — KEIN Escaping.

    Output-Encoding passiert at-render (core.escape.escape_html an den
    markup-interpretierenden Senken).
    """

    def test_html_chars_bleiben_klartext(self):
        raw = '<script>alert("xss")</script>'
        assert sanitize_text(raw) == raw

    def test_ampersand_bleibt_klartext(self):
        assert sanitize_text("a & b") == "a & b"

    def test_max_length_truncated(self):
        long_text = "a" * 600
        result = sanitize_text(long_text)
        assert len(result) == 500

    def test_steuerzeichen_entfernt_umbruch_bleibt(self):
        assert sanitize_text("a\x00b\x07c\nd\te") == "abc\nd\te"

    def test_empty_string(self):
        assert sanitize_text("") == ""

    def test_normal_text_unchanged(self):
        result = sanitize_text("Musterfirma GmbH")
        assert result == "Musterfirma GmbH"


# ---------------------------------------------------------------------------
# Tests: CustomerData round-trip
# ---------------------------------------------------------------------------


class TestCustomerDataRoundTrip:
    def test_to_dict_from_dict(self):
        cd = _make_customer_data()
        d = cd.to_dict()
        restored = CustomerData.from_dict(d)
        assert restored.firmenname == cd.firmenname
        assert restored.branche == cd.branche

    def test_from_dict_defaults(self):
        cd = CustomerData.from_dict({})
        assert cd.firmenname == ""
        assert cd.branche == "Sonstige"


class TestInfrastructureDataRoundTrip:
    def test_to_dict_from_dict(self):
        infra = _make_infra()
        restored = InfrastructureData.from_dict(infra.to_dict())
        assert restored.antivirus_status == "aktiv"
        assert restored.verschluesselung == ["BitLocker"]

    def test_list_fields_preserved(self):
        infra = InfrastructureData(
            betriebssysteme=["Windows 11", "macOS"],
            remote_access_tools=["RDP", "SSH"],
        )
        restored = InfrastructureData.from_dict(infra.to_dict())
        assert "Windows 11" in restored.betriebssysteme
        assert "RDP" in restored.remote_access_tools


class TestOrganizationalDataRoundTrip:
    def test_to_dict_from_dict(self):
        org = _make_org_all_ja()
        restored = OrganizationalData.from_dict(org.to_dict())
        assert restored.backup_strategie == "Ja"
        assert restored.dsgvo_konformitaet == "Ja"


class TestNetworkDataRoundTrip:
    def test_to_dict_from_dict(self):
        net = _make_network()
        restored = NetworkData.from_dict(net.to_dict())
        assert restored.wlan_sicherheit == "WPA3"
        assert restored.letzter_pentest == "2025"


# ---------------------------------------------------------------------------
# Tests: Scoring — score_to_risk_level
# ---------------------------------------------------------------------------


class TestScoreToRiskLevel:
    @pytest.mark.parametrize(
        "score, expected",
        [
            (100.0, "Niedrig"),
            (75.0, "Niedrig"),
            (74.9, "Mittel"),
            (55.0, "Mittel"),
            (54.9, "Hoch"),
            (35.0, "Hoch"),
            (34.9, "Kritisch"),
            (0.0, "Kritisch"),
        ],
    )
    def test_thresholds(self, score, expected):
        assert score_to_risk_level(score) == expected


# ---------------------------------------------------------------------------
# Tests: Infrastruktur-Score
# ---------------------------------------------------------------------------


class TestCalculateInfrastructureScore:
    def test_all_active_bitlocker_no_risky_tools(self):
        infra = _make_infra(av_status="aktiv", fw_status="aktiv")
        score = calculate_infrastructure_score(infra)
        assert score >= 90.0

    def test_inactive_av_reduces_score(self):
        infra = _make_infra(av_status="inaktiv", fw_status="aktiv")
        score = calculate_infrastructure_score(infra)
        assert score < calculate_infrastructure_score(_make_infra())

    def test_no_encryption_reduces_score(self):
        infra = _make_infra(verschluesselung=[])
        score = calculate_infrastructure_score(infra)
        assert score <= 70.0

    def test_keine_encryption_zero_enc_score(self):
        infra_no_enc = _make_infra(verschluesselung=["Keine"])
        infra_with_enc = _make_infra(verschluesselung=["BitLocker"])
        assert calculate_infrastructure_score(
            infra_no_enc
        ) < calculate_infrastructure_score(infra_with_enc)

    def test_risky_remote_tools_reduce_score(self):
        infra_risky = _make_infra(remote_tools=["TeamViewer", "AnyDesk"])
        infra_safe = _make_infra(remote_tools=["SSH"])
        assert calculate_infrastructure_score(
            infra_risky
        ) < calculate_infrastructure_score(infra_safe)

    def test_keine_remote_tool_full_remote_score(self):
        infra = _make_infra(remote_tools=["Keine"])
        score = calculate_infrastructure_score(infra)
        # "Keine" = kein Risiko, nur AV + FW + Enc beeinflussen
        assert score > 80.0

    def test_score_in_range(self):
        for av in ["aktiv", "inaktiv", "unbekannt"]:
            for fw in ["aktiv", "inaktiv", "unbekannt"]:
                infra = _make_infra(av_status=av, fw_status=fw)
                score = calculate_infrastructure_score(infra)
                assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# Tests: Organisations-Score
# ---------------------------------------------------------------------------


class TestCalculateOrganizationalScore:
    def test_all_ja_gives_100(self):
        assert calculate_organizational_score(_make_org_all_ja()) == 100.0

    def test_all_nein_gives_0(self):
        assert calculate_organizational_score(_make_org_all_nein()) == 0.0

    def test_avv_key_separate_storage_zaehlt_zum_score(self):
        # 3f-ii: das 7. Feld ist scoring-relevant.
        # 6× Ja + 1× Nein → 6/7 * 100 ≈ 85.7
        org = OrganizationalData(
            zugangskontrollen="Ja",
            backup_strategie="Ja",
            update_management="Ja",
            mitarbeitersensibilisierung="Ja",
            incident_response_plan="Ja",
            dsgvo_konformitaet="Ja",
            avv_key_separate_storage="Nein",
        )
        score = calculate_organizational_score(org)
        # 6/7 = 0.857142... → gerundet auf 1 Nachkommastelle 85.7
        assert abs(score - 85.7) < 0.05

    def test_nur_avv_key_separate_storage_ja(self):
        org = OrganizationalData(
            zugangskontrollen="Nein",
            backup_strategie="Nein",
            update_management="Nein",
            mitarbeitersensibilisierung="Nein",
            incident_response_plan="Nein",
            dsgvo_konformitaet="Nein",
            avv_key_separate_storage="Ja",
        )
        score = calculate_organizational_score(org)
        # 1/7 = 0.142857... → 14.3
        assert abs(score - 14.3) < 0.05

    def test_all_teilweise_gives_50(self):
        org = OrganizationalData(
            zugangskontrollen="Teilweise",
            backup_strategie="Teilweise",
            update_management="Teilweise",
            mitarbeitersensibilisierung="Teilweise",
            incident_response_plan="Teilweise",
            dsgvo_konformitaet="Teilweise",
            avv_key_separate_storage="Teilweise",
        )
        assert calculate_organizational_score(org) == 50.0

    def test_mixed_score_between_0_and_100(self):
        org = OrganizationalData(
            zugangskontrollen="Ja",
            backup_strategie="Nein",
            update_management="Ja",
            mitarbeitersensibilisierung="Nein",
            incident_response_plan="Ja",
            dsgvo_konformitaet="Nein",
        )
        score = calculate_organizational_score(org)
        assert 0.0 < score < 100.0


# ---------------------------------------------------------------------------
# Tests: Netzwerk-Score
# ---------------------------------------------------------------------------


class TestCalculateNetworkScore:
    def test_best_case_near_100(self):
        net = _make_network(segmentierung="Ja", wlan="WPA3", ids="Ja", pentest="2025")
        score = calculate_network_score(net)
        assert score >= 90.0

    def test_open_wlan_reduces_score(self):
        net_open = _make_network(wlan="Offen")
        net_wpa3 = _make_network(wlan="WPA3")
        assert calculate_network_score(net_open) < calculate_network_score(net_wpa3)

    def test_wep_lower_than_wpa2(self):
        net_wep = _make_network(wlan="WEP")
        net_wpa2 = _make_network(wlan="WPA2")
        assert calculate_network_score(net_wep) < calculate_network_score(net_wpa2)

    def test_no_pentest_reduces_score(self):
        net_with = _make_network(pentest="2025")
        net_without = _make_network(pentest="Nie")
        assert calculate_network_score(net_without) < calculate_network_score(net_with)

    def test_unknown_pentest_medium_score(self):
        net_unknown = _make_network(pentest="Unbekannt")
        net_no = _make_network(pentest="Nie")
        assert calculate_network_score(net_unknown) > calculate_network_score(net_no)

    def test_score_in_range(self):
        for wlan in ["WPA3", "WPA2", "WEP", "Offen", "Unbekannt"]:
            net = _make_network(wlan=wlan)
            score = calculate_network_score(net)
            assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# Tests: Gesamtscore
# ---------------------------------------------------------------------------


class TestCalculateOverallScore:
    """: Gewichte umgestellt auf 6 Kategorien
    (Infra 25 / Org 25 / Network 20 / Backup 10 / Sovereignty 10 /
    IR 10). Bestehende Aufrufe mit nur 3 Argumenten erhalten die
    neuen Sub-Audits werden uebersprungen wenn ``None`` — die
    Gewichte werden auf die aktiven Kategorien re-normalisiert, damit
    alte 3-Kategorien-Audits beim Re-Save nicht stumm gestaucht werden.
    """

    def test_weighted_calculation_all_categories(self):
        # Alle 6 Kategorien mit Vollscore -> 100
        assert calculate_overall_score(100.0, 100.0, 100.0, 100.0, 100.0, 100.0) == 100.0

    def test_legacy_three_inputs_only(self):
        # Nur die 3 Pflicht-Kategorien -> normalisiert auf 100
        # (Sub-Audits sind None, werden nicht gewichtet).
        assert calculate_overall_score(100.0, 100.0, 100.0) == 100.0

    def test_zero_inputs(self):
        assert calculate_overall_score(0.0, 0.0, 0.0) == 0.0

    def test_partial_inputs(self):
        # 80*0.25 + 60*0.25 + 70*0.20 = 49; normalisiert /0.70 = 70.0
        score = calculate_overall_score(80.0, 60.0, 70.0)
        assert score == pytest.approx(70.0, abs=0.1)

    def test_explicit_zero_subscore_counts(self):
        # Backup-Score 0 (durchlaufen, aber miserabel) zaehlt mit.
        assert calculate_overall_score(100.0, 100.0, 100.0, backup=0.0) < 100.0

    def test_clamped_to_100(self):
        assert calculate_overall_score(110.0, 110.0, 110.0, 110.0, 110.0, 110.0) == 100.0

    def test_clamped_to_0(self):
        assert calculate_overall_score(-10.0, -10.0, -10.0) == 0.0


# ---------------------------------------------------------------------------
# Tests: CategoryScores
# ---------------------------------------------------------------------------


class TestBuildCategoryScores:
    def test_returns_three_categories(self):
        cats = build_category_scores(80.0, 70.0, 60.0)
        assert len(cats) == 3

    def test_category_names(self):
        cats = build_category_scores(80.0, 70.0, 60.0)
        names = [c.name for c in cats]
        assert "IT-Infrastruktur" in names
        assert "Organisatorische Sicherheit" in names
        assert "Netzwerksicherheit" in names

    def test_labels_match_scores(self):
        cats = build_category_scores(80.0, 40.0, 20.0)
        assert cats[0].label == "Niedrig"
        assert cats[1].label == "Hoch"
        assert cats[2].label == "Kritisch"


# ---------------------------------------------------------------------------
# Tests: Recommendation Engine
# ---------------------------------------------------------------------------


class TestRecommendationEngine:
    def test_inactive_av_generates_kritisch(self):
        infra = _make_infra(av_status="inaktiv")
        recs = generate_recommendations(infra, _make_org_all_ja(), _make_network())
        priorities = [r.priority for r in recs]
        assert PRIO_KRITISCH in priorities

    def test_no_encryption_generates_kritisch(self):
        infra = _make_infra(verschluesselung=[])
        recs = generate_recommendations(infra, _make_org_all_ja(), _make_network())
        assert any(r.priority == PRIO_KRITISCH for r in recs)

    def test_backup_nein_generates_kritisch(self):
        org = OrganizationalData(backup_strategie="Nein")
        recs = generate_recommendations(_make_infra(), org, _make_network())
        assert any("Backup" in r.title for r in recs)

    def test_open_wlan_generates_kritisch(self):
        net = _make_network(wlan="Offen")
        recs = generate_recommendations(_make_infra(), _make_org_all_ja(), net)
        assert any(r.priority == PRIO_KRITISCH for r in recs)

    def test_sorted_by_priority(self):
        infra = _make_infra(av_status="inaktiv", verschluesselung=[])
        org = _make_org_all_nein()
        net = _make_network(wlan="Offen", pentest="Nie")
        recs = generate_recommendations(infra, org, net)
        priorities = [r.priority for r in recs]
        order = {"Kritisch": 0, "Hoch": 1, "Mittel": 2, "Niedrig": 3}
        ordered = sorted(priorities, key=lambda p: order.get(p, 99))
        assert priorities == ordered

    def test_recommendations_as_strings_returns_list_of_str(self):
        recs = recommendations_as_strings(
            _make_infra(), _make_org_all_ja(), _make_network()
        )
        assert all(isinstance(r, str) for r in recs)

    def test_perfect_setup_no_kritisch_recommendations(self):
        infra = _make_infra(
            av_status="aktiv",
            fw_status="aktiv",
            verschluesselung=["BitLocker"],
            remote_tools=["SSH"],
        )
        org = _make_org_all_ja()
        net = _make_network(wlan="WPA3", pentest="2025")
        recs = generate_recommendations(infra, org, net)
        assert all(r.priority != PRIO_KRITISCH for r in recs)

    def test_risky_remote_tools_recommendation(self):
        infra = _make_infra(remote_tools=["TeamViewer", "AnyDesk"])
        recs = generate_recommendations(infra, _make_org_all_ja(), _make_network())
        assert any("Remote-Access" in r.title for r in recs)

    def test_avv_key_storage_nein_erzeugt_recommendation(self):
        # 3f-ii: avv_key_separate_storage=Nein → eine organisatorische
        # Encryption-Audit-Empfehlung mit "Schluessel" im Titel.
        org = OrganizationalData(
            zugangskontrollen="Ja",
            backup_strategie="Ja",
            update_management="Ja",
            mitarbeitersensibilisierung="Ja",
            incident_response_plan="Ja",
            dsgvo_konformitaet="Ja",
            avv_key_separate_storage="Nein",
        )
        recs = generate_recommendations(_make_infra(), org, _make_network())
        key_recs = [r for r in recs if "Schluessel" in r.title]
        assert len(key_recs) == 1
        assert "getrennt" in key_recs[0].title.lower()

    def test_wpa2_generates_niedrig_recommendation(self):
        net = _make_network(wlan="WPA2")
        recs = generate_recommendations(_make_infra(), _make_org_all_ja(), net)
        assert any("WPA3" in r.title for r in recs)

    def test_teilweise_generates_mittel_recommendation(self):
        org = OrganizationalData(
            backup_strategie="Teilweise",
            zugangskontrollen="Ja",
            update_management="Ja",
            mitarbeitersensibilisierung="Ja",
            incident_response_plan="Ja",
            dsgvo_konformitaet="Ja",
        )
        recs = generate_recommendations(_make_infra(), org, _make_network())
        assert any(r.priority == PRIO_MITTEL for r in recs)


# ---------------------------------------------------------------------------
# Tests: CustomerAuditResult round-trip
# ---------------------------------------------------------------------------


class TestCustomerAuditResultRoundTrip:
    def _make_result(self) -> CustomerAuditResult:
        return CustomerAuditResult(
            audit_id=str(uuid.uuid4()),
            customer_data=_make_customer_data(),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            category_scores=[
                CategoryScore(name="IT-Infrastruktur", score=90.0, label="Niedrig")
            ],
            overall_score=85.0,
            risk_level="Niedrig",
            recommendations=["Empfehlung 1"],
            created_at="2026-04-06T12:00:00+00:00",
        )

    def test_to_dict_contains_all_keys(self):
        result = self._make_result()
        d = result.to_dict()
        for key in [
            "audit_id",
            "customer_data",
            "infrastructure_data",
            "organizational_data",
            "network_data",
            "category_scores",
            "overall_score",
            "risk_level",
            "recommendations",
            "created_at",
        ]:
            assert key in d

    def test_round_trip_preserves_data(self):
        result = self._make_result()
        restored = CustomerAuditResult.from_dict(result.to_dict())
        assert restored.audit_id == result.audit_id
        assert restored.overall_score == result.overall_score
        assert restored.risk_level == result.risk_level
        assert restored.customer_data.firmenname == result.customer_data.firmenname
        assert len(restored.category_scores) == 1

    def test_json_serializable(self):
        result = self._make_result()
        json_str = json.dumps(result.to_dict(), ensure_ascii=False)
        parsed = json.loads(json_str)
        assert parsed["overall_score"] == 85.0

    def test_from_dict_empty_gives_defaults(self):
        result = CustomerAuditResult.from_dict({})
        assert result.audit_id == ""
        assert result.risk_level == "Kritisch"
        assert result.category_scores == []


# ---------------------------------------------------------------------------
# Tests: CreateAuditUseCase
# ---------------------------------------------------------------------------


class TestCreateAuditUseCase:
    def test_execute_returns_result(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )

        repo = MagicMock()
        use_case = CreateAuditUseCase(repo)
        result = use_case.execute(
            customer_data=_make_customer_data(),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
        )
        assert isinstance(result, CustomerAuditResult)
        assert result.overall_score > 0.0
        assert result.risk_level in ("Niedrig", "Mittel", "Hoch", "Kritisch")
        # Bei Default-Audits (Backup/Sov/IR=0)
        # werden die optionalen Kategorien NICHT in category_scores
        # aufgenommen — Liste enthaelt also die 3 Pflicht-Kategorien.
        assert len(result.category_scores) == 3

    def test_execute_calls_repository_save(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )

        repo = MagicMock()
        use_case = CreateAuditUseCase(repo)
        use_case.execute(
            customer_data=_make_customer_data(),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
        )
        repo.save.assert_called_once()

    def test_execute_continues_if_save_fails(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )

        repo = MagicMock()
        repo.save.side_effect = RuntimeError("DB-Fehler")
        use_case = CreateAuditUseCase(repo)
        # Kein Fehler propagiert
        result = use_case.execute(
            customer_data=_make_customer_data(),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
        )
        assert result is not None

    def test_result_has_uuid(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )

        repo = MagicMock()
        use_case = CreateAuditUseCase(repo)
        result = use_case.execute(
            customer_data=_make_customer_data(),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
        )
        # Sollte gültige UUID sein
        assert len(result.audit_id) == 36
        assert result.audit_id.count("-") == 4


# ---------------------------------------------------------------------------
# Tests: CreateAuditUseCase — Subjekt-Verknüpfung, Step 4)
# ---------------------------------------------------------------------------


class _FakeSubjectStore:
    """Duck-typed SubjectStore-Fake für die Audit-Subjekt-Verknüpfung."""

    def __init__(self) -> None:
        self.clients: dict[str, str] = {}
        self.stammdaten: list[tuple] = []
        self.self_name: str | None = None

    def ensure_self_subject(self, name):  # noqa: ANN001, ANN202
        from core.security_subject.models import Subject, SubjectKind

        self.self_name = name
        return Subject(subject_id="self-1", kind=SubjectKind.EIGENES, name=name)

    def find_or_create_client(self, name):  # noqa: ANN001, ANN202
        from core.security_subject.models import Subject, SubjectKind

        sid = self.clients.setdefault(name, f"client-{len(self.clients) + 1}")
        return Subject(subject_id=sid, kind=SubjectKind.KUNDE, name=name)

    def update_stammdaten(  # noqa: ANN201
        self, subject_id, *, branche=None, groesse=None, contact=None  # noqa: ANN001
    ):
        self.stammdaten.append((subject_id, branche, groesse, contact))


class TestCreateAuditUseCaseSubjectT294:
    """ Step 4: find-or-create Subject beim Audit-Save (Live-Pfad)."""

    def test_customer_audit_creates_client_subject(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode

        store = _FakeSubjectStore()
        use_case = CreateAuditUseCase(MagicMock(), subject_store=store)
        result = use_case.execute(
            customer_data=_make_customer_data("Acme GmbH"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.CUSTOMER,
        )
        assert result.subject_id == "client-1"
        # branche/groesse/Ansprechpartner wurden ins Subjekt gezogen.
        assert store.stammdaten == [("client-1", "IT", "11-50", "Max Mustermann")]

    def test_self_audit_uses_self_subject(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode

        store = _FakeSubjectStore()
        use_case = CreateAuditUseCase(MagicMock(), subject_store=store)
        result = use_case.execute(
            customer_data=_make_customer_data("Meine Firma"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.SELF,
        )
        assert result.subject_id == "self-1"

    def test_without_store_subject_id_empty(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )

        use_case = CreateAuditUseCase(MagicMock())
        result = use_case.execute(
            customer_data=_make_customer_data(),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
        )
        assert result.subject_id == ""

    def test_subject_failure_is_fail_soft(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode

        store = MagicMock()
        store.find_or_create_client.side_effect = RuntimeError("DB weg")
        use_case = CreateAuditUseCase(MagicMock(), subject_store=store)
        result = use_case.execute(
            customer_data=_make_customer_data("Acme GmbH"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.CUSTOMER,
        )
        # Audit wird trotzdem erstellt; subject_id bleibt leer (fail-soft).
        assert result is not None
        assert result.subject_id == ""


# ---------------------------------------------------------------------------
# Tests: Mode-Gate — Kunden-Audit ohne Eigenscan Phase 1)
# ---------------------------------------------------------------------------


def _backup_with_detection() -> object:
    from tools.customer_audit.domain.entities import BackupAuditResult

    return BackupAuditResult(detection_enabled=True)


def _backup_with_detected_tools() -> object:
    from tools.customer_audit.domain.entities import BackupAuditResult

    # Detektion-Flag aus, aber Scan-Treffer vorhanden — zaehlt als Scan-Daten.
    return BackupAuditResult(detection_enabled=False, detected_tools=["Veeam Agent"])


def _sovereignty_with_detection() -> object:
    from tools.customer_audit.domain.entities import SovereigntyAuditResult

    return SovereigntyAuditResult(detection_enabled=True)


def _sovereignty_with_detected() -> object:
    from tools.customer_audit.domain.entities import (
        DetectedProvider,
        SovereigntyAuditResult,
    )

    return SovereigntyAuditResult(
        detection_enabled=False,
        detected=[
            DetectedProvider(
                name="Microsoft 365",
                status="eu_boundary",
                category="saas_other",
                via="dns_mx",
                evidence="mx: outlook.com",
            )
        ],
    )


class TestAuditModeGateFunction:
    """Reine Domain-Invariante:func:`assert_customer_audit_has_no_scan_data`."""

    def test_self_mode_allows_scan_data(self):
        from tools.customer_audit.domain.entities import AuditMode
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        # SELF darf gemessene Scan-Daten tragen — kein Fehler.
        assert_customer_audit_has_no_scan_data(
            AuditMode.SELF,
            _backup_with_detection(),
            _sovereignty_with_detection(),
        )

    def test_customer_clean_passes(self):
        from tools.customer_audit.domain.entities import (
            AuditMode,
            BackupAuditResult,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        # CUSTOMER ohne Scan-Daten = normaler Fragebogen-Pfad — kein Fehler.
        assert_customer_audit_has_no_scan_data(
            AuditMode.CUSTOMER, BackupAuditResult(), SovereigntyAuditResult()
        )

    def test_customer_declared_and_domain_allowed(self):
        from tools.customer_audit.domain.entities import (
            AuditMode,
            BackupAuditResult,
            DetectedProvider,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        # Selbst-deklarierte Provider + eingegebene Domain sind KEINE Scan-Daten.
        sov = SovereigntyAuditResult(
            detection_enabled=False,
            domain="kanzlei-mueller.at",
            declared=[
                DetectedProvider(
                    name="DATEV",
                    status="eu_sovereign",
                    category="saas_other",
                    via="self_declared",
                    evidence="",
                )
            ],
        )
        assert_customer_audit_has_no_scan_data(
            AuditMode.CUSTOMER, BackupAuditResult(), sov
        )

    def test_customer_backup_detection_raises(self):
        from tools.customer_audit.domain.entities import (
            AuditMode,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError):
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                _backup_with_detection(),
                SovereigntyAuditResult(),
            )

    def test_customer_backup_detected_tools_raises(self):
        from tools.customer_audit.domain.entities import (
            AuditMode,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError):
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                _backup_with_detected_tools(),
                SovereigntyAuditResult(),
            )

    def test_customer_sovereignty_detection_raises(self):
        from tools.customer_audit.domain.entities import (
            AuditMode,
            BackupAuditResult,
        )
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError):
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                BackupAuditResult(),
                _sovereignty_with_detection(),
            )

    def test_customer_sovereignty_detected_raises(self):
        from tools.customer_audit.domain.entities import (
            AuditMode,
            BackupAuditResult,
        )
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError):
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                BackupAuditResult(),
                _sovereignty_with_detected(),
            )

    def test_customer_backup_last_runs_raises(self):
        # last_successful_runs ist ein reines Detektor-Artefakt -> Verstoss.
        from tools.customer_audit.domain.entities import (
            AuditMode,
            BackupAuditResult,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError):
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                BackupAuditResult(last_successful_runs={"Veeam": "2026-06-27"}),
                SovereigntyAuditResult(),
            )

    def test_customer_sovereignty_scan_errors_raises(self):
        # scan_errors stammen aus dem DNS-/Netz-Scan des Beraterrechners.
        from tools.customer_audit.domain.entities import (
            AuditMode,
            BackupAuditResult,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError):
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                BackupAuditResult(),
                SovereigntyAuditResult(scan_errors=["DNS-Lookup fehlgeschlagen"]),
            )

    def test_customer_rechtshinweise_alone_allowed(self):
        # rechtshinweise werden auch aus declared abgeleitet -> kein Scan-Artefakt.
        from tools.customer_audit.domain.entities import (
            AuditMode,
            BackupAuditResult,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        assert_customer_audit_has_no_scan_data(
            AuditMode.CUSTOMER,
            BackupAuditResult(),
            SovereigntyAuditResult(rechtshinweise=["M365 ohne BYOK -> §43e BRAO"]),
        )

    def test_customer_both_scanners_message_lists_both(self):
        from tools.customer_audit.domain.entities import AuditMode
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError) as exc_info:
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                _backup_with_detection(),
                _sovereignty_with_detection(),
            )
        msg = str(exc_info.value)
        assert "Backup-Detektion" in msg
        assert "Souveränitäts-Scan" in msg

    def test_unknown_mode_fails_closed(self):
        # Fail-safe Default: nur SELF ist ausgenommen — ein nicht-SELF-Modus mit
        # Scan-Daten wird geblockt (Schutz gegen kuenftige Modi). Wir simulieren
        # das ueber CUSTOMER, da heute nur zwei Modi existieren; der Guard prueft
        # explizit `is SELF`, nicht `is not CUSTOMER`.
        from tools.customer_audit.domain.entities import (
            AuditMode,
            SovereigntyAuditResult,
        )
        from tools.customer_audit.domain.exceptions import AuditModeViolationError
        from tools.customer_audit.domain.mode_gate import (
            assert_customer_audit_has_no_scan_data,
        )

        with pytest.raises(AuditModeViolationError):
            assert_customer_audit_has_no_scan_data(
                AuditMode.CUSTOMER,
                _backup_with_detection(),
                SovereigntyAuditResult(),
            )


class TestCreateAuditUseCaseModeGate:
    """: CUSTOMER+Scanner failt im Use Case, SELF/clean bleiben gruen."""

    def test_customer_with_scan_data_raises_and_does_not_save(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode
        from tools.customer_audit.domain.exceptions import AuditModeViolationError

        repo = MagicMock()
        use_case = CreateAuditUseCase(repo)
        with pytest.raises(AuditModeViolationError):
            use_case.execute(
                customer_data=_make_customer_data("Acme GmbH"),
                infrastructure_data=_make_infra(),
                organizational_data=_make_org_all_ja(),
                network_data=_make_network(),
                audit_mode=AuditMode.CUSTOMER,
                backup_audit=_backup_with_detection(),
            )
        repo.save.assert_not_called()

    def test_self_with_scan_data_ok(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode

        repo = MagicMock()
        use_case = CreateAuditUseCase(repo)
        result = use_case.execute(
            customer_data=_make_customer_data("Meine Firma"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.SELF,
            backup_audit=_backup_with_detection(),
            sovereignty_audit=_sovereignty_with_detection(),
        )
        assert result is not None
        repo.save.assert_called_once()

    def test_customer_clean_still_saves(self):
        from tools.customer_audit.application.create_audit_use_case import (
            CreateAuditUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode

        repo = MagicMock()
        use_case = CreateAuditUseCase(repo)
        result = use_case.execute(
            customer_data=_make_customer_data("Acme GmbH"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.CUSTOMER,
        )
        assert result is not None
        repo.save.assert_called_once()


class TestCreateVersionUseCaseModeGate:
    """: das Gate greift auch beim Versionieren eines Kunden-Audits."""

    def test_customer_version_with_scan_data_raises_and_does_not_persist(self):
        from tools.customer_audit.application.create_version_use_case import (
            CreateVersionUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode
        from tools.customer_audit.domain.exceptions import AuditModeViolationError

        base = CustomerAuditResult(
            audit_id="base-1",
            customer_data=_make_customer_data("Acme GmbH"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.CUSTOMER,
        )
        repo = MagicMock()
        repo.load_by_id.return_value = base
        use_case = CreateVersionUseCase(repo)
        with pytest.raises(AuditModeViolationError):
            use_case.execute(
                "base-1",
                _make_customer_data("Acme GmbH"),
                _make_infra(),
                _make_org_all_ja(),
                _make_network(),
                audit_mode=AuditMode.CUSTOMER,
                sovereignty_audit=_sovereignty_with_detected(),
            )
        repo.save.assert_not_called()
        repo.mark_superseded.assert_not_called()

    def test_self_version_with_scan_data_ok(self):
        from tools.customer_audit.application.create_version_use_case import (
            CreateVersionUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode

        base = CustomerAuditResult(
            audit_id="base-1",
            customer_data=_make_customer_data("Meine Firma"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.SELF,
        )
        repo = MagicMock()
        repo.load_by_id.return_value = base
        use_case = CreateVersionUseCase(repo)
        result = use_case.execute(
            "base-1",
            _make_customer_data("Meine Firma"),
            _make_infra(),
            _make_org_all_ja(),
            _make_network(),
            audit_mode=AuditMode.SELF,
            backup_audit=_backup_with_detection(),
        )
        assert result is not None
        repo.save.assert_called_once()
        repo.mark_superseded.assert_called_once()

    def test_customer_version_clean_saves_and_supersedes(self):
        # Happy-Path: das Gate darf den sauberen Versions-Save nicht blockieren.
        from tools.customer_audit.application.create_version_use_case import (
            CreateVersionUseCase,
        )
        from tools.customer_audit.domain.entities import AuditMode

        base = CustomerAuditResult(
            audit_id="base-1",
            customer_data=_make_customer_data("Acme GmbH"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            audit_mode=AuditMode.CUSTOMER,
        )
        repo = MagicMock()
        repo.load_by_id.return_value = base
        use_case = CreateVersionUseCase(repo)
        result = use_case.execute(
            "base-1",
            _make_customer_data("Acme GmbH"),
            _make_infra(),
            _make_org_all_ja(),
            _make_network(),
            audit_mode=AuditMode.CUSTOMER,
        )
        assert result is not None
        repo.save.assert_called_once()
        repo.mark_superseded.assert_called_once()


# ---------------------------------------------------------------------------
# Tests: LoadAuditUseCase
# ---------------------------------------------------------------------------


class TestLoadAuditUseCase:
    def test_get_all_summaries_delegates_to_repo(self):
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.list_summaries.return_value = [{"id": "1", "firmenname": "Firma"}]
        use_case = LoadAuditUseCase(repo)
        result = use_case.get_all_summaries()
        repo.list_summaries.assert_called_once_with(limit=50)
        assert len(result) == 1

    def test_get_by_id_delegates_to_repo(self):
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.load_by_id.return_value = None
        use_case = LoadAuditUseCase(repo)
        result = use_case.get_by_id("test-id")
        repo.load_by_id.assert_called_once_with("test-id")
        assert result is None

    def test_delete_anonymizes_whole_chain_then_deletes(self):
        # P1-Kaskade: anonymisiert ALLE Ketten-audit_ids ZUERST, loescht DANN.
        from unittest.mock import patch

        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.list_chain_audit_ids.return_value = ["root-1", "v2-2"]
        repo.delete.return_value = True
        use_case = LoadAuditUseCase(repo)
        with patch(
            "tools.customer_audit.application.nis2_incident_service."
            "Nis2IncidentService"
        ) as svc_cls:
            svc = svc_cls.return_value
            assert use_case.delete("v2-2") is True
            # Anonymisierung lief ueber JEDE Ketten-audit_id.
            anon_calls = [c.args[0] for c in svc.anonymize_for_audit.call_args_list]
            assert sorted(anon_calls) == ["root-1", "v2-2"]
        repo.delete.assert_called_once_with("v2-2")

    def test_delete_unknown_audit_returns_false_without_anonymize(self):
        from unittest.mock import patch

        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.list_chain_audit_ids.return_value = []
        use_case = LoadAuditUseCase(repo)
        with patch(
            "tools.customer_audit.application.nis2_incident_service."
            "Nis2IncidentService"
        ) as svc_cls:
            assert use_case.delete("ghost") is False
            svc_cls.assert_not_called()
        repo.delete.assert_not_called()

    def test_delete_fail_loud_does_not_delete_on_anonymize_error(self):
        # P2-delete-Reihenfolge fail-LOUD: Anonymisierungs-Fehler verhindert die
        # Loeschung (kein stiller PII-Rest) und propagiert.
        from unittest.mock import patch

        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.list_chain_audit_ids.return_value = ["root-1"]
        use_case = LoadAuditUseCase(repo)
        with patch(
            "tools.customer_audit.application.nis2_incident_service."
            "Nis2IncidentService"
        ) as svc_cls:
            svc_cls.return_value.anonymize_for_audit.side_effect = RuntimeError(
                "boom"
            )
            with pytest.raises(RuntimeError, match="boom"):
                use_case.delete("root-1")
        repo.delete.assert_not_called()

    def test_delete_version_anonymizes_only_this_audit(self):
        # I (Live-Test 2026-07-01): Einzelversion-Loeschen anonymisiert NUR
        # diese audit_id (nicht die Kette) und ruft delete_version, NICHT delete.
        from types import SimpleNamespace
        from unittest.mock import patch

        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.load_by_id.return_value = SimpleNamespace(subject_id="")
        repo.delete_version.return_value = True
        use_case = LoadAuditUseCase(repo)
        with patch(
            "tools.customer_audit.application.nis2_incident_service."
            "Nis2IncidentService"
        ) as svc_cls:
            svc = svc_cls.return_value
            assert use_case.delete_version("v2") is True
            svc.anonymize_for_audit.assert_called_once_with("v2")
        repo.delete_version.assert_called_once_with("v2")
        repo.delete.assert_not_called()  # NICHT der Ketten-Loeschpfad

    def test_delete_version_unknown_returns_false(self):
        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.load_by_id.return_value = None
        use_case = LoadAuditUseCase(repo)
        assert use_case.delete_version("ghost") is False
        repo.delete_version.assert_not_called()

    def test_delete_version_fail_loud_on_anonymize_error(self):
        # fail-LOUD: Anonymisierungs-Fehler verhindert die Einzel-Loeschung.
        from types import SimpleNamespace
        from unittest.mock import patch

        from tools.customer_audit.application.load_audit_use_case import (
            LoadAuditUseCase,
        )

        repo = MagicMock()
        repo.load_by_id.return_value = SimpleNamespace(subject_id="s1")
        use_case = LoadAuditUseCase(repo)
        with patch(
            "tools.customer_audit.application.nis2_incident_service."
            "Nis2IncidentService"
        ) as svc_cls:
            svc_cls.return_value.anonymize_for_audit.side_effect = RuntimeError(
                "boom"
            )
            with pytest.raises(RuntimeError, match="boom"):
                use_case.delete_version("v2")
        repo.delete_version.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: ExportAuditUseCase
# ---------------------------------------------------------------------------


class TestExportAuditUseCase:
    def _make_result(self) -> CustomerAuditResult:
        return CustomerAuditResult(
            audit_id="test-123",
            customer_data=_make_customer_data("ExportFirma"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
            overall_score=75.0,
            risk_level="Niedrig",
        )

    def test_export_json_creates_file(self, tmp_path: Path):
        from tools.customer_audit.application.export_audit_use_case import (
            ExportAuditUseCase,
        )

        use_case = ExportAuditUseCase()
        result = self._make_result()
        target = tmp_path / "test_export.json"
        saved = use_case.export_json(result, target)
        assert saved.exists()
        parsed = json.loads(saved.read_text(encoding="utf-8"))
        assert parsed["overall_score"] == 75.0
        assert parsed["customer_data"]["firmenname"] == "ExportFirma"

    def test_build_report_data_structure(self):
        from tools.customer_audit.application.export_audit_use_case import (
            ExportAuditUseCase,
        )

        use_case = ExportAuditUseCase()
        result = self._make_result()
        data = use_case.build_report_data(result)
        assert data["type"] == "customer_audit"
        assert data["company"] == "ExportFirma"
        assert data["overall_score"] == 75.0
        assert "category_scores" in data
        assert "details" in data
        assert "customer" in data["details"]

    def test_export_json_valid_utf8(self, tmp_path: Path):
        from tools.customer_audit.application.export_audit_use_case import (
            ExportAuditUseCase,
        )

        use_case = ExportAuditUseCase()
        result = CustomerAuditResult(
            audit_id="utf8-test",
            customer_data=CustomerData(firmenname="Österreichische Müller GmbH"),
            infrastructure_data=_make_infra(),
            organizational_data=_make_org_all_ja(),
            network_data=_make_network(),
        )
        target = tmp_path / "utf8_test.json"
        use_case.export_json(result, target)
        content = target.read_text(encoding="utf-8")
        assert "Österreichische" in content
