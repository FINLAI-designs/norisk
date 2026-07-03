"""Tests für ``tools.mainpage.application.ki_todo_service`` (Sprint S2a).

End-to-End-Tests: rohe Findings → KiTodoService → erzeugte Tasks.
Dedup-Sicherheit, Storytelling-Integration, Klassifikator-Routing.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.database.db_context import clear_db_app_id
from core.rules.models import ClassifierHint, Rule, RuleMatch
from core.rules.rule_engine import RuleEngine
from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity
from tools.mainpage.application.journal_service import JournalService
from tools.mainpage.application.ki_todo_service import (
    KiTodoService,
    compute_dedup_key,
)
from tools.mainpage.application.task_service import TaskService
from tools.mainpage.data.mainpage_repository import MainpageRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_db_context():
    """Setzt den App-Kontext der DB-Schicht zwischen Tests zurück."""
    clear_db_app_id()
    yield
    clear_db_app_id()


@pytest.fixture
def isolated_db_dir(tmp_path: Path):
    """Patcht ``DB_DIR`` auf ein temporäres Verzeichnis."""
    with patch("core.database.encrypted_db.DB_DIR", tmp_path):
        yield tmp_path


@pytest.fixture
def task_service(isolated_db_dir: Path) -> TaskService:
    """Baut einen TaskService mit frischer Repo-Instanz."""
    repo = MainpageRepository()
    journal = JournalService(repo)
    return TaskService(repo, journal)


@pytest.fixture
def cert_engine() -> RuleEngine:
    """Engine mit einer minimalen Cert-Regel."""
    rule = Rule(
        id="cert_expiring",
        match=RuleMatch(
            tool="cert_monitor",
            finding_type="cert_expiring",
            min_severity=Severity.LOW,
        ),
        classifier_hint=ClassifierHint(
            asset_count=1, action_keywords=["renew"]
        ),
    )
    return RuleEngine([rule])


def _cert_finding(evidence_id: str = "cert-1") -> FindingInput:
    return FindingInput(
        tool="cert_monitor",
        finding_type="cert_expiring",
        severity=Severity.HIGH,
        subject="example.com",
        evidence_id=evidence_id,
        details={"days_left": 5, "expires_at": "2026-05-04"},
    )


# ---------------------------------------------------------------------------
# evaluate_findings — End-to-End
# ---------------------------------------------------------------------------


def test_evaluate_findings_erzeugt_task_mit_korrekten_feldern(
    task_service: TaskService, cert_engine: RuleEngine
):
    """Rohes Finding → Task mit Headline aus Storytelling + Urgency aus Klassifikator."""
    service = KiTodoService(task_service, cert_engine)
    tasks = service.evaluate_findings([_cert_finding()])

    assert len(tasks) == 1
    task = tasks[0]
    assert task.urgency == "quick"
    assert task.source == "auto"
    assert task.source_tool == "cert_monitor"
    assert "Zertifikat" in task.title
    assert task.evidence_refs == [
        {"tool": "cert_monitor", "finding_id": "cert-1"}
    ]
    # Description = Storytelling-Erklärung + Aktion
    assert "Let's Encrypt" in task.description


def test_evaluate_findings_ohne_match_kein_task(
    task_service: TaskService, cert_engine: RuleEngine
):
    """Findings ohne passende Regel werden übersprungen (kein Task)."""
    service = KiTodoService(task_service, cert_engine)
    other = FindingInput(
        tool="api_security",  # Engine kennt nur cert_monitor
        finding_type="missing_security_header",
        severity=Severity.HIGH,
        subject="api.example.de",
        evidence_id="api-1",
        details={
            "header_name": "Content-Security-Policy",
            "recommended_value": "default-src 'self'",
            "risk": "Cross-Site-Scripting-Angriffen",
        },
    )
    tasks = service.evaluate_findings([other])
    assert tasks == []


def test_evaluate_findings_dedup_pro_evidence(
    task_service: TaskService, cert_engine: RuleEngine
):
    """Doppelter Aufruf mit identischem Finding erzeugt **eine** Task."""
    service = KiTodoService(task_service, cert_engine)
    tasks_a = service.evaluate_findings([_cert_finding(evidence_id="cert-7")])
    tasks_b = service.evaluate_findings([_cert_finding(evidence_id="cert-7")])

    assert len(tasks_a) == 1
    assert len(tasks_b) == 1
    # Dedup: dieselbe Task-ID
    assert tasks_a[0].id == tasks_b[0].id


def test_evaluate_findings_unterschiedliche_evidence_ids_neue_tasks(
    task_service: TaskService, cert_engine: RuleEngine
):
    """Zwei Findings mit unterschiedlicher evidence_id ergeben zwei Tasks."""
    service = KiTodoService(task_service, cert_engine)
    findings = [
        _cert_finding(evidence_id="cert-A"),
        _cert_finding(evidence_id="cert-B"),
    ]
    tasks = service.evaluate_findings(findings)
    assert len(tasks) == 2
    assert tasks[0].id != tasks[1].id


def test_evaluate_findings_template_fehlt_loggt_und_skippt(
    task_service: TaskService,
):
    """Regel matcht, aber Storytelling-Template fehlt → Skip ohne Crash."""
    rule = Rule(
        id="r-fehlt",
        match=RuleMatch(
            tool="password_checker", finding_type="weak_password"
        ),
    )
    engine = RuleEngine([rule])
    service = KiTodoService(task_service, engine)
    finding = FindingInput(
        tool="password_checker",
        finding_type="weak_password",
        severity=Severity.MEDIUM,
        subject="admin@example.com",
        evidence_id="pw-1",
    )
    tasks = service.evaluate_findings([finding])
    assert tasks == []


# ---------------------------------------------------------------------------
# Default-Regeln aus configs/rules/
# ---------------------------------------------------------------------------


def test_for_default_rules_laedt_alle_regeln(task_service: TaskService):
    """Convenience-Builder findet alle Default-Regeln im Repo.

    Beim Hinzufuegen einer neuen Regel-yaml in ``configs/rules/`` muss
    die erwartete Zahl angepasst werden — der Drift-Test fungiert als
    Hinweis dass neue Rules registriert wurden:

    * ergaenzt ``hardening.yaml`` (+1 Regel) → 11
    * ergaenzt ``patch_monitor.yaml`` (+5 Regeln) → 16
    *-ii ergaenzt ``supply_chain_monitor.yaml`` (+2 Regeln) → 18
    * ergaenzt ``network_monitor.yaml`` (+6 Regeln) → 24
    """
    service = KiTodoService.for_default_rules(task_service)
    assert service._engine.rule_count() == 24  # noqa: SLF001


def test_default_regeln_treffen_cert_expiring(task_service: TaskService):
    """Default-Cert-Regel matcht ein klassisches cert_expiring-Finding."""
    service = KiTodoService.for_default_rules(task_service)
    tasks = service.evaluate_findings([_cert_finding()])
    assert len(tasks) == 1
    assert tasks[0].urgency == "quick"


def test_default_regeln_treffen_dependency_vulnerable_package(
    task_service: TaskService,
):
    """Default-Dependency-Regel matcht und produziert Quick-Win."""
    service = KiTodoService.for_default_rules(task_service)
    finding = FindingInput(
        tool="dependency_auditor",
        finding_type="vulnerable_package",
        severity=Severity.HIGH,
        subject="requests",
        evidence_id="dep-1",
        details={
            "package": "requests",
            "version": "2.30.0",
            "cve_id": "CVE-2024-1234",
            "summary": "Header-Injection",
            "fixed_version": "2.32.5",
        },
    )
    tasks = service.evaluate_findings([finding])
    assert len(tasks) == 1
    assert tasks[0].urgency == "quick"
    assert "requests" in tasks[0].title


# ---------------------------------------------------------------------------
# compute_dedup_key
# ---------------------------------------------------------------------------


def test_compute_dedup_key_deterministisch():
    """Gleiche Eingabe → gleicher Hash."""
    a = compute_dedup_key("cert_monitor", "cert_expiring", "cert-1")
    b = compute_dedup_key("cert_monitor", "cert_expiring", "cert-1")
    assert a == b
    assert len(a) == 64  # SHA-256 Hex


def test_compute_dedup_key_unterscheidet_evidence():
    """Unterschiedliche evidence_id → unterschiedlicher Hash."""
    a = compute_dedup_key("cert_monitor", "cert_expiring", "cert-1")
    b = compute_dedup_key("cert_monitor", "cert_expiring", "cert-2")
    assert a != b


def test_compute_dedup_key_unterscheidet_tools():
    """Unterschiedliches Tool → unterschiedlicher Hash."""
    a = compute_dedup_key("cert_monitor", "cert_expiring", "x")
    b = compute_dedup_key("api_security", "cert_expiring", "x")
    assert a != b
