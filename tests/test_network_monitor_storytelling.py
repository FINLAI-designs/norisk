"""Tests fuer die network_monitor-Storytelling-Integration E).

Deckt ab: Template-Rendering aller 6 Anomalie-Typen (build_story), Rule-Matching
(configs/rules/network_monitor.yaml), AnomalyService.detect_and_emit-Verdrahtung,
und die volle Pipeline (Finding → Rule → Template → KI-Todo-Task).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.rules.rule_engine import RuleEngine
from core.storytelling.narrative_builder import build_story
from core.storytelling.schemas import FindingInput
from core.vulnerability.domain.severity import Severity
from tools.network_monitor.application.anomaly_detector import AnomalyService
from tools.network_monitor.application.storytelling_adapter import (
    anomalies_to_findings,
)
from tools.network_monitor.domain.models import (
    Anomaly,
    AnomalySeverity,
    AnomalyType,
)

_RULES_DIR = Path(__file__).resolve().parents[1] / "configs" / "rules"


def _anom(
    atype: AnomalyType,
    sev: AnomalySeverity = AnomalySeverity.HIGH,
    value: int = 2_000_000_000,
    ip: str = "8.8.8.8",
    detail: str = r"C:\Users\x\AppData\Local\Temp\evil.exe",
) -> Anomaly:
    return Anomaly(
        anomaly_type=atype,
        severity=sev,
        pid=1234,
        process_name="evil.exe",
        value_bytes=value,
        threshold_bytes=1,
        remote_ip=ip,
        detail=detail,
    )


class TestTemplates:
    @pytest.mark.parametrize("atype", list(AnomalyType))
    def test_build_story_fuer_jeden_typ(self, atype: AnomalyType) -> None:
        findings = anomalies_to_findings([_anom(atype)])
        assert len(findings) == 1
        story = build_story(findings[0])  # darf nicht TemplateNotFound/Validation werfen
        assert story.headline
        assert story.explanation
        assert story.action
        assert "evil.exe" in story.headline or "evil.exe" in story.explanation


class TestRules:
    def test_network_finding_matcht_regel(self) -> None:
        engine = RuleEngine.from_directory(_RULES_DIR)
        finding = anomalies_to_findings([_anom(AnomalyType.SINGLE_IP)])[0]
        actions = engine.evaluate(finding)
        assert len(actions) >= 1

    def test_alle_sechs_finding_types_matchen(self) -> None:
        engine = RuleEngine.from_directory(_RULES_DIR)
        for atype in AnomalyType:
            finding = anomalies_to_findings([_anom(atype)])[0]
            assert engine.evaluate(finding), f"keine Regel fuer {finding.finding_type}"

    def test_fremder_tool_finding_matcht_nicht(self) -> None:
        engine = RuleEngine.from_directory(_RULES_DIR)
        finding = FindingInput(
            tool="network_monitor",
            finding_type="gibt_es_nicht",
            severity=Severity.HIGH,
            subject="x",
            evidence_id="x",
            details={},
        )
        assert engine.evaluate(finding) == []


class _FakeRepo:
    def outbound_per_process_since(self, cutoff_ts):  # noqa: ANN001, ARG002
        return []

    def offhours_outbound_per_process(self, cutoff_ts):  # noqa: ANN001, ARG002
        return []

    def traffic_per_remote_ip_since(self, cutoff_ts):  # noqa: ANN001, ARG002
        from tools.network_monitor.domain.models import RemoteIpTraffic

        return [
            RemoteIpTraffic(
                pid=1,
                process_name="evil.exe",
                remote_ip="8.8.8.8",
                bytes_sent=11_000_000_000,
                bytes_recv=0,
            )
        ]


class _FakeEmitter:
    def __init__(self) -> None:
        self.received: list | None = None

    def emit(self, findings) -> None:  # noqa: ANN001
        self.received = list(findings)


class TestDetectAndEmit:
    def test_detect_and_emit_verdrahtung(self) -> None:
        emitter = _FakeEmitter()
        service = AnomalyService(_FakeRepo())
        anomalies, emitted = service.detect_and_emit(now=1_000_000.0, emitter=emitter)
        assert len(anomalies) == 1
        assert emitted == 1
        assert emitter.received is not None
        assert emitter.received[0].tool == "network_monitor"


class TestFullPipeline:
    def test_finding_wird_zu_kitodo_task(self) -> None:
        # Voller Pfad: Finding → Rule → Template → Task (DB via conftest isoliert).
        from tools.mainpage.application.journal_service import JournalService
        from tools.mainpage.application.ki_todo_service import KiTodoService
        from tools.mainpage.application.task_service import TaskService
        from tools.mainpage.data.mainpage_repository import MainpageRepository

        repo = MainpageRepository()
        service = KiTodoService.for_default_rules(
            task_service=TaskService(repo, JournalService(repo))
        )
        findings = anomalies_to_findings([_anom(AnomalyType.SINGLE_IP)])
        tasks = service.evaluate_findings(findings)
        assert len(tasks) >= 1
