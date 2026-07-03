"""test_ki_todo_emitter Bridge zwischen Scannern und KiTodoService."""

from __future__ import annotations

import logging

from core.security.severity import Severity
from core.storytelling.ki_todo_emitter import KiTodoEmitter
from core.storytelling.schemas import FindingInput


def _make_finding(
    tool: str = "api_security",
    finding_type: str = "missing_security_header",
    subject: str = "example.test",
    evidence_id: str = "ev-1",
) -> FindingInput:
    return FindingInput(
        tool=tool,
        finding_type=finding_type,
        severity=Severity.HIGH,
        subject=subject,
        evidence_id=evidence_id,
        details={"header_name": "HSTS", "recommended_value": "max-age=31536000", "risk": "Downgrades"},
    )


class _FakeService:
    """Stub fuer KiTodoService — nur das was emit braucht."""

    def __init__(self, raise_exc: Exception | None = None) -> None:
        self.calls: list[list[FindingInput]] = []
        self.sync_calls: list[tuple[str, list[FindingInput]]] = []
        self._raise = raise_exc

    def evaluate_findings(self, findings):
        if self._raise is not None:
            raise self._raise
        self.calls.append(list(findings))
        return [object()] * len(findings)  # Fake "Tasks"

    def sync_findings(self, tool, findings):
        if self._raise is not None:
            raise self._raise
        self.sync_calls.append((tool, list(findings)))
        return [object()] * len(findings)


class TestEmitterCore:
    """emit ruft den Service auf, leere Findings sind no-op."""

    def test_emit_findings_ruft_service(self) -> None:
        emitter = KiTodoEmitter()
        fake = _FakeService()
        emitter._service = fake
        emitter._init_attempted = True

        emitter.emit([_make_finding()])
        assert len(fake.calls) == 1
        assert len(fake.calls[0]) == 1

    def test_emit_leere_liste_kein_service_call(self) -> None:
        emitter = KiTodoEmitter()
        fake = _FakeService()
        emitter._service = fake
        emitter._init_attempted = True

        emitter.emit([])
        assert fake.calls == []

    def test_emit_iterable_wird_zu_liste(self) -> None:
        """``emit`` akzeptiert beliebige Iterables, ruft Service mit Liste auf."""
        emitter = KiTodoEmitter()
        fake = _FakeService()
        emitter._service = fake
        emitter._init_attempted = True

        emitter.emit(iter([_make_finding()]))
        assert len(fake.calls) == 1
        assert len(fake.calls[0]) == 1


class TestEmitterReconcile:
    """ — emit mit reconcile_tool ruft den Voll-Sync."""

    def test_reconcile_tool_ruft_sync_findings(self) -> None:
        emitter = KiTodoEmitter()
        fake = _FakeService()
        emitter._service = fake
        emitter._init_attempted = True

        emitter.emit([_make_finding()], reconcile_tool="patch_monitor")
        assert len(fake.sync_calls) == 1
        assert fake.sync_calls[0][0] == "patch_monitor"
        assert fake.calls == []  # nicht zusaetzlich evaluate_findings

    def test_leere_liste_mit_reconcile_tool_laeuft(self) -> None:
        """Kernfall: 'alles installiert' muss den Sync erreichen."""
        emitter = KiTodoEmitter()
        fake = _FakeService()
        emitter._service = fake
        emitter._init_attempted = True

        emitter.emit([], reconcile_tool="patch_monitor")
        assert fake.sync_calls == [("patch_monitor", [])]

    def test_leere_liste_ohne_reconcile_bleibt_noop(self) -> None:
        """Altes Verhalten fuer Delta-Emitter anderer Tools bleibt."""
        emitter = KiTodoEmitter()
        fake = _FakeService()
        emitter._service = fake
        emitter._init_attempted = True

        emitter.emit([])
        assert fake.calls == []
        assert fake.sync_calls == []

    def test_sync_exception_wird_geschluckt(self, caplog) -> None:
        emitter = KiTodoEmitter()
        emitter._service = _FakeService(raise_exc=RuntimeError("sync-boom"))
        emitter._init_attempted = True

        with caplog.at_level(
            logging.WARNING,
            logger="finlai.core.storytelling.ki_todo_emitter",
        ):
            emitter.emit([_make_finding()], reconcile_tool="patch_monitor")

        assert any(
            "Hook fehlgeschlagen" in rec.message for rec in caplog.records
        )


class TestEmitterFailureSafety:
    """Hook darf NIE einen Scan brechen."""

    def test_service_exception_wird_geschluckt(self, caplog) -> None:
        emitter = KiTodoEmitter()
        emitter._service = _FakeService(raise_exc=RuntimeError("boom"))
        emitter._init_attempted = True

        with caplog.at_level(logging.WARNING, logger="finlai.core.storytelling.ki_todo_emitter"):
            # Sollte nicht crashen
            emitter.emit([_make_finding()])

        # WARNING-Log mit Hook-Hinweis
        assert any(
            "Hook fehlgeschlagen" in rec.message and "RuntimeError" in rec.message
            for rec in caplog.records
        )

    def test_service_init_fehlt_no_op(self) -> None:
        """Wenn der Service nicht initialisierbar ist (None), bleibt emit no-op."""
        emitter = KiTodoEmitter()
        emitter._service = None
        emitter._init_attempted = True

        # Sollte nicht crashen, kein Service-Call.
        emitter.emit([_make_finding()])


class TestLazyInitOnlyOnce:
    """Service-Init wird genau einmal versucht, auch bei wiederholtem emit."""

    def test_init_attempted_flag(self) -> None:
        emitter = KiTodoEmitter()
        # Erster emit triggert _lazy_service — Service-Bau scheitert in
        # Test-Umgebung (keine SQLCipher-DB), Flag wird gesetzt.
        emitter.emit([_make_finding()])
        assert emitter._init_attempted is True

        # Zweiter emit darf NICHT erneut versuchen zu initialisieren.
        attempt_state_before = emitter._init_attempted
        emitter.emit([_make_finding()])
        assert emitter._init_attempted == attempt_state_before
