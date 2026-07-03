"""test_usage_signals — Cross-Tool-Nutzungssignale aus dem SELF-Audit.

Testet den Read-Adapter ``CustomerAuditUsageSignals``: die tri-state-
Ableitung (True/False/None) aus dem jüngsten SELF-Sovereignty-Audit, inkl. der
Konservativitäts-Gates (nur SELF, nur „abgeschlossen" rechtfertigt ``False``).

Bezug: [[-cross-tool-org-auto-detection]].
"""

from __future__ import annotations

from types import SimpleNamespace

from tools.customer_audit.application.usage_signals import CustomerAuditUsageSignals
from tools.customer_audit.domain.entities import (
    AuditMode,
    DetectedProvider,
    SovereigntyAuditResult,
)


class _StubRepo:
    """Minimaler Repo-Ersatz: liefert genau ein (oder kein) Audit zurück."""

    def __init__(self, audit: object | None) -> None:
        self._audit = audit

    def latest_summary_by_subject(self, subject_id: str) -> dict | None:
        return None if self._audit is None else {"audit_id": "x"}

    def load_by_id(self, audit_id: str) -> object | None:
        return self._audit


def _provider(name: str, status: str, category: str) -> DetectedProvider:
    return DetectedProvider(
        name=name, status=status, category=category, via="self_declared", evidence=""
    )


def _audit(
    mode: AuditMode, sov: SovereigntyAuditResult, created_at: str = "2026-06-05T10:00:00"
) -> object:
    # Der Adapter konsumiert ausschließlich audit_mode/sovereignty_audit/created_at —
    # ein schlanker Stub genügt (keine vollständige CustomerAuditResult-Montage).
    return SimpleNamespace(audit_mode=mode, sovereignty_audit=sov, created_at=created_at)


def _signale(audit: object | None, subject_id: str = "own-1"):
    return CustomerAuditUsageSignals(_StubRepo(audit)).signale_fuer(subject_id)


def test_leerer_subject_id_alle_none() -> None:
    sig = CustomerAuditUsageSignals(_StubRepo(None)).signale_fuer("")
    assert sig.nutzt_m365 is None
    assert sig.hat_auftragsverarbeiter is None


def test_kein_audit_alle_none() -> None:
    sig = _signale(None)
    assert (sig.nutzt_m365, sig.nutzt_kanzlei_software) == (None, None)
    assert (sig.nutzt_cloud_speicher, sig.hat_auftragsverarbeiter) == (None, None)


def test_nicht_self_audit_alle_none() -> None:
    sov = SovereigntyAuditResult(detection_enabled=True)
    sig = _signale(_audit(AuditMode.CUSTOMER, sov))
    assert sig.nutzt_m365 is None


def test_nicht_abgeschlossen_alle_none() -> None:
    # Detection aus UND nichts deklariert → kein belastbares Audit → None.
    sov = SovereigntyAuditResult(detection_enabled=False)
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_m365 is None
    assert sig.hat_auftragsverarbeiter is None


def test_abgeschlossen_leer_alles_false() -> None:
    # Detection lief fehlerfrei, aber keine Provider → positive Nicht-Nutzung → False.
    sov = SovereigntyAuditResult(detection_enabled=True)
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_m365 is False
    assert sig.nutzt_kanzlei_software is False
    assert sig.nutzt_cloud_speicher is False
    assert sig.hat_auftragsverarbeiter is False


def test_gescheiterter_scan_alle_none() -> None:
    # Detection aktiv, aber Scan FEHLGESCHLAGEN (scan_errors), nichts deklariert →
    # Unwissen, kein Nicht-Nutzungs-Befund → None (No-op), kein falsches Auto-N/A.
    # 3-Sub-Agent-Review P2 /: „Abwesenheit eines Signals ≠ Nicht-Nutzung".
    sov = SovereigntyAuditResult(
        detection_enabled=True, scan_errors=["DNS-Lookup fehlgeschlagen"]
    )
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_m365 is None
    assert sig.nutzt_kanzlei_software is None
    assert sig.nutzt_cloud_speicher is None
    assert sig.hat_auftragsverarbeiter is None


def test_gescheiterter_scan_aber_deklariert_bleibt_belastbar() -> None:
    # Scan fehlgeschlagen, aber der User hat aktiv DATEV deklariert → die
    # Deklaration bleibt belastbar: kanzlei True, leere Kategorien → False.
    sov = SovereigntyAuditResult(
        detection_enabled=True,
        scan_errors=["DNS-Lookup fehlgeschlagen"],
        declared=[_provider("DATEV", "eu_sovereign", "kanzlei_software")],
    )
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_kanzlei_software is True
    assert sig.nutzt_m365 is False


def test_m365_deklariert_true() -> None:
    sov = SovereigntyAuditResult(
        declared=[_provider("Microsoft 365", "eu_boundary", "office_suite")]
    )
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_m365 is True
    # office_suite zählt auch als Cloud-Speicher (OneDrive/SharePoint).
    assert sig.nutzt_cloud_speicher is True
    assert sig.hat_auftragsverarbeiter is True
    # Keine Kanzlei-SW deklariert, Audit aber abgeschlossen → False.
    assert sig.nutzt_kanzlei_software is False


def test_kanzlei_und_cloud_true() -> None:
    sov = SovereigntyAuditResult(
        declared=[
            _provider("DATEV", "eu_sovereign", "kanzlei_software"),
            _provider("Dropbox", "cloud_act", "file_sync"),
        ]
    )
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_kanzlei_software is True
    assert sig.nutzt_cloud_speicher is True
    assert sig.hat_auftragsverarbeiter is True
    assert sig.nutzt_m365 is False


def test_self_hosted_kein_auftragsverarbeiter() -> None:
    # Self-hosted Nextcloud: Cloud-Speicher ja, aber kein Auftragsverarbeiter.
    sov = SovereigntyAuditResult(
        declared=[_provider("Nextcloud", "self_hosted", "file_sync")]
    )
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_cloud_speicher is True
    assert sig.hat_auftragsverarbeiter is False


def test_audit_datum_durchgereicht() -> None:
    sov = SovereigntyAuditResult(detection_enabled=True)
    sig = _signale(_audit(AuditMode.SELF, sov, created_at="2026-06-05T12:34:56"))
    assert sig.audit_datum == "2026-06-05T12:34:56"


def test_detected_und_declared_kombiniert() -> None:
    # Auto-erkannt zählt ebenso wie deklariert.
    sov = SovereigntyAuditResult(
        detection_enabled=True,
        detected=[_provider("Azure", "cloud_act", "saas_other")],
    )
    sig = _signale(_audit(AuditMode.SELF, sov))
    assert sig.nutzt_m365 is True
