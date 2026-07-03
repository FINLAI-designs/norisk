"""Tests für die Storytelling-Engine (Sprint S1a).

Deckt ab:
  - Schema-Constraints (Pydantic-Validierung, frozen)
  - channel_router: vollständiges Mapping aller 4 Urgency-Stufen
  - finding_templates: jedes der 5 Templates rendert für 3 Severity-
    Beispiele und produziert valide Story-Felder
  - narrative_builder: build_story für jedes Template, plus Fehlerfall
    für unbekannte Template-Keys

Tests sind reine Pure-Python-Tests — kein PySide6, keine DB.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.storytelling.channel_router import route
from core.storytelling.finding_templates import (
    TEMPLATES,
    list_template_keys,
)
from core.storytelling.narrative_builder import (
    TemplateNotFoundError,
    build_story,
)
from core.storytelling.schemas import Channel, FindingInput, Story, Urgency
from core.vulnerability.domain.severity import Severity

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


def test_finding_input_ist_frozen():
    """``FindingInput`` ist unveränderlich — Pydantic frozen=True."""
    fi = FindingInput(
        tool="cert_monitor",
        finding_type="cert_expiring",
        severity=Severity.HIGH,
        subject="example.com",
        evidence_id="cert-1",
    )
    with pytest.raises(ValidationError):
        fi.tool = "anders"  # type: ignore[misc]


def test_finding_input_required_fields_validation():
    """Leere Pflichtfelder lösen ValidationError aus."""
    with pytest.raises(ValidationError):
        FindingInput(
            tool="",
            finding_type="cert_expiring",
            severity=Severity.HIGH,
            subject="x",
            evidence_id="y",
        )


def test_story_max_headline_length():
    """Headline > 200 Zeichen löst ValidationError aus."""
    with pytest.raises(ValidationError):
        Story(
            urgency=Urgency.AKUT,
            headline="x" * 201,
            explanation="x",
            action="x",
            evidence_finding_id="x",
            channel=Channel.NOTIFICATION,
        )


# ---------------------------------------------------------------------------
# Channel-Router
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "urgency,expected",
    [
        (Urgency.AKUT, Channel.NOTIFICATION),
        (Urgency.WICHTIG, Channel.DASHBOARD_HERO),
        (Urgency.TREND, Channel.AKKORDEON_DETAIL),
        (Urgency.KONTEXT, Channel.WOCHEN_REPORT),
    ],
)
def test_channel_router_mapping(urgency: Urgency, expected: Channel):
    """Alle 4 Urgency-Stufen routen auf den dokumentierten Kanal."""
    assert route(urgency) == expected


# ---------------------------------------------------------------------------
# Template-Registry
# ---------------------------------------------------------------------------


def test_registry_hat_alle_templates():
    """Registry enthaelt alle aktuell registrierten Templates.

    Sprint S1a: 5 initiale Templates.
    ``system_scanner/hardening_check_failed``.
    5 ``patch_monitor/*``-Templates (alle mit
    derselben Render-Funktion ``_render_patch_recommendation``).
 E: 6 ``network_monitor/*``-Templates (alle mit
    ``_render_network_anomaly``).
    ``dependency_auditor/unpinned_dependency``
    (aggregierter Versions-Pin-Hinweis statt Task-Flut).
    Bei neuem Template muss dieser Test mitziehen.
    """
    assert set(list_template_keys()) == {
        ("api_security", "missing_security_header"),
        ("cert_monitor", "cert_expiring"),
        ("csaf_advisor", "active_advisory_match"),
        ("dependency_auditor", "vulnerable_package"),
        ("dependency_auditor", "unpinned_dependency"),
        ("network_scanner", "exposed_admin_port"),
        ("system_scanner", "hardening_check_failed"),
        ("patch_monitor", "patch_update_urgent"),
        ("patch_monitor", "patch_eol_no_patch"),
        ("patch_monitor", "patch_workaround_available"),
        ("patch_monitor", "patch_with_csaf_context"),
        ("patch_monitor", "patch_update_available"),
        ("network_monitor", "volume_anomaly"),
        ("network_monitor", "off_hours"),
        ("network_monitor", "single_ip_exfil"),
        ("network_monitor", "game_download"),
        ("network_monitor", "unknown_process"),
        ("network_monitor", "dns_tunneling"),
        ("system_tuner", "privacy_default_risky"),
    }


# ---------------------------------------------------------------------------
# narrative_builder — Fehlerfälle
# ---------------------------------------------------------------------------


def test_build_story_unbekannte_kombination_raises():
    """Unbekannte ``(tool, finding_type)`` löst TemplateNotFoundError aus."""
    finding = FindingInput(
        tool="password_checker",
        finding_type="weak_password",
        severity=Severity.MEDIUM,
        subject="admin@example.com",
        evidence_id="pw-1",
    )
    with pytest.raises(TemplateNotFoundError):
        build_story(finding)


def test_build_story_setzt_channel_aus_router():
    """``Story.channel`` wird vom channel_router befüllt, nicht vom Template."""
    finding = FindingInput(
        tool="cert_monitor",
        finding_type="cert_expiring",
        severity=Severity.HIGH,
        subject="example.com",
        evidence_id="cert-1",
        details={"days_left": 5, "expires_at": "2026-05-04"},
    )
    story = build_story(finding)
    assert story.channel == route(story.urgency)


def test_build_story_durchreicht_evidence_id():
    """``evidence_finding_id`` ist 1:1 aus FindingInput.evidence_id."""
    finding = FindingInput(
        tool="cert_monitor",
        finding_type="cert_expiring",
        severity=Severity.HIGH,
        subject="example.com",
        evidence_id="cert-evidence-42",
        details={"days_left": 30, "expires_at": "2026-05-29"},
    )
    story = build_story(finding)
    assert story.evidence_finding_id == "cert-evidence-42"


# ---------------------------------------------------------------------------
# Template 1: cert_expiring — kontextspezifische Urgency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "days_left,expected_urgency",
    [
        (-3, Urgency.AKUT),  # bereits abgelaufen
        (5, Urgency.AKUT),   # ≤ 7 Tage
        (20, Urgency.WICHTIG),  # ≤ 30 Tage
        (60, Urgency.TREND),  # ≤ 90 Tage
        (180, Urgency.KONTEXT),  # > 90 Tage
    ],
)
def test_cert_expiring_urgency_aus_days_left(
    days_left: int, expected_urgency: Urgency
):
    """Cert-Template lässt ``days_left`` über Severity dominieren."""
    finding = FindingInput(
        tool="cert_monitor",
        finding_type="cert_expiring",
        severity=Severity.LOW,  # bewusst niedrig — days_left soll dominieren
        subject="example.com",
        evidence_id="cert-1",
        details={"days_left": days_left, "expires_at": "2026-06-01"},
    )
    story = build_story(finding)
    assert story.urgency == expected_urgency


def test_cert_expiring_abgelaufen_andere_headline():
    """Abgelaufene Zerts bekommen andere Headline-Formulierung."""
    finding = FindingInput(
        tool="cert_monitor",
        finding_type="cert_expiring",
        severity=Severity.CRITICAL,
        subject="example.com",
        evidence_id="cert-1",
        details={"days_left": -3, "expires_at": "2026-04-26"},
    )
    story = build_story(finding)
    assert "abgelaufen" in story.headline.lower()
    assert "3" in story.headline


# ---------------------------------------------------------------------------
# Template 2: missing_security_header — 3 Severity-Beispiele
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected_urgency",
    [
        (Severity.CRITICAL, Urgency.AKUT),
        (Severity.HIGH, Urgency.WICHTIG),
        (Severity.MEDIUM, Urgency.TREND),
    ],
)
def test_missing_security_header_severity_zu_urgency(
    severity: Severity, expected_urgency: Urgency
):
    """API-Header-Template folgt dem Default-Severity-Mapping."""
    finding = FindingInput(
        tool="api_security",
        finding_type="missing_security_header",
        severity=severity,
        subject="api.example.com",
        evidence_id="api-1",
        details={
            "header_name": "Content-Security-Policy",
            "recommended_value": "default-src 'self'",
            "risk": "Cross-Site-Scripting-Angriffen",
        },
    )
    story = build_story(finding)
    assert story.urgency == expected_urgency
    assert "Content-Security-Policy" in story.headline
    assert "Cross-Site-Scripting" in story.explanation


# ---------------------------------------------------------------------------
# Template 3: exposed_admin_port — 3 Severity-Beispiele
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,port,service,expected_urgency",
    [
        (Severity.CRITICAL, 3389, "RDP", Urgency.AKUT),
        (Severity.HIGH, 22, "SSH", Urgency.WICHTIG),
        (Severity.MEDIUM, 3306, "MySQL", Urgency.TREND),
    ],
)
def test_exposed_admin_port(
    severity: Severity, port: int, service: str, expected_urgency: Urgency
):
    """Network-Template enthält Port und Service-Name in Headline + Action."""
    finding = FindingInput(
        tool="network_scanner",
        finding_type="exposed_admin_port",
        severity=severity,
        subject="192.0.2.42",
        evidence_id=f"net-{port}",
        details={"port": port, "protocol": "TCP", "service_name": service},
    )
    story = build_story(finding)
    assert story.urgency == expected_urgency
    assert str(port) in story.headline
    assert service in story.headline
    assert str(port) in story.action  # Action verweist auf den konkreten Port


# ---------------------------------------------------------------------------
# Template 4: csaf_advisory_match — 3 Severity-Beispiele
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected_urgency",
    [
        (Severity.CRITICAL, Urgency.AKUT),
        (Severity.HIGH, Urgency.WICHTIG),
        (Severity.LOW, Urgency.KONTEXT),
    ],
)
def test_csaf_advisory_match(severity: Severity, expected_urgency: Urgency):
    """CSAF-Template: Advisory-ID, Vendor und fixed_version landen im Text."""
    finding = FindingInput(
        tool="csaf_advisor",
        finding_type="active_advisory_match",
        severity=severity,
        subject="openssl",
        evidence_id="csaf-1",
        details={
            "vendor": "OpenSSL Project",
            "product": "openssl",
            "version": "1.1.1",
            "advisory_id": "CVE-2024-0001",
            "summary": "Memory-Leak im TLS-Handshake",
            "fixed_version": "1.1.1z",
            "url": "https://example.org/advisories/CVE-2024-0001",
        },
    )
    story = build_story(finding)
    assert story.urgency == expected_urgency
    assert "CVE-2024-0001" in story.headline
    assert "OpenSSL Project" in story.headline
    assert "1.1.1z" in story.action


def test_csaf_advisory_match_ohne_url_action_ohne_link():
    """Wenn keine URL übergeben wird, fügt das Template auch keine ein."""
    finding = FindingInput(
        tool="csaf_advisor",
        finding_type="active_advisory_match",
        severity=Severity.HIGH,
        subject="x",
        evidence_id="csaf-2",
        details={
            "vendor": "v",
            "product": "x",
            "version": "1",
            "advisory_id": "ADV-1",
            "summary": "",
            "fixed_version": "2",
            "url": "",
        },
    )
    story = build_story(finding)
    assert "Anleitung im Advisory" not in story.action


# ---------------------------------------------------------------------------
# Template 5: vulnerable_package — 3 Severity-Beispiele
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,expected_urgency",
    [
        (Severity.CRITICAL, Urgency.AKUT),
        (Severity.HIGH, Urgency.WICHTIG),
        (Severity.MEDIUM, Urgency.TREND),
    ],
)
def test_vulnerable_package(severity: Severity, expected_urgency: Urgency):
    """Dependency-Template enthält Package-Name, CVE-ID und fixed_version."""
    finding = FindingInput(
        tool="dependency_auditor",
        finding_type="vulnerable_package",
        severity=severity,
        subject="requests",
        evidence_id="dep-1",
        details={
            "package": "requests",
            "version": "2.30.0",
            "cve_id": "CVE-2024-1234",
            "summary": "Header-Injection in Cookies",
            "fixed_version": "2.32.5",
        },
    )
    story = build_story(finding)
    assert story.urgency == expected_urgency
    assert "requests" in story.headline
    assert "CVE-2024-1234" in story.headline
    assert "2.32.5" in story.action


# ---------------------------------------------------------------------------
# Cross-Cutting: jedes registrierte Template ergibt eine valide Story
# ---------------------------------------------------------------------------


def _minimal_finding(tool: str, finding_type: str) -> FindingInput:
    """Baut ein minimales Finding mit Template-spezifischen Defaults."""
    details_per_template = {
        ("cert_monitor", "cert_expiring"): {
            "days_left": 10,
            "expires_at": "2026-05-09",
        },
        ("api_security", "missing_security_header"): {
            "header_name": "Strict-Transport-Security",
            "recommended_value": "max-age=63072000",
            "risk": "HTTPS-Downgrade-Angriffen",
        },
        ("network_scanner", "exposed_admin_port"): {
            "port": 22,
            "protocol": "TCP",
            "service_name": "SSH",
        },
        ("csaf_advisor", "active_advisory_match"): {
            "vendor": "Acme",
            "product": "thing",
            "version": "1.0",
            "advisory_id": "ADV-1",
            "summary": "",
            "fixed_version": "1.1",
            "url": "",
        },
        ("dependency_auditor", "vulnerable_package"): {
            "package": "lib",
            "version": "1.0",
            "cve_id": "CVE-X",
            "summary": "",
            "fixed_version": "1.1",
        },
        # aggregierter Versions-Pin-Hinweis (dependency_auditor).
        ("dependency_auditor", "unpinned_dependency"): {
            "count": 3,
            "packages": "pypdf, lxml, ftfy",
            "advisories": 24,
            "source_file": "requirements.txt",
        },
        ("system_scanner", "hardening_check_failed"): {
            "check_id": "SH-001",
            "label": "Firewall aktiv",
            "detail": "Domain-Profil deaktiviert",
        },
        # alle 5 Patch-Templates teilen sich
        # ``_render_patch_recommendation`` — Differenzierung via
        # ``details["recommendation"]``.
        ("patch_monitor", "patch_update_urgent"): {
            "recommendation": "update_urgent",
            "name": "Firefox",
            "installed_version": "120.0",
            "available_version": "121.0",
            "cve_ids": ["CVE-2024-1234"],
            "cvss_max": 8.5,
            "exploit_available": True,
        },
        ("patch_monitor", "patch_eol_no_patch"): {
            "recommendation": "eol_no_patch",
            "name": "Old SW",
            "installed_version": "1.0",
            "available_version": "",
            "eol": True,
        },
        ("patch_monitor", "patch_workaround_available"): {
            "recommendation": "workaround_available",
            "name": "OpenSSL",
            "installed_version": "3.0.0",
            "available_version": "",
            "cve_ids": ["CVE-2024-5678"],
        },
        ("patch_monitor", "patch_with_csaf_context"): {
            "recommendation": "patch_available_with_csaf_context",
            "name": "Cisco-X",
            "installed_version": "1.0",
            "available_version": "1.1",
            "cve_ids": ["CVE-2024-9999"],
        },
        ("patch_monitor", "patch_update_available"): {
            "recommendation": "update_available",
            "name": "VLC",
            "installed_version": "3.0.20",
            "available_version": "3.0.21",
        },
        # E: alle 6 network_monitor-Templates teilen sich
        # ``_render_network_anomaly`` — Differenzierung via finding_type.
        ("network_monitor", "volume_anomaly"): {
            "process_name": "evil.exe",
            "value_bytes": 2_000_000_000,
            "remote_ip": "",
            "detail": "",
        },
        ("network_monitor", "off_hours"): {
            "process_name": "evil.exe",
            "value_bytes": 200_000_000,
            "remote_ip": "",
            "detail": "",
        },
        ("network_monitor", "single_ip_exfil"): {
            "process_name": "evil.exe",
            "value_bytes": 11_000_000_000,
            "remote_ip": "8.8.8.8",
            "detail": "",
        },
        ("network_monitor", "game_download"): {
            "process_name": "steam.exe",
            "value_bytes": 5_000_000_000,
            "remote_ip": "23.59.111.12",
            "detail": "Steam CDN",
        },
        ("network_monitor", "unknown_process"): {
            "process_name": "x.exe",
            "value_bytes": 20_000_000,
            "remote_ip": "",
            "detail": r"C:\Users\x\AppData\Local\Temp\x.exe",
        },
        ("network_monitor", "dns_tunneling"): {
            "process_name": "evil.exe",
            "value_bytes": 1500,
            "remote_ip": "",
            "detail": "a1b2c3.tunnel.example.com (max-Label 6, Entropie 2.5)",
        },
        ("system_tuner", "privacy_default_risky"): {
            "rationale": "Reduziert optionale Telemetrie.",
            "docs_url": "https://learn.microsoft.com/x",
            "category": "telemetry",
            "risk_tier": "T1_safe",
            "current_value": "(nicht gesetzt)",
            "desired_value": "1",
        },
    }
    return FindingInput(
        tool=tool,
        finding_type=finding_type,
        severity=Severity.HIGH,
        subject="x",
        evidence_id="ev-1",
        details=details_per_template[(tool, finding_type)],
    )


def test_alle_templates_produzieren_gueltige_stories():
    """Smoke-Test: jedes Template rendert ohne Validation-Error."""
    for tool, finding_type in list_template_keys():
        finding = _minimal_finding(tool, finding_type)
        story = build_story(finding)
        assert isinstance(story, Story)
        assert story.headline.strip()
        assert story.explanation.strip()
        assert story.action.strip()


def test_jedes_template_hat_eine_render_funktion():
    """Sicherheits-Check: TEMPLATES-Dict-Werte sind callable."""
    for fn in TEMPLATES.values():
        assert callable(fn)
