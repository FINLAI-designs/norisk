"""Tests fuer DependencyAuditorWidget Review-Fixes.

Prueft:
1. ok_count in der Summary-Leiste: Pakete ohne verifizierbare Version
   zaehlen NICHT als OK; Zaehler ist gegen negative Werte abgesichert.
2. R22/: OSV-Summaries werden im Tooltip escaped (Auto-RichText).

Author: Patrick Riederich
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from tools.dependency_auditor.domain.models import (
    DependencyAuditResult,
    DependencyInfo,
    VulnerabilityInfo,
    VulnSeverity,
)
from tools.dependency_auditor.gui.dependency_auditor_widget import (
    DependencyAuditorWidget,
)

pytestmark = pytest.mark.gui


def _dep(name: str, pinned: str | None = None) -> DependencyInfo:
    return DependencyInfo(
        name=name,
        version_pinned=pinned,
        version_spec=f"=={pinned}" if pinned else "",
        line_number=1,
    )


def _vuln(
    summary: str = "Test-Vulnerability",
    package_name: str = "requests",
) -> VulnerabilityInfo:
    return VulnerabilityInfo(
        vuln_id="GHSA-test-0001",
        package_name=package_name,
        affected_versions=">=2.0,<2.32",
        fixed_version="2.32.0",
        severity=VulnSeverity.HIGH,
        summary=summary,
        url="https://example.com/vuln",
    )


def _result(**overrides) -> DependencyAuditResult:
    defaults = dict(
        source_file="requirements.txt",
        scan_timestamp="2026-06-12T10:00:00Z",
        total_dependencies=0,
        total_vulnerabilities=0,
    )
    defaults.update(overrides)
    return DependencyAuditResult(**defaults)


@pytest.fixture
def widget(qtbot) -> DependencyAuditorWidget:
    w = DependencyAuditorWidget(service=MagicMock())
    qtbot.addWidget(w)
    return w


class TestOkCount:
    """: 'Version unbekannt'-Pakete zaehlen nicht als OK."""

    def test_unverified_wird_abgezogen(self, widget) -> None:
        ghost = _dep("ghost-package")
        result = _result(
            total_dependencies=3,
            total_vulnerabilities=1,
            dependencies=[_dep("requests", "2.31.0"), _dep("pillow", "10.0.0"), ghost],
            vulnerabilities=[_vuln()],
            unverified_dependencies=[ghost],
            unverified_vulnerabilities=[_vuln(package_name="ghost-package")],
        )
        widget._populate_summary(result)
        assert widget._lbl_ok.text() == "OK 1 OK"
        # Label zaehlt Advisories (unverified_count), nicht Pakete.
        assert "1 Version unbekannt" in widget._lbl_unverified.text()

    def test_ok_count_nie_negativ(self, widget) -> None:
        """Mehr Vulns als Dependencies (mehrere CVEs pro Paket) → 0, nicht negativ."""
        dep = _dep("requests", "2.31.0")
        result = _result(
            total_dependencies=1,
            total_vulnerabilities=3,
            dependencies=[dep],
            vulnerabilities=[_vuln(), _vuln(), _vuln()],
        )
        widget._populate_summary(result)
        assert widget._lbl_ok.text() == "OK 0 OK"


class TestTooltipEscape:
    """R22/: untrusted OSV-Summary im Tooltip escapen."""

    _BOESE_SUMMARY = '<img src="x" onerror="alert(1)"> Boese'

    def test_vuln_tooltip_escaped(self, widget) -> None:
        result = _result(
            total_dependencies=1,
            total_vulnerabilities=1,
            dependencies=[_dep("requests", "2.31.0")],
            vulnerabilities=[_vuln(summary=self._BOESE_SUMMARY)],
        )
        widget._populate_tree(result)
        top = widget._tree.topLevelItem(0)
        tooltip = top.child(0).toolTip(1)
        assert "<" not in tooltip
        assert "&lt;img" in tooltip

    def test_unverified_tooltip_escaped(self, widget) -> None:
        ghost = _dep("ghost-package")
        result = _result(
            total_dependencies=1,
            dependencies=[ghost],
            unverified_dependencies=[ghost],
            unverified_vulnerabilities=[
                _vuln(summary=self._BOESE_SUMMARY, package_name="ghost-package")
            ],
        )
        widget._populate_tree(result)
        top = widget._tree.topLevelItem(0)
        assert "VERSION UNBEKANNT" in top.text(0)
        tooltip = top.child(0).toolTip(1)
        assert "<" not in tooltip
        assert "&lt;img" in tooltip
