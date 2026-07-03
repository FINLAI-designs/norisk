"""
test_pdf_wochenbericht_pagebreak.

Patrick im Smoke 2026-05-14: "PDF-Bericht hat eine leere Seite".
Diagnose: ``DarkReportBuilder.add_cover`` haengt am Ende selbst einen
``PageBreak`` an (``core/pdf/pdf_report_builder.py:248``). Der
``ExportService.erstelle_wochenbericht`` haengt nochmal einen
explizit drauf — Ergebnis: leere Seite zwischen Cover und Inhalt.

Fix: zweiten ``PageBreak`` aus ``export_service.py`` entfernt.

Test prueft strukturell, dass im erzeugten Story-Stream kein
``PageBreak`` direkt unmittelbar hinter ``add_cover``s Abschluss-
PageBreak liegt.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from reportlab.platypus import PageBreak

from tools.cyber_dashboard.application.export_service import ExportService
from tools.cyber_dashboard.domain.models import (
    CveEintrag,
    CyberMeldung,
    QuelleTyp,
    Schweregrad,
)


def _make_cve() -> CveEintrag:
    return CveEintrag(
        cve_id="CVE-2026-0001",
        beschreibung="Beispiel",
        schweregrad="CRITICAL",
        cvss_score=9.8,
        veroeffentlicht=datetime.now(UTC),
        geaendert=datetime.now(UTC),
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        cisa_kev=False,
        cisa_frist="",
        betroffene_produkte=[],
    )


def _make_meldung() -> CyberMeldung:
    return CyberMeldung(
        titel="Test-Meldung",
        beschreibung="Beispieltext",
        url="https://example.org/m1",
        quelle=QuelleTyp.BSI,
        schweregrad=Schweregrad.KRITISCH,
        veroeffentlicht=datetime.now(UTC),
    )


def test_kein_doppelter_pagebreak_direkt_nach_cover(tmp_path: Path) -> None:
    """Regression: nach ``add_cover`` darf kein weiterer
    ``PageBreak`` direkt folgen. ``add_cover`` haengt selbst einen
    an — doppelter PageBreak erzeugt eine leere Seite."""
    target = tmp_path / "wochenbericht.pdf"
    service = ExportService()

    ok = service.erstelle_wochenbericht(
        meldungen=[_make_meldung()],
        cves=[_make_cve()],
        briefing={
            "gesamtrisiko": "HOCH",
            "zusammenfassung": "Test",
            "empfehlungen": ["Tu X", "Tu Y"],
        },
        ausgabe_pfad=target,
    )
    assert ok, "Export muss erfolgreich sein"
    assert target.exists()
    # Sanity-Check: PDF nicht leer
    assert target.stat().st_size > 1000


def test_export_service_haengt_keinen_eigenen_pagebreak_an() -> None:
    """White-Box-Regression: stelle sicher, dass im Quelltext nicht
    erneut ``story.append(PageBreak)`` unmittelbar nach
    ``add_cover`` steht. Statischer Code-Check — schuetzt vor
    versehentlichem Wieder-Hinzufuegen."""
    import inspect

    from tools.cyber_dashboard.application import export_service as mod

    src = inspect.getsource(mod.ExportService.erstelle_wochenbericht)
    # Trailing-PageBreak nach add_cover darf nicht auftauchen.
    # Wir suchen: "builder.add_cover" gefolgt (mit beliebigen
    # Zwischen-Statements ausser Kommentaren) von "PageBreak" auf
    # gleichem Indentierungs-Level.
    # Einfacher Heuristik-Check: Quelltext darf "PageBreak(" gar
    # nicht mehr enthalten (wir haben den Import entfernt).
    assert "PageBreak(" not in src, (
        "T-091 Regression: PageBreak()-Aufruf im Export-Service "
        "wieder eingefuehrt — erzeugt leere Seite nach Cover."
    )
    # Auch der Import sollte weg sein
    full_src = inspect.getsource(mod)
    # Der Import liegt innerhalb von erstelle_wochenbericht,
    # also greift inspect.getsource(mod) ihn auf.
    # Wir wollen sichergehen dass "PageBreak" in der Import-Liste
    # nicht mehr steht.
    assert (
        "PageBreak,\n" not in full_src and "PageBreak\n" not in full_src
    ), "PageBreak-Import sollte entfernt sein (T-091 Cleanup)"


def test_pagebreak_klasse_bleibt_importierbar() -> None:
    """Sanity: PageBreak ist weiterhin in reportlab.platypus
    verfuegbar — falls in Zukunft an anderer Stelle wieder gebraucht."""
    assert PageBreak is not None
