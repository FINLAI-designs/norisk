"""narrative_builder — `build_story(input)` (Sprint S1a).

Die einzige öffentliche Eintritts-Funktion der Storytelling-Engine.
Schlägt das passende Template in:data:`finding_templates.TEMPLATES`
nach, ruft den Renderer auf und routet die resultierende Urgency
über:func:`channel_router.route` in einen Anzeige-Kanal.

Workflow::

    finding = FindingInput(tool="cert_monitor", finding_type="cert_expiring",
                           severity=Severity.HIGH, subject="example.com",
                           evidence_id="cert-42",
                           details={"days_left": 5, "expires_at": "2026-05-04"})
    story = build_story(finding)
    # story.urgency, story.headline, story.explanation, story.action,
    # story.evidence_finding_id, story.channel

Schichtzugehörigkeit: core/ — kein PySide6, kein DB-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.storytelling.channel_router import route
from core.storytelling.finding_templates import TEMPLATES
from core.storytelling.schemas import FindingInput, Story


class TemplateNotFoundError(KeyError):
    """Kein Template registriert für die angefragte ``(tool, finding_type)``-Kombination.

    Wird von:func:`build_story` geworfen statt einer generischen
    ``KeyError``, damit Konsumenten gezielt darauf reagieren können
    (z. B. mit einer Fallback-Story "Befund ohne Template").
    """


def build_story(finding: FindingInput) -> Story:
    """Wandelt einen ``FindingInput`` in eine voll gerenderte ``Story`` um.

    Args:
        finding: Normalisierter Eingang. ``finding.tool`` +
            ``finding.finding_type`` müssen einer Template-Registrierung
            in:data:`finding_templates.TEMPLATES` entsprechen.

    Returns:
        Die gerenderte:class:`Story` mit gesetztem ``channel``.

    Raises:
        TemplateNotFoundError: Wenn keine Template-Funktion für
            ``(finding.tool, finding.finding_type)`` registriert ist.
        pydantic.ValidationError: Wenn der Renderer ein leeres oder
            zu langes Headline/Explanation/Action liefert (
            ``Story``-Field-Constraints).
    """
    key = (finding.tool, finding.finding_type)
    renderer = TEMPLATES.get(key)
    if renderer is None:
        raise TemplateNotFoundError(
            f"Kein Storytelling-Template für ({finding.tool!r}, "
            f"{finding.finding_type!r}) registriert."
        )

    urgency, headline, explanation, action = renderer(finding)
    return Story(
        urgency=urgency,
        headline=headline,
        explanation=explanation,
        action=action,
        evidence_finding_id=finding.evidence_id,
        channel=route(urgency),
    )
