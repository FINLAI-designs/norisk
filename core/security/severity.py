"""core.security.severity — Kanonisches Severity-Enum.

R-Sev-Sprint (Run 2): kanonisches Enum fuer Schweregrade, mit Mappern
fuer die heterogenen tool-lokalen Varianten (api_security ``Severity``,
dependency_auditor ``VulnSeverity``, cyber_dashboard ``Schweregrad``,
validation_report ``Severity``).

Vor lebte dieses Enum unter ``core/vulnerability/domain/severity.py``.
Mit der Konsolidierung ist ``core/security/severity.py`` die kanonische
Position — der alte Pfad ist ein Shim und re-exportiert byte-identisch.

Begriffe
--------
- ``Severity`` — kanonisches Enum, Werte kleingeschrieben englisch
  (Default-Konvention im Repo, vgl. ``tools/api_security/domain/models.py``).
- Ordnung: ``CRITICAL > HIGH > MEDIUM > LOW > INFO`` — über ``__lt__``
  vergleichbar, damit ``max``/``sorted`` ohne Helper-Funktion
  funktioniert.

Tool-lokale Severity-Enums die NICHT auf das kanonische gewechselt sind
(Stand 2026-05-07):

- ``tools/cyber_dashboard/domain/models.py:Schweregrad`` — deutsche
  Lowercase-Werte, in DB persistiert. Migration als separater Task.
- ``tools/dependency_auditor/domain/models.py:VulnSeverity`` — deutsche
  UPPERCASE-Werte, in DB persistiert. Migration als separater Task.
- ``core/security/validation_report.py:Severity`` — englische UPPERCASE-
  Werte, in Reports persistiert. Migration auf Folge-Task.

Caller koennen via:func:`from_vuln_severity` /:func:`from_csaf` /
:func:`from_cvss` zwischen den Welten konvertieren.

Schichtzugehörigkeit: ``core/security/`` (framework-agnostisch).

Author: Patrick Riederich
Version: 1.0 — von core/vulnerability/domain/severity.py umgezogen)
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Kanonisches Severity-Enum
# ---------------------------------------------------------------------------

# Ordnung von schwächster zu stärkster Severity. Wird sowohl von ``__lt__``
# als auch von ``sort_index`` konsumiert — Single Source of Truth, damit
# Ordnung nirgendwo doppelt definiert ist.
_SEVERITY_ORDER: tuple[str, ...] = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)


class Severity(Enum):
    """Kanonisches Severity-Enum für alle Vulnerability-Quellen.

    Ordnung: ``CRITICAL > HIGH > MEDIUM > LOW > INFO``.
    Werte sind kleingeschrieben englisch (Default-Konvention im Repo).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: object) -> bool:
        """Vergleicht zwei ``Severity``-Werte nach Schweregrad-Ordnung.

        ``INFO < LOW < MEDIUM < HIGH < CRITICAL``. Vergleich mit
        Nicht-``Severity``-Werten gibt ``NotImplemented`` zurück, damit
        Python einen sauberen ``TypeError`` liefert.
        """
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_ORDER.index(self.value) < _SEVERITY_ORDER.index(
            other.value
        )

    def sort_index(self) -> int:
        """Numerischer Index für stabile Sortierung (höher = schwerer).

        ``INFO`` → 0, ``CRITICAL`` → 4. Pendant zu den ``sort_order``-
        Methoden in den existierenden, tool-lokalen Severity-Enums, dort
        allerdings invertiert (kritisch = 0). Hier bewusst aufsteigend,
        damit die Reihenfolge mit ``__lt__`` konsistent ist.
        """
        return _SEVERITY_ORDER.index(self.value)


# ---------------------------------------------------------------------------
# Mapping-Helper
# ---------------------------------------------------------------------------

# CSAF-Severity-Vokabular (CSAF 2.0 §3.2.3.18.3 ``aggregate_severity/text``,
# zusätzlich die in der Praxis häufigen ``vulnerabilities[].scores[].cvss_v3``-
# Severity-Strings). CSAF kennt kein ``info`` — Unbekanntes wird auf
# ``INFO`` gemappt, damit Konsumenten nie ``None`` behandeln müssen.
_CSAF_TO_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,  # Alternative CSAF-Schreibweise
    "low": Severity.LOW,
    "none": Severity.INFO,
}


def from_csaf(value: str | None) -> Severity:
    """Wandelt einen CSAF-Severity-String in das kanonische ``Severity``.

    CSAF nutzt die Strings ``critical``/``high``/``medium``/``low``
    (case-insensitive). Unbekannte Werte und ``None`` werden auf
    ``Severity.INFO`` gemappt.

    Achtung: CSAF kennt kein ``info`` — bei einem Roundtrip zurück nach
    CSAF muss ``INFO`` daher gesondert behandelt werden (z. B. als
    ``"none"`` oder ausgeblendet).
    """
    if value is None:
        return Severity.INFO
    return _CSAF_TO_SEVERITY.get(value.strip().lower(), Severity.INFO)


def from_cvss(score: float | None) -> Severity:
    """Wandelt einen CVSS-v3-Base-Score (0.0–10.0) in ``Severity``.

    Mapping nach CVSS v3.1 Spec §5 (Qualitative Severity Rating Scale):

    - ``>= 9.0`` → ``CRITICAL``
    - ``>= 7.0`` → ``HIGH``
    - ``>= 4.0`` → ``MEDIUM``
    - ``> 0.0`` → ``LOW``
    - sonst (``0.0`` oder ``None``) → ``INFO``

    Werte außerhalb [0.0, 10.0] werden nicht gesondert behandelt — die
    Spec lässt nur Scores in diesem Bereich zu; Aufrufer ist für
    Eingabe-Validierung verantwortlich.
    """
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


# Mapping der bestehenden ``VulnSeverity``-Enum-Werte aus
# ``tools/dependency_auditor/domain/models.py`` (deutsche Großbuchstaben)
# auf das kanonische Severity. ``VulnSeverity`` kennt kein ``INFO`` —
# bei einem Roundtrip muss ``INFO`` gesondert behandelt werden.
_VULN_SEVERITY_TO_SEVERITY: dict[str, Severity] = {
    "kritisch": Severity.CRITICAL,
    "hoch": Severity.HIGH,
    "mittel": Severity.MEDIUM,
    "niedrig": Severity.LOW,
    # ``Schweregrad`` (cyber_dashboard) verwendet zusätzlich ``info`` —
    # kein eigener Helper, weil das kanonische Mapping ohnehin identisch
    # wäre. Konsumenten können ``Schweregrad.value`` in Kleinbuchstaben
    # durchreichen.
    "info": Severity.INFO,
}


def from_vuln_severity(value: str | None) -> Severity:
    """Wandelt einen ``VulnSeverity``-/``Schweregrad``-Wert in ``Severity``.

    Akzeptiert die deutschen Werte aus
    ``tools/dependency_auditor/domain/models.py`` (``KRITISCH``/``HOCH``/
    ``MITTEL``/``NIEDRIG``) sowie die Werte aus
    ``tools/cyber_dashboard/domain/models.py`` (``kritisch``/``hoch``/
    ``mittel``/``niedrig``/``info``). Vergleich ist case-insensitive,
    Whitespace wird getrimmt.

    Unbekannte Werte und ``None`` werden auf ``Severity.INFO`` gemappt.

    Achtung: ``VulnSeverity`` kennt kein ``INFO`` — bei einem Roundtrip
    muss ``INFO`` gesondert behandelt werden.
    """
    if value is None:
        return Severity.INFO
    return _VULN_SEVERITY_TO_SEVERITY.get(value.strip().lower(), Severity.INFO)
