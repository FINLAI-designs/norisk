"""
risk_entities — BSI-200-3-Risiko-Matrix fuer den Customer-Audit-Wizard.

Iter 2e: Domain-Modelle fuer die vereinfachte
Risiko-Methodik nach BSI 200-3:

- 4x4-Matrix (Eintrittswahrscheinlichkeit x Schadenshoehe)
- 4 Risiko-Stufen (gering / mittel / hoch / sehr hoch)
- 10 Default-Risiken vor-konfiguriert (Konzept §5.2)
- User-Customs ergaenzbar (Patrick-Direktive 2026-05-15)
- Massnahmen-Mapping auf bestehende NoRisk-Tools

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Final

MAX_RISK_TITLE_LENGTH: int = 200
MAX_RISK_DESCRIPTION_LENGTH: int = 1000
MAX_RISK_NOTES_LENGTH: int = 2000


class RiskProbability(Enum):
    """Eintrittswahrscheinlichkeit nach BSI 200-3 (4-stufig).

    Werte als Punktezahlen — multiplikativ verrechnet mit
:class:`RiskImpact` zur:class:`RiskLevel`-Ableitung.
    """

    SELTEN = 1  # < 1x pro Jahr
    MITTEL = 2  # 1-2x pro Jahr
    HAEUFIG = 3  # mehrfach pro Jahr
    SEHR_HAEUFIG = 4  # quasi laufend

    @property
    def label(self) -> str:
        return {
            RiskProbability.SELTEN: "selten",
            RiskProbability.MITTEL: "mittel",
            RiskProbability.HAEUFIG: "haeufig",
            RiskProbability.SEHR_HAEUFIG: "sehr haeufig",
        }[self]


class RiskImpact(Enum):
    """Schadenshoehe nach BSI 200-3 (4-stufig)."""

    VERNACHLAESSIGBAR = 1  # finanzielle Schaden < 5k EUR, keine Datenverluste
    BEGRENZT = 2  # 5k-50k EUR, einzelne Stunden Ausfall
    BETRAECHTLICH = 3  # 50k-500k EUR, Tage Ausfall, einzelne Datenverluste
    EXISTENZBEDROHEND = 4  # > 500k EUR oder Mandantenverlust / Lizenzentzug

    @property
    def label(self) -> str:
        return {
            RiskImpact.VERNACHLAESSIGBAR: "vernachlaessigbar",
            RiskImpact.BEGRENZT: "begrenzt",
            RiskImpact.BETRAECHTLICH: "betraechtlich",
            RiskImpact.EXISTENZBEDROHEND: "existenzbedrohend",
        }[self]


class RiskLevel(Enum):
    """Aggregierte Risiko-Stufe (4-stufig).

    Ableitung aus ``probability.value * impact.value`` (1..16):
        1-3 → GERING
        4-6 → MITTEL
        7-9 → HOCH
        10-16 → SEHR_HOCH

    Schwellen folgen BSI-200-3-Praxis: 25% / 50% / 75% des Score-Bereichs.
    """

    GERING = "gering"
    MITTEL = "mittel"
    HOCH = "hoch"
    SEHR_HOCH = "sehr_hoch"

    @classmethod
    def from_score(cls, probability: RiskProbability, impact: RiskImpact) -> RiskLevel:
        score = probability.value * impact.value
        if score <= 3:
            return cls.GERING
        if score <= 6:
            return cls.MITTEL
        if score <= 9:
            return cls.HOCH
        return cls.SEHR_HOCH

    @property
    def label(self) -> str:
        return {
            RiskLevel.GERING: "gering",
            RiskLevel.MITTEL: "mittel",
            RiskLevel.HOCH: "hoch",
            RiskLevel.SEHR_HOCH: "sehr hoch",
        }[self]


class RiskCategory(Enum):
    """Risiko-Kategorien — gruppieren die Defaults fuer UI-Filtering."""

    CYBER = "cyber"  # Ransomware, Phishing, Datenexfiltration
    DATEN = "daten"  # Datenverlust, Mandantendaten-Diebstahl
    TECHNIK = "technik"  # Hardware-Defekt, Patch-Luecke
    ORGANISATION = "organisation"  # Insider, Mitarbeiter-Fehler
    EXTERN = "extern"  # Stromausfall, Lieferketten-Ausfall
    COMPLIANCE = "compliance"  # DSGVO-Verstoss, Berufsrechts-Verletzung


@dataclass(frozen=True)
class RiskCatalogEntry:
    """Vorlage fuer ein Standard-Risiko aus dem Default-Katalog.

    Statisch im Code definiert (:data:`DEFAULT_RISK_CATALOG`). Wird
    per Audit in einen:class:`RiskAssessment` materialisiert.

    Attributes:
        key: Stabiler Schluessel (z. B. ``"ransomware"``).
        title: Anzeige-Titel.
        description: 1-3 Saetze, was das Risiko konkret bedeutet.
        category::class:`RiskCategory`.
        default_probability: Vor-eingestellter Schaetzwert.
        default_impact: Vor-eingestellter Schaetzwert.
        recommended_tools: Liste von NoRisk-Tool-Namen (z. B.
                             ``("patch_monitor", "csaf_advisor")``), die
                             dem User helfen das Risiko zu mitigieren.
    """

    key: str
    title: str
    description: str
    category: RiskCategory
    default_probability: RiskProbability
    default_impact: RiskImpact
    recommended_tools: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.key.strip():
            raise ValueError("RiskCatalogEntry.key darf nicht leer sein.")
        if not self.title.strip():
            raise ValueError("RiskCatalogEntry.title darf nicht leer sein.")
        if len(self.title) > MAX_RISK_TITLE_LENGTH:
            raise ValueError(
                f"RiskCatalogEntry.title darf max. {MAX_RISK_TITLE_LENGTH} Zeichen haben."
            )
        if len(self.description) > MAX_RISK_DESCRIPTION_LENGTH:
            raise ValueError(
                f"RiskCatalogEntry.description darf max. "
                f"{MAX_RISK_DESCRIPTION_LENGTH} Zeichen haben."
            )

    @property
    def default_level(self) -> RiskLevel:
        return RiskLevel.from_score(self.default_probability, self.default_impact)


@dataclass(frozen=True)
class RiskAssessment:
    """Risiko-Bewertung im Kontext eines konkreten Audits.

    Wenn ``is_custom = True``: vom User definiertes Risiko (``catalog_key``
    leer, ``custom_title`` Pflicht). Sonst: Verweis auf einen
:class:`RiskCatalogEntry` per ``catalog_key``.

    Attributes:
        id: Datenbank-ID (``None`` vor INSERT).
        audit_id: FK zur Audit-ID.
        catalog_key: Schluessel im Default-Catalog (oder leer bei Custom).
        custom_title: User-Titel bei Custom-Risiko.
        custom_description: User-Beschreibung bei Custom-Risiko.
        custom_category::class:`RiskCategory` bei Custom-Risiko
                           (sonst aus dem Catalog).
        probability: Aktuelle Eintrittswahrscheinlichkeit.
        impact: Aktuelle Schadenshoehe.
        notes: Optionale Notizen vom Auditor.
        is_custom: ``True`` wenn User-definiert.
        is_accepted: User hat das Risiko **bewusst akzeptiert**
                           (nicht weiter mitigiert) — analog "deferred"
                           im Detection-Modell.
        created_at: UTC-Stamp.
        updated_at: UTC-Stamp.
    """

    id: int | None
    audit_id: str
    catalog_key: str
    probability: RiskProbability
    impact: RiskImpact
    custom_title: str = ""
    custom_description: str = ""
    custom_category: RiskCategory | None = None
    notes: str = ""
    is_custom: bool = False
    is_accepted: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        # ``audit_id`` darf transient leer sein (Wizard-Bauphase), wird
        # vor dem Persist-Call vom Wizard mit der echten Audit-UUID ersetzt.
        if self.is_custom:
            if self.catalog_key:
                raise ValueError(
                    "RiskAssessment.is_custom=True schliesst catalog_key aus."
                )
            title = self.custom_title.strip()
            if not title:
                raise ValueError(
                    "RiskAssessment: custom_title ist Pflicht bei is_custom=True."
                )
            if len(title) > MAX_RISK_TITLE_LENGTH:
                raise ValueError(
                    f"RiskAssessment.custom_title darf max. "
                    f"{MAX_RISK_TITLE_LENGTH} Zeichen haben."
                )
            if self.custom_category is None:
                raise ValueError(
                    "RiskAssessment: custom_category ist Pflicht bei is_custom=True."
                )
            if title != self.custom_title:
                object.__setattr__(self, "custom_title", title)
        else:
            if not self.catalog_key.strip():
                raise ValueError(
                    "RiskAssessment.catalog_key ist Pflicht bei is_custom=False."
                )
        if len(self.notes) > MAX_RISK_NOTES_LENGTH:
            raise ValueError(
                f"RiskAssessment.notes darf max. {MAX_RISK_NOTES_LENGTH} "
                "Zeichen haben."
            )
        if len(self.custom_description) > MAX_RISK_DESCRIPTION_LENGTH:
            raise ValueError(
                f"RiskAssessment.custom_description darf max. "
                f"{MAX_RISK_DESCRIPTION_LENGTH} Zeichen haben."
            )

    @property
    def level(self) -> RiskLevel:
        return RiskLevel.from_score(self.probability, self.impact)

    def display_title(self, catalog: dict[str, RiskCatalogEntry]) -> str:
        """Anzeige-Titel: aus Catalog-Lookup oder Custom-Title."""
        if self.is_custom:
            return self.custom_title
        entry = catalog.get(self.catalog_key)
        return entry.title if entry is not None else self.catalog_key

    def category(self, catalog: dict[str, RiskCatalogEntry]) -> RiskCategory:
        if self.is_custom and self.custom_category is not None:
            return self.custom_category
        entry = catalog.get(self.catalog_key)
        return entry.category if entry is not None else RiskCategory.CYBER


# ---------------------------------------------------------------------------
# 10 Default-Risiken (Konzept §5.2 / Patrick-Direktive 2026-05-15)
# ---------------------------------------------------------------------------


DEFAULT_RISK_CATALOG: Final[tuple[RiskCatalogEntry, ...]] = (
    RiskCatalogEntry(
        key="ransomware",
        title="Ransomware-Angriff",
        description=(
            "Verschluesselung kritischer Daten durch Schadsoftware. Bei einer "
            "Kanzlei droht Stillstand, Loesegeld-Erpressung und Daten-Leck."
        ),
        category=RiskCategory.CYBER,
        default_probability=RiskProbability.MITTEL,
        default_impact=RiskImpact.EXISTENZBEDROHEND,
        recommended_tools=(
            "patch_monitor",
            "csaf_advisor",
            "system_scanner",
            "email_scanner",
        ),
    ),
    RiskCatalogEntry(
        key="phishing",
        title="Phishing / Spear-Phishing",
        description=(
            "Gezielte Mail-/SMS-Angriffe auf Mitarbeiter zur Kompromittierung "
            "von Zugangsdaten oder Schadsoftware-Installation."
        ),
        category=RiskCategory.CYBER,
        default_probability=RiskProbability.HAEUFIG,
        default_impact=RiskImpact.BETRAECHTLICH,
        recommended_tools=("email_scanner", "password_checker"),
    ),
    RiskCatalogEntry(
        key="mandantendaten_leak",
        title="Mandantendaten-Diebstahl / -Leck",
        description=(
            "Unautorisierter Abfluss vertraulicher Mandantendaten (Cyber-"
            "Einbruch, Insider, USB-Stick-Verlust)."
        ),
        category=RiskCategory.DATEN,
        default_probability=RiskProbability.MITTEL,
        default_impact=RiskImpact.EXISTENZBEDROHEND,
        recommended_tools=(
            "document_scanner",
            "system_scanner",
            "supply_chain_monitor",
        ),
    ),
    RiskCatalogEntry(
        key="patch_luecke",
        title="Ungepatchte Sicherheitsluecke",
        description=(
            "Bekannte CVE in installierter Software wird nicht zeitnah gepatcht — "
            "Angreifer nutzt sie als Einstieg."
        ),
        category=RiskCategory.TECHNIK,
        default_probability=RiskProbability.HAEUFIG,
        default_impact=RiskImpact.BETRAECHTLICH,
        recommended_tools=("patch_monitor", "csaf_advisor", "system_scanner"),
    ),
    RiskCatalogEntry(
        key="backup_ausfall",
        title="Backup-Ausfall im Ernstfall",
        description=(
            "Im Wiederherstellungsfall (Ransomware, Hardware-Defekt) sind "
            "Backups unvollstaendig, korrupt oder zu alt."
        ),
        category=RiskCategory.TECHNIK,
        default_probability=RiskProbability.MITTEL,
        default_impact=RiskImpact.EXISTENZBEDROHEND,
        recommended_tools=("system_scanner",),
    ),
    RiskCatalogEntry(
        key="insider_bedrohung",
        title="Insider-Bedrohung",
        description=(
            "Aktiver oder ehemaliger Mitarbeiter missbraucht Berechtigungen "
            "vorsaetzlich oder fahrlaessig."
        ),
        category=RiskCategory.ORGANISATION,
        default_probability=RiskProbability.SELTEN,
        default_impact=RiskImpact.BETRAECHTLICH,
        recommended_tools=("supply_chain_monitor",),
    ),
    RiskCatalogEntry(
        key="hardware_defekt",
        title="Hardware-Defekt kritischer Komponente",
        description=(
            "Server, NAS oder Workstation-Festplatte faellt aus — Datenverlust "
            "oder Stillstand bis Ersatz beschafft ist."
        ),
        category=RiskCategory.TECHNIK,
        default_probability=RiskProbability.MITTEL,
        default_impact=RiskImpact.BEGRENZT,
        recommended_tools=("system_scanner",),
    ),
    RiskCatalogEntry(
        key="stromausfall",
        title="Stromausfall / Stoerung Infrastruktur",
        description=(
            "Laengere Unterbrechung der Stromversorgung oder Internet-Anbindung "
            "blockiert den Kanzleibetrieb."
        ),
        category=RiskCategory.EXTERN,
        default_probability=RiskProbability.MITTEL,
        default_impact=RiskImpact.BEGRENZT,
        recommended_tools=(),
    ),
    RiskCatalogEntry(
        key="mitarbeiter_fehler",
        title="Mitarbeiter-Fehler (versehentliche Datenfreigabe)",
        description=(
            "Fehl-Adressierung von E-Mails, falsche Bedienung Cloud-Sharing, "
            "Verlust mobiler Geraete."
        ),
        category=RiskCategory.ORGANISATION,
        default_probability=RiskProbability.HAEUFIG,
        default_impact=RiskImpact.BEGRENZT,
        recommended_tools=("email_scanner",),
    ),
    RiskCatalogEntry(
        key="compliance_verstoss",
        title="DSGVO- oder Berufsrechts-Verstoss",
        description=(
            "Fehlende AVVs, mangelhafte Loeschkonzepte oder unzureichende "
            "Datenschutzfolgenabschaetzung fuehren zu Aufsichts-Sanktionen."
        ),
        category=RiskCategory.COMPLIANCE,
        default_probability=RiskProbability.MITTEL,
        default_impact=RiskImpact.BETRAECHTLICH,
        recommended_tools=("supply_chain_monitor",),
    ),
)


DEFAULT_RISK_CATALOG_BY_KEY: Final[dict[str, RiskCatalogEntry]] = {
    entry.key: entry for entry in DEFAULT_RISK_CATALOG
}


def risk_score_matrix() -> list[list[int]]:
    """Liefert die 4x4-Score-Matrix [probability][impact] (1..4 indexiert).

    Wird vom UI fuer die Heatmap-Darstellung gebraucht.
    """
    matrix: list[list[int]] = []
    for prob in (
        RiskProbability.SELTEN,
        RiskProbability.MITTEL,
        RiskProbability.HAEUFIG,
        RiskProbability.SEHR_HAEUFIG,
    ):
        row: list[int] = []
        for imp in (
            RiskImpact.VERNACHLAESSIGBAR,
            RiskImpact.BEGRENZT,
            RiskImpact.BETRAECHTLICH,
            RiskImpact.EXISTENZBEDROHEND,
        ):
            row.append(prob.value * imp.value)
        matrix.append(row)
    return matrix
