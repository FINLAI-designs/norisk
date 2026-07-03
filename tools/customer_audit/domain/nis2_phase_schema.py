"""nis2_phase_schema — Pro-Phase-Pflichtformulare fuer den NIS2-Tracker.

Definiert je:class:`~tools.customer_audit.domain.nis2_incident.IncidentPhase`
eine Liste von Formularfeldern (Pflicht + optional) gemaess NIS2 Art. 23 /
Art. 23 Abs. 4 und der DSGVO-Art.33-Verzweigung. Die Inhalte stammen aus
 §1 (Pro-Phase-Pflichtformulare).

Das Schema ist die *eine* Quelle der Wahrheit fuer:

- Die GUI (rendert die Felder je Phase — Schicht 2, nicht Teil dieses Backends).
- Die Service-Schicht (:func:`validate` prueft Pflichtfelder vor ``append_phase_event``).

Bewusst KEINE typisierten DB-Spalten — die Daten landen als JSON-``payload``
in ``nis2_phase_events`` §1). Schema-Aenderungen erhoehen
``payload_schema_version``, nicht das DB-Layout.

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui.

ADR-Bezug: docs/adr/-nis2-tracker-revisionssicher.md §1.

Author: Patrick Riederich
Version: 0.1 (NIS2-revisionssicher, Schicht 1 Backend)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from tools.customer_audit.domain.nis2_incident import IncidentPhase

#: Hinweistext fuer alle Freitextfelder (Logger-Redaction-Analogie §4).
#: Wird in der GUI als Feld-Hilfetext angezeigt, damit keine direkt
#: identifizierenden Personendaten in den (nur HMAC-, nicht
#: pseudonymisierungs-)geschuetzten Trail wandern.
PII_HINWEIS: Final[str] = (
    "Bitte KEINE Klarnamen, IBANs, vollstaendigen E-Mail-Adressen oder "
    "sonstige direkt identifizierenden Personendaten eintragen — nur "
    "Rollen/Funktionen und sachliche Beschreibung. Personenbezug wird ueber "
    "das Flag erfasst, nicht ueber Freitext."
)


class FieldType(StrEnum):
    """Eingabetyp eines Formularfeldes (steuert das GUI-Widget)."""

    TEXT = "text"
    MULTILINE = "multiline"
    BOOL = "bool"
    TRISTATE = "tristate"  # ja / nein / unbekannt
    NUMBER = "number"
    LIST = "list"  # Liste von Strings (z. B. IoCs)
    DATETIME = "datetime"


@dataclass(frozen=True, slots=True)
class FormField:
    """Beschreibt ein einzelnes Phasen-Formularfeld.

    Attributes:
        key: Stabiler Payload-Schluessel (snake_case, im JSON-payload).
        label: Anzeigetext fuer die GUI.
        typ::class:`FieldType` — steuert das Eingabe-Widget.
        required: True, wenn das Feld zum Einreichen der Phase Pflicht ist.
        help_text: "Was-zu-tun"-Hilfetext §1).
    """

    key: str
    label: str
    typ: FieldType
    required: bool
    help_text: str


#: Pro-Phase-Formularfelder. Schluessel = IncidentPhase. Reihenfolge ist die
#: Render-Reihenfolge in der GUI. Phasen ohne Eintrag (z. B. POST_INCIDENT)
#: haben kein Pflichtformular.
_PHASE_FORMS: Final[dict[IncidentPhase, tuple[FormField, ...]]] = {
    IncidentPhase.DETECT: (
        FormField(
            key="kenntnisnahme_zeitpunkt",
            label="Zeitpunkt der Kenntnisnahme",
            typ=FieldType.DATETIME,
            required=True,
            help_text=(
                "Wann wurde der Vorfall erstmals bemerkt? Dieser Zeitpunkt "
                "verankert die NIS2-Fristen (24h/72h/30d)."
            ),
        ),
        FormField(
            key="quelle",
            label="Quelle der Meldung",
            typ=FieldType.TEXT,
            required=False,
            help_text="Wer/was hat den Vorfall gemeldet? (Rolle, System, Alarm)",
        ),
    ),
    IncidentPhase.TRIAGE: (
        FormField(
            key="ersteinschaetzung",
            label="Ersteinschaetzung",
            typ=FieldType.MULTILINE,
            required=True,
            help_text="Kurze sachliche Einordnung des Vorfalls.",
        ),
        FormField(
            key="erheblich",
            label="Erheblicher Vorfall im NIS2-Sinn?",
            typ=FieldType.TRISTATE,
            required=True,
            help_text=(
                "Ja/Nein/Unbekannt — steuert, ob eine Meldepflicht greift."
            ),
        ),
    ),
    IncidentPhase.EARLY_WARNING: (
        FormField(
            key="verdacht_rechtswidrig",
            label="Verdacht auf rechtswidrige/boeswillige Handlung?",
            typ=FieldType.TRISTATE,
            required=True,
            help_text="NIS2 Art.23: Ja/Nein/Unbekannt fuer die 24h-Fruehwarnung.",
        ),
        FormField(
            key="grenzueberschreitend",
            label="Grenzueberschreitende Auswirkungen?",
            typ=FieldType.TRISTATE,
            required=True,
            help_text="Sind andere EU-Mitgliedstaaten betroffen?",
        ),
        FormField(
            key="betroffene_dienste",
            label="Betroffene Dienste/Systeme",
            typ=FieldType.MULTILINE,
            required=True,
            help_text="Welche Dienste sind beeintraechtigt? (Funktion, nicht Person)",
        ),
        FormField(
            key="sofortmassnahmen",
            label="Ergriffene Sofortmassnahmen",
            typ=FieldType.MULTILINE,
            required=False,
            help_text="Was wurde bereits zur Eindaemmung getan?",
        ),
    ),
    IncidentPhase.NOTIFICATION: (
        FormField(
            key="schweregrad",
            label="Schweregrad",
            typ=FieldType.TEXT,
            required=True,
            help_text="low/medium/high/critical — Klassifikation des Vorfalls.",
        ),
        FormField(
            key="impact_verfuegbarkeit",
            label="Auswirkung auf Verfuegbarkeit",
            typ=FieldType.MULTILINE,
            required=True,
            help_text="Ausfaelle, Dauer, betroffene Nutzerzahl (aggregiert).",
        ),
        FormField(
            key="impact_integritaet",
            label="Auswirkung auf Integritaet/Vertraulichkeit",
            typ=FieldType.MULTILINE,
            required=False,
            help_text="Datenabfluss/-manipulation? Sachlich beschreiben.",
        ),
        FormField(
            key="erste_ursache",
            label="Erste Ursachenvermutung",
            typ=FieldType.MULTILINE,
            required=True,
            help_text="Vorlaeufige Einschaetzung der Ursache.",
        ),
        FormField(
            key="iocs",
            label="Indicators of Compromise (IoCs)",
            typ=FieldType.LIST,
            required=False,
            help_text="Technische Indikatoren (Hashes, IPs, Domains).",
        ),
        FormField(
            key="personenbezug",
            label="Personenbezogene Daten betroffen?",
            typ=FieldType.BOOL,
            required=True,
            help_text=(
                "Steuert die DSGVO-Art.33-72h-Meldung an die Datenschutzbehoerde."
            ),
        ),
        FormField(
            key="kommunikationsstatus",
            label="Kommunikationsstatus",
            typ=FieldType.TEXT,
            required=False,
            help_text="Wurden Betroffene/CSIRT/Behoerden informiert?",
        ),
    ),
    IncidentPhase.FINAL_REPORT: (
        FormField(
            key="beschreibung",
            label="Abschliessende Vorfallsbeschreibung",
            typ=FieldType.MULTILINE,
            required=True,
            help_text="Vollstaendiger Hergang des Vorfalls.",
        ),
        FormField(
            key="ursache",
            label="Endgueltige Ursache (Root Cause)",
            typ=FieldType.MULTILINE,
            required=True,
            help_text="Festgestellte Grundursache.",
        ),
        FormField(
            key="massnahmen",
            label="Ergriffene und geplante Massnahmen",
            typ=FieldType.MULTILINE,
            required=True,
            help_text="Behebung + praeventive Massnahmen.",
        ),
        FormField(
            key="grenzueberschreitend",
            label="Grenzueberschreitende Auswirkungen (final)",
            typ=FieldType.TRISTATE,
            required=True,
            help_text="Abschliessende Bewertung der grenzueberschreitenden Wirkung.",
        ),
    ),
    IncidentPhase.POST_INCIDENT: (),
}


def fields_for(phase: IncidentPhase) -> tuple[FormField, ...]:
    """Pure: liefert die Formularfelder einer Phase (leer wenn ohne Formular).

    Args:
        phase: Die abzufragende Phase.

    Returns:
        Tuple der:class:`FormField` in Render-Reihenfolge.
    """
    return _PHASE_FORMS.get(phase, ())


def required_keys(phase: IncidentPhase) -> list[str]:
    """Pure: Payload-Schluessel der Pflichtfelder einer Phase.

    Args:
        phase: Die abzufragende Phase.

    Returns:
        Liste der ``key``-Werte aller als ``required`` markierten Felder.
    """
    return [f.key for f in fields_for(phase) if f.required]


def validate(phase: IncidentPhase, payload: dict) -> list[str]:
    """Pure: prueft, welche Pflichtfelder im ``payload`` fehlen.

    Ein Pflichtfeld gilt als fehlend, wenn der Schluessel nicht vorhanden ist
    oder sein Wert ``None``, leerer String oder reines Whitespace ist. Fuer
    Listen/Dicts gilt eine leere Sammlung ebenfalls als fehlend. ``False`` (z. B.
    ein BOOL-Pflichtfeld) ist ein gueltiger Wert und gilt NICHT als fehlend.

    Args:
        phase: Die einzureichende Phase.
        payload: Die strukturierten Formulardaten.

    Returns:
        Liste der ``key``-Werte fehlender Pflichtfelder (leer = valide).
    """
    fehlende: list[str] = []
    for key in required_keys(phase):
        if key not in payload or _is_empty(payload[key]):
            fehlende.append(key)
    return fehlende


def _is_empty(value: object) -> bool:
    """Pure: True, wenn ein Wert als "nicht ausgefuellt" gilt.

    ``None``, leerer/whitespace-String und leere Sammlung sind leer. ``False``
    (z. B. ein BOOL-Pflichtfeld) ist ein gueltiger Wert und NICHT leer.

    Args:
        value: Der zu pruefende Feldwert.

    Returns:
        True, wenn der Wert als fehlend zu werten ist.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, dict)):
        return len(value) == 0
    return False
