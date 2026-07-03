"""
models — Domain-Modelle fuer den Awareness-Tracker.

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui.

Iteration 3a: Employee + Training + Validity-Berechnung.
TrainingType-Enum mit den 5 Standard-Typen einer Kanzlei (DSGVO/IT-Security/
Phishing/Incident-Response/Compliance-BRAO) plus CUSTOM. Phishing-Sim-Events
(``PhishingSimEvent``) kommen in 3c — die Strukturen hier sind Schulungs-
Tracking-fokussiert.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum

MAX_NAME_LENGTH: int = 200
MAX_EMAIL_LENGTH: int = 320  # RFC 5321
MAX_ROLE_LENGTH: int = 100
MAX_DEPARTMENT_LENGTH: int = 100
MAX_NOTES_LENGTH: int = 2000
MAX_TITLE_LENGTH: int = 200
MAX_CUSTOM_TYPE_LABEL_LENGTH: int = 100
MAX_PROVIDER_LENGTH: int = 200

# Validity-Schwellwerte fuer Schulungs-Auffrischung.
TRAINING_VALIDITY_WARNING_DAYS_DEFAULT: int = 60

# Iter 3c — Phishing-Sim-Logger.
MAX_CAMPAIGN_NAME_LENGTH: int = 200
MAX_VENDOR_LABEL_LENGTH: int = 100


class TrainingType(Enum):
    """Standard-Schulungstypen einer Kanzlei.

    Die Auswahl folgt den fuer Berufsgeheimnistraeger relevanten Pflicht-
    Schulungen (DSGVO Art. 39 Abs. 1 lit. b, BRAO §43e). ``CUSTOM`` deckt
    interne Spezial-Schulungen ab — dann ist ``Training.custom_type_label``
    Pflicht.
    """

    DSGVO_BASICS = "dsgvo_basics"  # Datenschutz-Grundlagen
    IT_SECURITY = "it_security"  # IT-Sicherheit allgemein
    PHISHING_AWARENESS = "phishing_awareness"  # Phishing-/Social-Engineering
    INCIDENT_RESPONSE = "incident_response"  # Notfall-/Meldepflicht-Drill
    COMPLIANCE_BRAO = "compliance_brao"  # Berufsrecht / Verschwiegenheit
    CUSTOM = "custom"  # Kanzlei-spezifische Schulung

    @classmethod
    def from_value(cls, value: str) -> TrainingType:
        """Robuste Konvertierung aus DB-String mit Default-Fallback.

        Args:
            value: Roh-String aus der DB.

        Returns:
            Passende:class:`TrainingType`; bei unbekanntem Wert ``CUSTOM``.
        """
        try:
            return cls(value)
        except ValueError:
            return cls.CUSTOM


class ValidityStatus(Enum):
    """Aggregierter Status einer Schulung gegen ``valid_until``."""

    VALID = "valid"  # Noch gueltig mit ausreichend Puffer
    EXPIRING_SOON = "expiring_soon"  # 0..warning_days Puffer
    EXPIRED = "expired"  # ``valid_until`` in der Vergangenheit
    PERMANENT = "permanent"  # Schulung ohne Ablaufdatum (Onboarding o.ae.)


@dataclass(frozen=True)
class Employee:
    """Ein Mitarbeiter / eine Mitarbeiterin im Awareness-Tracker.

    Die DB speichert die Stamm-Daten verschluesselt (SQLCipher) — Mail-
    Adresse + Rolle sind PII und sollen die DB nicht ungeschuetzt verlassen.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        full_name: Anzeige-Name (1..200 Zeichen, getrimmt).
        email: E-Mail-Adresse (optional, max. 320 Zeichen).
        role: Funktion (z. B. ``"Anwaltsfachangestellte"``).
        department: Abteilung / Standort (Freitext).
        is_active: ``False`` markiert Off-Boarded-Mitarbeiter — Eintraege
                     bleiben fuer Audit-Historie erhalten, fallen aber aus
                     Reminder-Listen heraus.
        notes: Freitext (max. 2000 Zeichen).
        created_at: Erst-Anlage (UTC).
        updated_at: Letzte Aenderung (UTC).

    Raises:
        ValueError: Bei leerem ``full_name`` oder ueberlangem Eingabe-Feld.
    """

    id: int | None
    full_name: str
    email: str = ""
    role: str = ""
    department: str = ""
    is_active: bool = True
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        name = self.full_name.strip()
        if not name:
            raise ValueError("Employee.full_name darf nicht leer sein.")
        if len(name) > MAX_NAME_LENGTH:
            raise ValueError(
                f"Employee.full_name darf max. {MAX_NAME_LENGTH} Zeichen "
                f"haben (aktuell {len(name)})."
            )
        email = self.email.strip()
        if len(email) > MAX_EMAIL_LENGTH:
            raise ValueError(
                f"Employee.email darf max. {MAX_EMAIL_LENGTH} Zeichen haben."
            )
        role = self.role.strip()
        if len(role) > MAX_ROLE_LENGTH:
            raise ValueError(
                f"Employee.role darf max. {MAX_ROLE_LENGTH} Zeichen haben."
            )
        department = self.department.strip()
        if len(department) > MAX_DEPARTMENT_LENGTH:
            raise ValueError(
                f"Employee.department darf max. {MAX_DEPARTMENT_LENGTH} "
                f"Zeichen haben."
            )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"Employee.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben."
            )
        # frozen → object.__setattr__ als einzige Normalisierungs-Moeglichkeit.
        if name != self.full_name:
            object.__setattr__(self, "full_name", name)
        if email != self.email:
            object.__setattr__(self, "email", email)
        if role != self.role:
            object.__setattr__(self, "role", role)
        if department != self.department:
            object.__setattr__(self, "department", department)


@dataclass(frozen=True)
class Training:
    """Eine absolvierte Schulung eines:class:`Employee`.

    Ein Training bezieht sich auf einen Typ + Titel + Datum. Wenn
    ``valid_until`` gesetzt ist, gilt die Schulung als renewable (z. B.
    DSGVO-Auffrischung alle 2 Jahre). ``None`` heisst Permanent (z. B.
    Onboarding-Schulung, einmaliger Workshop).

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        employee_id: FK zu:class:`Employee`.
        training_type::class:`TrainingType`.
        title: Konkrete Schulungs-Bezeichnung (1..200 Zeichen).
        completed_at: Abschluss-Datum (UTC). Pflicht.
        valid_until: Ablauf-Datum (UTC) oder ``None`` (permanent).
        provider: Schulungs-Anbieter (max. 200 Zeichen, optional).
        custom_type_label: Pflicht wenn ``training_type == CUSTOM``;
                             sonst ignoriert. Max. 100 Zeichen.
        notes: Freitext (max. 2000 Zeichen).
        created_at: Erst-Anlage des DB-Eintrags (UTC).

    Raises:
        ValueError: Bei leerem Title, fehlendem custom_type_label fuer
            CUSTOM, oder valid_until < completed_at.
    """

    id: int | None
    employee_id: int
    training_type: TrainingType
    title: str
    completed_at: datetime
    valid_until: datetime | None = None
    provider: str = ""
    custom_type_label: str = ""
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        title = self.title.strip()
        if not title:
            raise ValueError("Training.title darf nicht leer sein.")
        if len(title) > MAX_TITLE_LENGTH:
            raise ValueError(
                f"Training.title darf max. {MAX_TITLE_LENGTH} Zeichen haben "
                f"(aktuell {len(title)})."
            )
        provider = self.provider.strip()
        if len(provider) > MAX_PROVIDER_LENGTH:
            raise ValueError(
                f"Training.provider darf max. {MAX_PROVIDER_LENGTH} Zeichen haben."
            )
        custom_label = self.custom_type_label.strip()
        if self.training_type is TrainingType.CUSTOM:
            if not custom_label:
                raise ValueError(
                    "Training.custom_type_label ist Pflicht bei training_type=CUSTOM."
                )
            if len(custom_label) > MAX_CUSTOM_TYPE_LABEL_LENGTH:
                raise ValueError(
                    f"Training.custom_type_label darf max. "
                    f"{MAX_CUSTOM_TYPE_LABEL_LENGTH} Zeichen haben."
                )
        else:
            # Non-CUSTOM-Trainings duerfen kein custom_type_label tragen
            # (Datenhygiene). Wir werfen nicht, sondern normalisieren leer.
            custom_label = ""
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"Training.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben."
            )
        if self.valid_until is not None and self.valid_until < self.completed_at:
            raise ValueError(
                "Training.valid_until darf nicht vor completed_at liegen."
            )
        if title != self.title:
            object.__setattr__(self, "title", title)
        if provider != self.provider:
            object.__setattr__(self, "provider", provider)
        if custom_label != self.custom_type_label:
            object.__setattr__(self, "custom_type_label", custom_label)

    def validity_status(
        self,
        now: datetime | None = None,
        warning_days: int = TRAINING_VALIDITY_WARNING_DAYS_DEFAULT,
    ) -> ValidityStatus:
        """Berechnet den Validity-Status gegen ``valid_until``.

        Args:
            now: Referenz-Zeitpunkt. Default: ``datetime.now(UTC)``.
                          Wird in Tests injiziert.
            warning_days: Schwelle fuer ``EXPIRING_SOON``. Default: 60.

        Returns:
            ``PERMANENT`` wenn ``valid_until is None``, sonst eine der
            anderen drei Stufen.
        """
        if self.valid_until is None:
            return ValidityStatus.PERMANENT
        reference = now or datetime.now(UTC)
        if self.valid_until < reference:
            return ValidityStatus.EXPIRED
        if (self.valid_until - reference) <= timedelta(days=warning_days):
            return ValidityStatus.EXPIRING_SOON
        return ValidityStatus.VALID

    @property
    def display_type_label(self) -> str:
        """Anzeige-Label des Trainingstyps.

        Fuer CUSTOM wird das ``custom_type_label`` zurueckgegeben, sonst
        eine Title-Case-Ableitung aus dem Enum-Wert.
        """
        if self.training_type is TrainingType.CUSTOM and self.custom_type_label:
            return self.custom_type_label
        return self.training_type.value.replace("_", " ").title()


# ---------------------------------------------------------------------------
# Iter 3c — Phishing-Simulations-Logger
# ---------------------------------------------------------------------------


class PhishingSimVendor(Enum):
    """Bekannte Phishing-Sim-Anbieter fuer KMU/Kanzleien.

    Manuelle Erfassung (Konzept §6.1) — wir tracken nur die Kampagnen-
    Aggregate, nicht das Tool selbst. CUSTOM erlaubt unbekannte Anbieter
    oder hauseigene Kampagnen (z. B. interner IT-Test).
    """

    KNOWBE4 = "knowbe4"
    COFENSE = "cofense"
    SOSAFE = "sosafe"
    PROOFPOINT = "proofpoint"
    HOXHUNT = "hoxhunt"
    PHISHME = "phishme"
    INTERN = "intern"  # Hauseigene IT-Kampagne (Pen-Test light)
    CUSTOM = "custom"

    @classmethod
    def from_value(cls, value: str) -> PhishingSimVendor:
        """Robuste Konvertierung aus DB-String mit Default-Fallback."""
        try:
            return cls(value)
        except ValueError:
            return cls.CUSTOM


@dataclass(frozen=True)
class PhishingSimEvent:
    """Eine Phishing-Simulations-Kampagne mit Aggregat-Zahlen.

    Granularitaet: pro Kampagne, nicht pro Mitarbeiter. Patrick-Direktive
    aus 3c-Design 2026-05-16: Pro-Mitarbeiter-Tracking ist fuer das
    Office-Management unrealistisch — Aggregat reicht fuer KPI- und
    Trend-Sicht.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        name: Kampagnen-Name (1..200 Zeichen).
        vendor::class:`PhishingSimVendor`.
        run_date: Datum der Kampagne (UTC).
        target_count: Anzahl angeschriebener Mitarbeiter (>= 1).
        click_count: Anzahl Klicks auf Phishing-Link (>= 0, <= target).
        report_count: Anzahl Meldungen via Phishing-Report-Button
                             (>= 0, kann groesser als target sein wenn
                             Mitarbeiter mehrfach melden oder ueber Umwege
                             Bescheid bekommen).
        training_assigned: ``True`` wenn Click-Mitarbeiter nachgeschult wurden.
        custom_vendor_label: Pflicht wenn ``vendor == CUSTOM``.
        notes: Freitext (max. 2000 Zeichen).
        created_at: DB-Erst-Anlage (UTC).

    Raises:
        ValueError: Bei Constraint-Verletzung.
    """

    id: int | None
    name: str
    vendor: PhishingSimVendor
    run_date: datetime
    target_count: int
    click_count: int
    report_count: int = 0
    training_assigned: bool = False
    custom_vendor_label: str = ""
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("PhishingSimEvent.name darf nicht leer sein.")
        if len(name) > MAX_CAMPAIGN_NAME_LENGTH:
            raise ValueError(
                f"PhishingSimEvent.name darf max. {MAX_CAMPAIGN_NAME_LENGTH} "
                f"Zeichen haben (aktuell {len(name)})."
            )
        if self.target_count < 1:
            raise ValueError(
                "PhishingSimEvent.target_count muss >= 1 sein."
            )
        if self.click_count < 0:
            raise ValueError(
                "PhishingSimEvent.click_count darf nicht negativ sein."
            )
        if self.click_count > self.target_count:
            raise ValueError(
                "PhishingSimEvent.click_count darf nicht groesser als "
                "target_count sein."
            )
        if self.report_count < 0:
            raise ValueError(
                "PhishingSimEvent.report_count darf nicht negativ sein."
            )
        custom_label = self.custom_vendor_label.strip()
        if self.vendor is PhishingSimVendor.CUSTOM:
            if not custom_label:
                raise ValueError(
                    "PhishingSimEvent.custom_vendor_label ist Pflicht "
                    "bei vendor=CUSTOM."
                )
            if len(custom_label) > MAX_VENDOR_LABEL_LENGTH:
                raise ValueError(
                    f"PhishingSimEvent.custom_vendor_label darf max. "
                    f"{MAX_VENDOR_LABEL_LENGTH} Zeichen haben."
                )
        else:
            # Datenhygiene: Non-CUSTOM-Events haben kein custom_vendor_label.
            custom_label = ""
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"PhishingSimEvent.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben."
            )
        if name != self.name:
            object.__setattr__(self, "name", name)
        if custom_label != self.custom_vendor_label:
            object.__setattr__(self, "custom_vendor_label", custom_label)

    @property
    def click_rate(self) -> float:
        """Klick-Rate in Prozent (0.0.. 100.0).

        Bei ``target_count == 0`` wuerde ZeroDivision drohen — durch das
        Constraint in:meth:`__post_init__` ist das aber ausgeschlossen.
        """
        return 100.0 * self.click_count / self.target_count

    @property
    def report_rate(self) -> float:
        """Report-Rate in Prozent (0.0.. 100.0+).

        Kann ueber 100 % gehen wenn ``report_count > target_count`` (echte
        Mitarbeiter melden auch dann, wenn sie nicht direkt Ziel waren —
        z. B. ueber Kollegen, die ihnen die Mail weitergeleitet haben).
        """
        return 100.0 * self.report_count / self.target_count

    @property
    def display_vendor_label(self) -> str:
        """Anzeige-Label des Anbieters."""
        if (
            self.vendor is PhishingSimVendor.CUSTOM
            and self.custom_vendor_label
        ):
            return self.custom_vendor_label
        return self.vendor.value.upper() if len(self.vendor.value) <= 5 else self.vendor.value.title()
