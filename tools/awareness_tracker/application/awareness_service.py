"""
awareness_service — UseCases rund um Mitarbeiter + Schulungen.

Orchestriert das:class:`AwarenessRepository`. In Iter 3a sind die
UseCases reine Pass-Through-Aufrufe; ICS-Renewal-Reminder, Bulk-Import
(CSV) und Reporting kommen in 3b/3c.

Schichtzugehoerigkeit: application/ — darf domain/ + data/ + core/
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from core.logger import get_logger
from tools.awareness_tracker.data.awareness_repository import (
    AwarenessRepository,
)
from tools.awareness_tracker.domain.human_risk_score import (
    HumanRiskScore,
)
from tools.awareness_tracker.domain.human_risk_score import (
    compute_human_risk_score as _compute_human_risk_score,
)
from tools.awareness_tracker.domain.models import (
    TRAINING_VALIDITY_WARNING_DAYS_DEFAULT,
    Employee,
    PhishingSimEvent,
    PhishingSimVendor,
    Training,
    TrainingType,
    ValidityStatus,
)

_log = get_logger(__name__)


@dataclass(frozen=True)
class PhishingSimKpi:
    """Aggregierte KPI-Zusammenfassung ueber alle Kampagnen.

    Attributes:
        campaign_count: Anzahl Kampagnen im Datensatz.
        avg_click_rate: Durchschnittliche Klick-Rate in Prozent
                              (gewichtet nach target_count).
        avg_report_rate: Durchschnittliche Report-Rate in Prozent
                              (gewichtet nach target_count).
        latest_click_rate: Klick-Rate der neuesten Kampagne (oder None).
        trend_delta_percent: Click-Rate-Delta zwischen neuester Kampagne
                              und Durchschnitt der vorherigen — negativ
                              = besser geworden, positiv = schlechter.
                              ``None`` bei < 2 Kampagnen.
    """

    campaign_count: int
    avg_click_rate: float
    avg_report_rate: float
    latest_click_rate: float | None
    trend_delta_percent: float | None

    @property
    def is_empty(self) -> bool:
        return self.campaign_count == 0

    @property
    def trend_label(self) -> str:
        """Label fuer die Trend-Anzeige (Pfeil + Wort)."""
        if self.trend_delta_percent is None:
            return "—"
        if self.trend_delta_percent <= -1.0:
            return f"↓ {abs(self.trend_delta_percent):.1f} %P besser"
        if self.trend_delta_percent >= 1.0:
            return f"↑ {self.trend_delta_percent:.1f} %P schlechter"
        return "≈ stabil"


class AwarenessService:
    """Anwendungs-Service fuer Mitarbeiter- und Schulungsverwaltung."""

    def __init__(self, repository: AwarenessRepository | None = None) -> None:
        """Initialisiert den Service.

        Args:
            repository: Optionales Repository (z. B. mit Test-DB). Default:
                neue:class:`AwarenessRepository`-Instanz auf der Produktiv-DB.
        """
        self._repo = repository or AwarenessRepository()

    # ------------------------------------------------------------------
    # Employee-UseCases
    # ------------------------------------------------------------------

    def add_employee(
        self,
        full_name: str,
        email: str = "",
        role: str = "",
        department: str = "",
        is_active: bool = True,
        notes: str = "",
    ) -> Employee:
        """Legt einen neuen Mitarbeiter an.

        Args:
            full_name: Name (Pflicht).
            email: E-Mail-Adresse (optional).
            role: Funktion / Berufsbezeichnung.
            department: Abteilung / Standort.
            is_active: Default ``True``.
            notes: Freitext.

        Returns:
            Den persistierten:class:`Employee` inkl. vergebener ID.

        Raises:
            ValueError: Bei ungueltigen Domain-Werten (:class:`Employee.__post_init__`).
        """
        employee = Employee(
            id=None,
            full_name=full_name,
            email=email,
            role=role,
            department=department,
            is_active=is_active,
            notes=notes,
        )
        new_id = self._repo.add_employee(employee)
        return replace(employee, id=new_id)

    def get_employee(self, employee_id: int) -> Employee | None:
        """Liefert einen Mitarbeiter anhand der ID oder ``None``."""
        return self._repo.get_employee(employee_id)

    def list_employees(self, include_inactive: bool = True) -> list[Employee]:
        """Liefert alle Mitarbeiter (Name aufsteigend).

        Args:
            include_inactive: Wenn ``False``, nur aktive Mitarbeiter.
        """
        return self._repo.list_employees(include_inactive=include_inactive)

    def update_employee(self, employee: Employee) -> None:
        """Aktualisiert einen bestehenden Mitarbeiter.

        Raises:
            ValueError: Bei fehlender ID oder unbekanntem Datensatz.
        """
        self._repo.update_employee(employee)

    def delete_employee(self, employee_id: int) -> bool:
        """Loescht einen Mitarbeiter (samt seiner Schulungen via CASCADE).

        Returns:
            ``True`` wenn geloescht, ``False`` wenn nicht gefunden.
        """
        return self._repo.delete_employee(employee_id)

    # ------------------------------------------------------------------
    # Training-UseCases
    # ------------------------------------------------------------------

    def add_training(
        self,
        employee_id: int,
        training_type: TrainingType,
        title: str,
        completed_at: datetime,
        valid_until: datetime | None = None,
        provider: str = "",
        custom_type_label: str = "",
        notes: str = "",
    ) -> Training:
        """Legt eine neue Schulung fuer einen Mitarbeiter an.

        Args:
            employee_id: FK zu:class:`Employee`.
            training_type::class:`TrainingType`.
            title: Konkrete Schulungs-Bezeichnung.
            completed_at: Abschluss-Datum (UTC).
            valid_until: Ablauf-Datum (UTC) oder ``None``.
            provider: Schulungs-Anbieter.
            custom_type_label: Pflicht bei ``training_type=CUSTOM``.
            notes: Freitext.

        Returns:
            Den persistierten:class:`Training` inkl. vergebener ID.

        Raises:
            ValueError: Bei ungueltigen Domain-Werten oder unbekanntem
                ``employee_id`` (FK fehlend).
        """
        if self._repo.get_employee(employee_id) is None:
            raise ValueError(
                f"AwarenessService.add_training: kein Employee mit id={employee_id}."
            )
        training = Training(
            id=None,
            employee_id=employee_id,
            training_type=training_type,
            title=title,
            completed_at=completed_at,
            valid_until=valid_until,
            provider=provider,
            custom_type_label=custom_type_label,
            notes=notes,
        )
        new_id = self._repo.add_training(training)
        return replace(training, id=new_id)

    def update_training(self, training: Training) -> None:
        """Aktualisiert eine bestehende Schulung.

        Args:
            training::class:`Training` mit gesetzter ``id``.

        Raises:
            ValueError: Bei fehlender ID oder unbekanntem Datensatz.
        """
        self._repo.update_training(training)

    def get_training(self, training_id: int) -> Training | None:
        """Liefert eine Schulung anhand ihrer ID oder ``None``."""
        return self._repo.get_training(training_id)

    def list_trainings_for_employee(self, employee_id: int) -> list[Training]:
        """Liefert alle Schulungen eines Mitarbeiters (neueste zuerst)."""
        return self._repo.list_trainings_for_employee(employee_id)

    def list_trainings(self) -> list[Training]:
        """Liefert alle Schulungen aller Mitarbeiter (neueste zuerst)."""
        return self._repo.list_trainings()

    def delete_training(self, training_id: int) -> bool:
        """Loescht eine Schulung.

        Returns:
            ``True`` wenn geloescht, ``False`` wenn nicht gefunden.
        """
        return self._repo.delete_training(training_id)

    # ------------------------------------------------------------------
    # Renewal-Queries (3b)
    # ------------------------------------------------------------------

    def list_trainings_due_soon(
        self,
        warning_days: int = TRAINING_VALIDITY_WARNING_DAYS_DEFAULT,
        now: datetime | None = None,
    ) -> list[Training]:
        """Liefert alle Schulungen mit Status ``EXPIRED`` oder ``EXPIRING_SOON``.

        Permanent-Schulungen (kein ``valid_until``) werden ausgefiltert,
        weil sie keinen Renewal-Bedarf haben. Sortierung: abgelaufene
        zuerst (nach ``valid_until`` aufsteigend), dann auslaufende.

        Args:
            warning_days: Schwelle fuer ``EXPIRING_SOON``. Default: 60 Tage
                          aus:data:`TRAINING_VALIDITY_WARNING_DAYS_DEFAULT`.
            now: Referenz-Zeitpunkt (testbar). Default: jetzt.

        Returns:
            Liste der renewal-pflichtigen Schulungen.
        """
        trainings = self._repo.list_trainings()
        due: list[Training] = []
        for training in trainings:
            status = training.validity_status(now=now, warning_days=warning_days)
            if status in (
                ValidityStatus.EXPIRED,
                ValidityStatus.EXPIRING_SOON,
            ):
                due.append(training)
        # Sortierung: nach valid_until aufsteigend; PERMANENT (None) wurde
        # bereits gefiltert, hier ist valid_until garantiert gesetzt.
        due.sort(
            key=lambda t: t.valid_until or datetime.max  # noqa: E501
        )
        return due

    def employee_lookup(self) -> dict[int, str]:
        """Helper: liefert ein ``{id: full_name}``-Mapping fuer den ICS-Export
        und den Schulungs-Tab (Namens-Anzeige statt FK-Anzeige).
        """
        return {
            e.id: e.full_name for e in self._repo.list_employees() if e.id is not None
        }

    # ------------------------------------------------------------------
    # Phishing-Sim-UseCases (3c)
    # ------------------------------------------------------------------

    def add_phishing_sim(
        self,
        name: str,
        vendor: PhishingSimVendor,
        run_date: datetime,
        target_count: int,
        click_count: int,
        report_count: int = 0,
        training_assigned: bool = False,
        custom_vendor_label: str = "",
        notes: str = "",
    ) -> PhishingSimEvent:
        """Legt eine neue Phishing-Sim-Kampagne an.

        Raises:
            ValueError: Bei Domain-Constraint-Verletzung (:class:`PhishingSimEvent.__post_init__`).
        """
        event = PhishingSimEvent(
            id=None,
            name=name,
            vendor=vendor,
            run_date=run_date,
            target_count=target_count,
            click_count=click_count,
            report_count=report_count,
            training_assigned=training_assigned,
            custom_vendor_label=custom_vendor_label,
            notes=notes,
        )
        new_id = self._repo.add_phishing_sim(event)
        return replace(event, id=new_id)

    def get_phishing_sim(self, event_id: int) -> PhishingSimEvent | None:
        """Liefert eine Phishing-Sim-Kampagne anhand ihrer ID oder ``None``."""
        return self._repo.get_phishing_sim(event_id)

    def list_phishing_sims(self) -> list[PhishingSimEvent]:
        """Liefert alle Kampagnen, neueste run_date zuerst."""
        return self._repo.list_phishing_sims()

    def update_phishing_sim(self, event: PhishingSimEvent) -> None:
        """Aktualisiert eine bestehende Kampagne.

        Raises:
            ValueError: Bei fehlender ID oder unbekanntem Datensatz.
        """
        self._repo.update_phishing_sim(event)

    def delete_phishing_sim(self, event_id: int) -> bool:
        """Loescht eine Kampagne. Returns ``True`` bei Hit."""
        return self._repo.delete_phishing_sim(event_id)

    def compute_phishing_sim_kpi(self) -> PhishingSimKpi:
        """Aggregiert KPI-Zahlen ueber alle Kampagnen.

        - ``avg_click_rate``/``avg_report_rate`` sind **gewichtete**
          Durchschnitte (Gewicht = ``target_count``), damit eine
          50-Personen-Kampagne nicht gleichwertig zu einer
          5-Personen-Pilot-Welle gewichtet wird.
        - ``trend_delta_percent`` vergleicht die neueste Kampagne mit dem
          gewichteten Durchschnitt aller vorherigen.

        Returns:
:class:`PhishingSimKpi` (immer instanziiert — bei leerer
            Datenbasis ``is_empty == True``).
        """
        events = self._repo.list_phishing_sims()
        if not events:
            return PhishingSimKpi(
                campaign_count=0,
                avg_click_rate=0.0,
                avg_report_rate=0.0,
                latest_click_rate=None,
                trend_delta_percent=None,
            )
        total_targets = sum(e.target_count for e in events)
        total_clicks = sum(e.click_count for e in events)
        total_reports = sum(e.report_count for e in events)
        avg_click = 100.0 * total_clicks / total_targets
        avg_report = 100.0 * total_reports / total_targets

        # events ist nach run_date DESC sortiert (Repository-Vertrag).
        latest = events[0]
        latest_click = latest.click_rate

        trend_delta: float | None
        if len(events) >= 2:
            previous = events[1:]
            prev_targets = sum(e.target_count for e in previous)
            prev_clicks = sum(e.click_count for e in previous)
            if prev_targets > 0:
                prev_avg = 100.0 * prev_clicks / prev_targets
                trend_delta = latest_click - prev_avg
            else:
                trend_delta = None
        else:
            trend_delta = None

        return PhishingSimKpi(
            campaign_count=len(events),
            avg_click_rate=avg_click,
            avg_report_rate=avg_report,
            latest_click_rate=latest_click,
            trend_delta_percent=trend_delta,
        )

    # ------------------------------------------------------------------
    # Human-Risk-Score (IA-Welle 2)
    # ------------------------------------------------------------------

    def training_completion(self, now: datetime | None = None) -> tuple[float, int]:
        """Anteil aktiver Mitarbeiter mit mindestens einer gueltigen Schulung.

        "Gueltig" heisst: der Validity-Status ist NICHT ``EXPIRED`` (also
        VALID, EXPIRING_SOON oder PERMANENT). Inaktive Mitarbeiter zaehlen
        nicht in den Nenner.

        Args:
            now: Referenz-Zeitpunkt (testbar). Default: jetzt.

        Returns:
            Tupel ``(quote_in_prozent, anzahl_aktiver_mitarbeiter)``. Bei
            null aktiven Mitarbeitern: ``(0.0, 0)``.
        """
        active = [
            e
            for e in self._repo.list_employees(include_inactive=False)
            if e.id is not None
        ]
        if not active:
            return 0.0, 0
        covered_ids: set[int] = {
            t.employee_id
            for t in self._repo.list_trainings()
            if t.validity_status(now=now) is not ValidityStatus.EXPIRED
        }
        covered = sum(1 for e in active if e.id in covered_ids)
        return 100.0 * covered / len(active), len(active)

    def compute_human_risk_score(self, now: datetime | None = None) -> HumanRiskScore:
        """Aggregiert Phishing-KPI + Schulungs-Quote zum Human-Risk-Score.

        Args:
            now: Referenz-Zeitpunkt (testbar). Default: jetzt.

        Returns:
            Ein:class:`HumanRiskScore` (immer instanziiert — bei leerer
            Datenbasis Score 0 mit ``has_any_data == False``).
        """
        kpi = self.compute_phishing_sim_kpi()
        completion, active_count = self.training_completion(now=now)
        return _compute_human_risk_score(
            avg_report_rate=None if kpi.is_empty else kpi.avg_report_rate,
            avg_click_rate=None if kpi.is_empty else kpi.avg_click_rate,
            campaign_count=kpi.campaign_count,
            training_completion=completion,
            active_employee_count=active_count,
            trend_delta=kpi.trend_delta_percent,
        )
