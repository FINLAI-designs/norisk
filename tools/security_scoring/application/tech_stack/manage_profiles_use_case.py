"""
manage_profiles_use_case — Use Cases für SystemProfile-Verwaltung.

Orchestriert CRUD-Operationen und Migration vorhandener Ziel-Namen.

Schichtzugehörigkeit: application/ — keine GUI-Imports.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from core.exceptions import ValidationError
from core.logger import get_logger
from tools.security_scoring.domain.tech_stack.entities import SystemProfile, TechStack
from tools.security_scoring.domain.tech_stack.enums import SystemType

if TYPE_CHECKING:
    from tools.security_scoring.data.tech_stack_repository import TechStackRepository

log = get_logger(__name__)

_DEFAULT_OWN_SYSTEM_NAME = "Mein System"


def _now() -> str:
    """Gibt aktuellen UTC-Timestamp als ISO-String zurück."""
    return datetime.now(UTC).isoformat()


def create_default_manage_profiles_use_case() -> ManageProfilesUseCase | None:
    """Default-Factory mit ``TechStackRepository``.

 (RUN2-GUI): Erlaubt Cross-Tool-GUIs (csaf_advisor, cyber_dashboard),
    den Use Case zu beziehen ohne ``data/`` direkt zu importieren.

    Returns:
        Use Case mit production-tauglichem Repository, oder ``None``
        wenn das Repository nicht initialisierbar ist (z. B. SQLCipher-
        Schluessel fehlt). Fehlerbehandlung bleibt damit bei den
        Aufrufern, die schon vorher bei ``TechStackRepository``-
        Exceptions auf ``None`` ausweichen mussten.
    """
    try:
        from tools.security_scoring.data.tech_stack_repository import (  # noqa: PLC0415
            TechStackRepository,
        )

        repo = TechStackRepository()
    except (OSError, RuntimeError, ImportError):
        return None
    return ManageProfilesUseCase(repo)


class ManageProfilesUseCase:
    """Verwaltungs-Use-Case für SystemProfile.

    Bietet CRUD-Operationen, Sicherstellung des eigenen Systems
    und Migration vorhandener Ziel-Namen.

    Attributes:
        _repo: TechStackRepository-Instanz.
    """

    def __init__(self, repo: TechStackRepository) -> None:
        """Initialisiert den Use Case.

        Args:
            repo: TechStackRepository-Instanz.
        """
        self._repo = repo

    # ------------------------------------------------------------------
    # Eigenes System
    # ------------------------------------------------------------------

    def ensure_own_system(self, name: str = _DEFAULT_OWN_SYSTEM_NAME) -> SystemProfile:
        """Stellt sicher dass das eigene System existiert (idempotent).

        Falls kein eigenes System vorhanden ist, wird eines angelegt.
        Wird beim App-Start aufgerufen.

        Args:
            name: Name des eigenen Systems (Default: "Mein System").

        Returns:
            Vorhandenes oder neu erstelltes eigenes System.
        """
        existing = self._repo.get_own_system()
        if existing is not None:
            return existing

        now = _now()
        profile = SystemProfile(
            id=str(uuid.uuid4()),
            name=name,
            system_type=SystemType.EIGENES,
            description="Eigenes System (automatisch erstellt)",
            created_at=now,
            updated_at=now,
        )
        self._repo.create(profile)
        # DSGVO Art. 5: keinen Namen ins (unverschluesselte) App-Log — der
        # Audit-/Backfill-Pfad loggt hier Firmen/Mandanten. ID reicht.
        log.info("Eigenes System angelegt: %s", profile.id[:8])
        return profile

    # ------------------------------------------------------------------
    # Kundensysteme
    # ------------------------------------------------------------------

    def create_customer_profile(
        self,
        name: str,
        description: str = "",
        contact: str = "",
    ) -> SystemProfile:
        """Legt ein neues Kundensystem an.

        Args:
            name: Anzeigename des Kunden (Pflichtfeld, nicht leer).
            description: Optionale Beschreibung.
            contact: Optionaler Ansprechpartner.

        Returns:
            Neu erstelltes SystemProfile.

        Raises:
            ValueError: Wenn name leer ist.
        """
        if not name.strip():
            raise ValidationError("Kunden-Name darf nicht leer sein.")

        now = _now()
        profile = SystemProfile(
            id=str(uuid.uuid4()),
            name=name.strip(),
            system_type=SystemType.KUNDE,
            description=description,
            contact=contact,
            tech_stack=TechStack(),
            created_at=now,
            updated_at=now,
        )
        self._repo.create(profile)
        # DSGVO Art. 5: Firmenname/Mandant NICHT ins App-Log (Anwaltsgeheimnis);
        # der-Audit-/Backfill-Pfad legt Kunden automatisch an. ID reicht.
        log.info("Kundensystem angelegt: %s", profile.id[:8])
        return profile

    def find_or_create_customer(self, name: str) -> SystemProfile:
        """Findet ein Kundensystem per Name oder legt es neu an (idempotent).

        Dedup-Grundlage für die tool-übergreifende Subjekt-Identität:
        ein Kunden-Audit und ein Kunden-Scoring desselben Firmennamens
        referenzieren dasselbe Profil.

        Args:
            name: Firmenname des Kunden/Mandanten (nicht leer).

        Returns:
            Vorhandenes oder neu erstelltes KUNDE-Profil.

        Raises:
            ValidationError: Wenn name leer ist.
        """
        if not name.strip():
            raise ValidationError("Kunden-Name darf nicht leer sein.")
        existing = self._repo.get_customer_by_name(name.strip())
        if existing is not None:
            return existing
        return self.create_customer_profile(name)

    def update_profile(self, profile: SystemProfile) -> None:
        """Aktualisiert ein bestehendes Profil.

        Args:
            profile: Profil mit aktualisierten Daten.

        Raises:
            ValueError: Wenn name leer ist.
        """
        if not profile.name.strip():
            raise ValidationError("Profilname darf nicht leer sein.")
        self._repo.update(profile)

    def delete_customer_profile(self, profile_id: str) -> None:
        """Löscht ein Kundenprofil.

        Das eigene System kann nicht gelöscht werden.

        Args:
            profile_id: UUID des zu löschenden Profils.

        Raises:
            ValueError: Wenn versucht wird, das eigene System zu löschen.
        """
        self._repo.delete(profile_id)

    # ------------------------------------------------------------------
    # Abfragen
    # ------------------------------------------------------------------

    def get_all_profiles(self) -> list[SystemProfile]:
        """Gibt alle Profile zurück (eigenes System zuerst).

        Returns:
            Liste aller SystemProfile.
        """
        return self._repo.get_all()

    def get_profile_by_id(self, profile_id: str) -> SystemProfile | None:
        """Gibt ein Profil anhand der ID zurück.

        Args:
            profile_id: UUID des Profils.

        Returns:
            SystemProfile oder None.
        """
        return self._repo.get_by_id(profile_id)

    def get_own_system(self) -> SystemProfile | None:
        """Gibt das eigene System zurück, ohne es anzulegen.

        Im Gegensatz zu:meth:`ensure_own_system` legt diese Abfrage nichts
        an — für reine Lese-Pfade (z. B. Subjekt-``get_self``).

        Returns:
            SystemProfile (EIGENES) oder None, falls noch keines existiert.
        """
        return self._repo.get_own_system()

    # ------------------------------------------------------------------
    # Migration
    # ------------------------------------------------------------------

    def migrate_existing_targets(self, target_names: list[str]) -> int:
        """Migriert vorhandene Ziel-Namen zu SystemProfile-Einträgen.

        Erstellt für jeden noch nicht vorhandenen Ziel-Namen ein KUNDE-Profil.
        Wird einmalig beim ersten Start nach dem Update aufgerufen.

        Args:
            target_names: Liste vorhandener Ziel-Namen aus der scores-Tabelle.

        Returns:
            Anzahl neu erstellter Profile.
        """
        created = 0
        for name in target_names:
            if not name.strip():
                continue
            if self._repo.get_by_name(name) is not None:
                continue
            now = _now()
            profile = SystemProfile(
                id=str(uuid.uuid4()),
                name=name.strip(),
                system_type=SystemType.KUNDE,
                description="Migriert aus vorhandenen Score-Daten",
                created_at=now,
                updated_at=now,
            )
            self._repo.create(profile)
            created += 1

        if created:
            log.info("Migration: %d Ziel-Namen als Kundensysteme importiert", created)
        return created
