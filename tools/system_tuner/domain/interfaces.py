"""
interfaces — Ports (abstrakte Schnittstellen) fuer system_tuner.

Domain-Ports, die die application-Schicht implementiert/konsumiert.

Schichtzugehoerigkeit: domain/ (darf core importieren — tools->core ist erlaubt).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.probes.hardening_probe import ProbeResult
from tools.system_tuner.domain.apply_entities import Snapshot
from tools.system_tuner.domain.entities import Tweak
from tools.system_tuner.domain.enums import RegistryValueType, ServiceStartMode


class ITweakCatalog(ABC):
    """Port: liefert die kuratierte, validierte Tweak-Liste."""

    @abstractmethod
    def load(self) -> list[Tweak]:
        """Laedt + validiert den Katalog.

        Returns:
            Liste valider:class:`Tweak`-Instanzen (Invarianten erfuellt).

        Raises:
            CatalogError: bei Parse-/Schema-/Invarianten-Verletzung.
        """


class ITweakProbe(ABC):
    """Port: read + write Zugriff auf Registry/Dienste (Phase 2 Apply).

    Getrennt vom read-only:class:`IHardeningProbe` (Scan) — der Apply-Pfad
    braucht zusaetzlich Schreib-/Loesch-Ops. Adapter (Windows/Mock) wirft nie;
    Fehler landen im:class:`ProbeResult` bzw. werden als ``None`` signalisiert.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """``True`` nur auf einer Plattform, die echte Writes erlaubt (Windows)."""

    @abstractmethod
    def read_registry_value(
        self, hive: str, key_path: str, value_name: str
    ) -> str | None:
        """Liest einen Registry-Wert (``None`` wenn fehlend/Fehler)."""

    @abstractmethod
    def read_service_start_mode(self, service_name: str) -> ServiceStartMode | None:
        """Liest den Starttyp eines Dienstes (``None`` wenn unbekannt)."""

    @abstractmethod
    def write_registry_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_type: RegistryValueType,
        value: str | int,
    ) -> ProbeResult:
        """Schreibt einen Registry-Wert (legt Key bei Bedarf an)."""

    @abstractmethod
    def delete_registry_value(
        self, hive: str, key_path: str, value_name: str
    ) -> ProbeResult:
        """Loescht einen Registry-Wert (fuer Revert eines vorher fehlenden Werts)."""

    @abstractmethod
    def set_service_start_mode(
        self, service_name: str, mode: ServiceStartMode
    ) -> ProbeResult:
        """Setzt den Starttyp eines Dienstes."""


class ISnapshotRepo(ABC):
    """Port: persistiert Vorzustands-Snapshots fuer den Revert."""

    @abstractmethod
    def save(self, snapshot: Snapshot) -> None:
        """Sichert einen Snapshot (latest-wins je ``tweak_id``).

        Die Implementierung darf append-only persistieren; ``get``/``list_all``
        liefern dann den jeweils neuesten Snapshot je Tweak.
        """

    @abstractmethod
    def get(self, tweak_id: str) -> Snapshot | None:
        """Liefert den **jeweils neuesten** Snapshot zu einem Tweak (oder ``None``)."""

    @abstractmethod
    def list_all(self) -> list[Snapshot]:
        """Liefert den jeweils neuesten Snapshot je ``tweak_id`` ('Alle zuruecknehmen')."""
