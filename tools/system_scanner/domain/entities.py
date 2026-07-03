"""
entities — Domain-Entities für das System-Scanner-Modul.

Reine Datenklassen ohne externe Abhängigkeiten.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from core.security.severity import Severity
from tools.system_scanner.domain.enums import (
    ComponentStatus,
    ComponentType,
    OSPlatform,
    UnmeasuredReason,
)


@dataclass
class InstalledSoftware:
    """Repräsentiert ein installiertes Softwarepaket.

    Attributes:
        name: Anzeigename des Pakets.
        version: Versionsnummer als String.
        vendor: Hersteller/Publisher.
        install_date: Installationsdatum (ISO-String oder leer).
        is_security_relevant: True wenn sicherheitsrelevant.
    """

    name: str
    version: str = ""
    vendor: str = ""
    install_date: str = ""
    is_security_relevant: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity in ein JSON-serialisierbares Dict.

        Returns:
            Dict-Repräsentation.
        """
        return {
            "name": self.name,
            "version": self.version,
            "vendor": self.vendor,
            "install_date": self.install_date,
            "is_security_relevant": self.is_security_relevant,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InstalledSoftware:
        """Deserialisiert ein Dict in eine InstalledSoftware-Entity.

        Args:
            d: Dict-Repräsentation.

        Returns:
            InstalledSoftware-Instanz.
        """
        return cls(
            name=d.get("name", ""),
            version=d.get("version", ""),
            vendor=d.get("vendor", ""),
            install_date=d.get("install_date", ""),
            is_security_relevant=d.get("is_security_relevant", False),
        )


@dataclass
class SecurityComponent:
    """Eine erkannte Sicherheitskomponente des Systems.

    Attributes:
        name: Anzeigename (z.B. "Windows Defender").
        type: Kategorie der Komponente.
        status: Betriebsstatus.
        version: Versionsnummer als String.
        last_updated: Datum der letzten Aktualisierung (ISO-String oder leer).
        detail: Optionaler Detailtext (z.B. Pfad, Konfiguration).
    """

    name: str
    type: ComponentType
    status: ComponentStatus
    version: str = ""
    last_updated: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            Dict-Repräsentation.
        """
        return {
            "name": self.name,
            "type": self.type.value,
            "status": self.status.value,
            "version": self.version,
            "last_updated": self.last_updated,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SecurityComponent:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            SecurityComponent-Instanz.
        """
        return cls(
            name=d.get("name", ""),
            type=ComponentType(d.get("type", ComponentType.ANTIVIRUS.value)),
            status=ComponentStatus(d.get("status", ComponentStatus.UNKNOWN.value)),
            version=d.get("version", ""),
            last_updated=d.get("last_updated", ""),
            detail=d.get("detail", ""),
        )


@dataclass
class ManualScannerEntry:
    """Ein manuell erfasster Sicherheitskomponenten-Eintrag.

    Persistent in SQLCipher (Tabelle ``manual_scanner_entries``). Wird in
    der UI neben Scan-Ergebnissen angezeigt, mit ``(manuell)``-Label und
    Bearbeiten/Löschen-Buttons. Überlebt jeden Scan — wird NICHT durch
    Scan-Ergebnisse überschrieben.

    Attributes:
        entry_id: DB-Primärschlüssel (``None`` für neue Einträge, wird
                    beim ``add`` vom Repository gesetzt).
        category: Kategorie (nur ``ANTIVIRUS``, ``FIREWALL`` oder
                    ``ENCRYPTION`` sinnvoll — UI blendet Button nur in
                    diesen drei Gruppen ein).
        name: Anzeigename (Pflicht, max. 100 Zeichen).
        version: Versionsnummer (optional, max. 50 Zeichen).
        status: Aktiv / Inaktiv / Unbekannt.
        created_at: Anlage-Zeitpunkt (UTC).
        updated_at: Letzte Bearbeitung (UTC).
    """

    entry_id: int | None
    category: ComponentType
    name: str
    version: str = ""
    status: ComponentStatus = ComponentStatus.UNKNOWN
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Normalisiert Enum-Felder.

        ``QComboBox.currentData`` unwrappt ``StrEnum``-Instanzen zu plain
        ``str`` bei der Runde durch Qt's QVariant. Diese Normalisierung
        sorgt dafür, dass Repository-Aufrufer immer echte Enum-Instanzen
        sehen — ein ``entry.category.value`` kann nicht mehr scheitern.
        """
        if not isinstance(self.category, ComponentType):
            self.category = ComponentType(self.category)
        if not isinstance(self.status, ComponentStatus):
            self.status = ComponentStatus(self.status)

    def to_security_component(self) -> SecurityComponent:
        """Wandelt den Eintrag in eine ``SecurityComponent`` zum Rendern.

        Die UI nutzt dieselbe ``_ComponentCard`` für Scan- und Manuell-
        Einträge; nur ein zusätzliches Flag im Render-Aufruf blendet das
        ``(manuell)``-Label und die Edit/Delete-Buttons ein.

        Returns:
:class:`SecurityComponent` ohne Detail-String.
        """
        return SecurityComponent(
            name=self.name,
            type=self.category,
            status=self.status,
            version=self.version,
            last_updated=self.updated_at.isoformat() if self.updated_at else "",
            detail="",
        )


@dataclass
class OSInfo:
    """Betriebssystem-Informationen.

    Attributes:
        platform: Erkanntes Betriebssystem.
        name: Anzeigename (z.B. "Windows 11 Home").
        version: Versionsnummer.
        build: Build-Nummer (Windows) oder Kernel-Version (Linux/macOS).
        architecture: Prozessorarchitektur (z.B. "AMD64").
        last_update: Letztes Windows-Update / Patch-Datum (ISO-String oder leer).
        update_status: Status der OS-Updates (ComponentStatus).
    """

    platform: OSPlatform
    name: str = ""
    version: str = ""
    build: str = ""
    architecture: str = ""
    last_update: str = ""
    update_status: ComponentStatus = ComponentStatus.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert die Entity.

        Returns:
            Dict-Repräsentation.
        """
        return {
            "platform": self.platform.value,
            "name": self.name,
            "version": self.version,
            "build": self.build,
            "architecture": self.architecture,
            "last_update": self.last_update,
            "update_status": self.update_status.value,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> OSInfo:
        """Deserialisiert ein Dict.

        Args:
            d: Dict-Repräsentation.

        Returns:
            OSInfo-Instanz.
        """
        return cls(
            platform=OSPlatform(d.get("platform", OSPlatform.UNKNOWN.value)),
            name=d.get("name", ""),
            version=d.get("version", ""),
            build=d.get("build", ""),
            architecture=d.get("architecture", ""),
            last_update=d.get("last_update", ""),
            update_status=ComponentStatus(
                d.get("update_status", ComponentStatus.UNKNOWN.value)
            ),
        )


@dataclass(frozen=True, slots=True)
class HardeningCheck:
    """Ergebnis eines einzelnen Windows-Hardening-Checks Phase 3).

    Frozen + slots — unveraenderbar, speicherarm, hashable.

    Die 10 Checks SH-001..SH-010 sind in [[NoRisk_HARDENING_SCORE]] §5
    Phase 3 spezifiziert. Beispiele: SH-001 (Firewall aktiv), SH-003
    (RDP deaktiviert oder MFA), SH-005 (SMBv1 deaktiviert).

    ``severity`` aus dem kanonischen:class:`Severity`-Enum
    (``core/security/severity.py``-Sprint) — kein tool-lokales
    Enum (siehe v2 K3).

    Attributes:
        check_id: Stabile ID, z. B. ``"SH-001"``. Wird in
            ``hard_cap_events.triggered_by`` referenziert + im Audit-Log
            geloggt.
        label: Menschen-lesbarer Check-Name, z. B.
            ``"Windows Firewall aktiv"``. Deutsch fuer GUI.
        passed: ``True`` wenn der Check erfuellt ist (Konfiguration ist
            sicher). ``False`` bei Verletzung. Bei ``measurable=False`` ist
            ``passed`` bedeutungslos (Konvention: ``False``, aber NIE als
            Verstoss gewertet).
        severity: Schweregrad bei ``passed=False``. Bei ``passed=True``
            irrelevant fuer Score-Beitrag.
        measurable: ``True`` (Default) wenn der Zustand tatsaechlich ermittelt
            werden konnte. ``False`` = "nicht messbar" (Probe-Fehler ohne
            Admin, Tool fehlt z.B. BitLocker auf Home-Editionen, Ausgabe in
            fremder Sprache nicht interpretierbar). Ein nicht messbarer Check
            zaehlt NICHT als Verstoss — weder im Score, noch in den Hard-Caps,
            noch als Finding. Additiv mit Default ``True`` ->
            rueckwaertskompatibel mit allen persistierten Checks.
        detail: Freie Beschreibung, z. B. ``"Domain-Profil deaktiviert"``
            oder ``"UAC EnableLUA=1 OK"``. Fuer Tooltips + Forensik.
        unmeasured_reason: Bei ``measurable=False`` die Ursachen-Kategorie
            (:class:`UnmeasuredReason`: needs_admin / parse_failed /
            not_applicable / user_declined). ``None`` wenn gemessen.
            Steuert Mess-zuerst-Flow, Score-Behandlung und Report-Sektion.
        skip_reason: Menschen-lesbare Begruendung fuer ``not_applicable`` (z.B.
            "BitLocker auf Home nicht vorhanden") oder ``user_declined``
            (Opt-out-Notiz). Leer wenn nicht zutreffend.
    """

    check_id: str
    label: str
    passed: bool
    severity: Severity
    detail: str = ""
    measurable: bool = True
    unmeasured_reason: UnmeasuredReason | None = None
    skip_reason: str = ""

    def __post_init__(self) -> None:
        """Erzwingt die-Mess-Invariante strukturell.

        Ein nicht messbarer Check MUSS seine Ursache tragen — sonst koennen
        Mess-zuerst-Flow, Score-Behandlung und Report-Sektion ihn nicht
        kategorisieren. Bewusst ASYMMETRISCH: ``measurable=True`` mit gesetztem
        Reason ist erlaubt (``apply_manual_overrides`` hebt ``measurable`` per
        Alternative auf True, ohne den Reason zu loeschen).

        Raises:
            ValueError: Wenn ``measurable=False`` ohne ``unmeasured_reason``.
        """
        if not self.measurable and self.unmeasured_reason is None:
            raise ValueError(
                f"HardeningCheck {self.check_id!r}: measurable=False erfordert "
                f"unmeasured_reason (ADR-026-Invariante)."
            )

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisierbare Dict-Repraesentation."""
        return {
            "check_id": self.check_id,
            "label": self.label,
            "passed": self.passed,
            "severity": self.severity.value,
            "detail": self.detail,
            "measurable": self.measurable,
            "unmeasured_reason": (
                self.unmeasured_reason.value
                if self.unmeasured_reason is not None
                else None
            ),
            "skip_reason": self.skip_reason,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> HardeningCheck:
        """Deserialisiert aus Dict.

        Args:
            d: Dict-Repraesentation (z. B. aus JSON).

        Returns:
            HardeningCheck-Instanz.
        """
        return cls(
            check_id=d.get("check_id", ""),
            label=d.get("label", ""),
            passed=bool(d.get("passed", False)),
            severity=Severity(d.get("severity", Severity.INFO.value)),
            detail=d.get("detail", ""),
            # Default True -> alte JSON ohne measurable bleibt "messbar".
            measurable=bool(d.get("measurable", True)),
            # additiv: alte JSON ohne diese Felder -> None/"" (kompatibel).
            unmeasured_reason=(
                UnmeasuredReason(d["unmeasured_reason"])
                if d.get("unmeasured_reason")
                else None
            ),
            skip_reason=d.get("skip_reason", ""),
        )


@dataclass(frozen=True, slots=True)
class HardeningCoverage:
    """Mess-Abdeckung der Hardening-Checks Phase 3).

    Anteil der ANWENDBAREN Checks, der tatsaechlich gemessen werden konnte.
    ``NOT_APPLICABLE``-Checks (Feature strukturell nicht vorhanden) zaehlen
    NICHT in den Nenner; ``USER_DECLINED`` (Opt-out) zaehlt in den Nenner als
    Defizit (Owner-Prinzip P6a). Niedrige Coverage begrenzt im Score die Ampel
    (Stage-Guard) — ein 100%-Score auf 40% Abdeckung ist KEIN "Secure".

    Attributes:
        measured: Checks, deren Zustand ermittelt wurde (``measurable=True``).
        applicable: Anwendbare Checks (Gesamt minus ``NOT_APPLICABLE``).
        not_applicable: Checks, deren Feature strukturell fehlt.
        opted_out: Checks, deren Messung der Nutzer bewusst uebersprang
            (``USER_DECLINED``) — Teilmenge der nicht gemessenen anwendbaren.
    """

    measured: int
    applicable: int
    not_applicable: int
    opted_out: int

    @property
    def ratio(self) -> float:
        """Anteil gemessen/anwendbar (0.0-1.0). 1.0 wenn nichts anwendbar."""
        if self.applicable <= 0:
            return 1.0
        return self.measured / self.applicable


def compute_hardening_coverage(checks: list[HardeningCheck]) -> HardeningCoverage:
    """Berechnet die Mess-Abdeckung aus einer HardeningCheck-Liste.

    Args:
        checks: Die Hardening-Checks eines Scans.

    Returns:
:class:`HardeningCoverage` — ``measured``/``applicable`` plus die
        Sonderfaelle ``not_applicable`` (raus aus dem Nenner) und ``opted_out``
        (im Nenner, druckt die ``ratio``).
    """
    # Bucket-Klassifikation an den Mess-Zustand koppeln: ein per Alternative
    # gemessener Check (measurable=True) kann noch seinen Alt-Reason
    # (NOT_APPLICABLE) tragen — er zaehlt als MESSBAR, nicht als n/a, sonst fiele
    # er faelschlich aus dem Nenner P2-Review).
    unmeasured = [c for c in checks if not c.measurable]
    not_applicable = sum(
        1 for c in unmeasured if c.unmeasured_reason == UnmeasuredReason.NOT_APPLICABLE
    )
    opted_out = sum(
        1 for c in unmeasured if c.unmeasured_reason == UnmeasuredReason.USER_DECLINED
    )
    measured = sum(1 for c in checks if c.measurable)
    applicable = len(checks) - not_applicable
    return HardeningCoverage(
        measured=measured,
        applicable=applicable,
        not_applicable=not_applicable,
        opted_out=opted_out,
    )


@dataclass(frozen=True, slots=True)
class MeasurementDisposition:
    """Mess-zuerst-Gate-Status P4, Soft-Gate D4).

    Was VOR Bewertung/Report mit dem Nutzer zu klaeren ist (Owner-Prinzip):
    "offene" Checks sind mit Adminrechten nachmessbar (``NEEDS_ADMIN``). Das Gate
    ist SOFT (D4) — es blockiert den Report nicht, sondern treibt per
    "N offen"-Banner die Mess-zuerst-Aktion; bleibt der Nutzer dabei, druckt die
    niedrige Coverage die Ampel (Stage-Guard).

    Fail-closed: solange offene Checks existieren, ist ``gate_open=True``
    (die Default-Annahme ist NICHT "alles gut").

    Attributes:
        open_remeasurable: Mit Admin-Recheck nachmessbare Checks
            (``NEEDS_ADMIN``) — Treiber des "N offen"-Banners + Mess-zuerst-Flows.
        blocked: Nicht nutzer-behebbar nicht gemessen (``PARSE_FAILED``) —
            Tool-/Locale-Grenze, kein Admin-Recheck-Kandidat; bleibt Defizit.
        opted_out: Bewusst uebersprungen (``USER_DECLINED``).
        not_applicable: Strukturell n/a (``NOT_APPLICABLE``) — score-neutral.
        measured: Tatsaechlich gemessen (``measurable=True``).
    """

    open_remeasurable: int
    blocked: int
    opted_out: int
    not_applicable: int
    measured: int

    @property
    def gate_open(self) -> bool:
        """True solange mit Admin nachmessbare Checks offen sind (fail-closed)."""
        return self.open_remeasurable > 0


def evaluate_measurement_disposition(
    checks: list[HardeningCheck],
) -> MeasurementDisposition:
    """Leitet den Mess-zuerst-Gate-Status aus den Checks ab P4).

    Args:
        checks: Die Hardening-Checks eines Scans.

    Returns:
:class:`MeasurementDisposition` mit den fuenf Mess-Zustands-Buckets.
    """

    # Reason-Buckets nur ueber NICHT-messbare Checks (ein per Alternative
    # gemessener Check ist measured, nicht offen/n/a P2-Review).
    # __post_init__ garantiert, dass jeder nicht-messbare Check einen Reason
    # traegt -> die vier Buckets partitionieren alle nicht-messbaren lueckenlos.
    unmeasured = [c for c in checks if not c.measurable]

    def _count(reason: UnmeasuredReason) -> int:
        return sum(1 for c in unmeasured if c.unmeasured_reason == reason)

    return MeasurementDisposition(
        open_remeasurable=_count(UnmeasuredReason.NEEDS_ADMIN),
        blocked=_count(UnmeasuredReason.PARSE_FAILED),
        opted_out=_count(UnmeasuredReason.USER_DECLINED),
        not_applicable=_count(UnmeasuredReason.NOT_APPLICABLE),
        measured=sum(1 for c in checks if c.measurable),
    )


@dataclass
class ScanResult:
    """Ergebnis eines vollständigen System-Scans.

    Attributes:
        scan_id: UUID des Scans.
        timestamp: Zeitpunkt des Scans (datetime).
        os_info: Betriebssystem-Informationen.
        software_list: Alle erkannten installierten Programme.
        security_components: Erkannte Sicherheitskomponenten.
        hardening_checks: Ergebnisse der Windows-Hardening-Checks
 Phase 3, SH-001..SH-010). Leere Liste
                         wenn der Scanner noch nicht produktiv ist
                         (Phase 3 noch nicht voll implementiert).
        scan_duration_s: Dauer des Scans in Sekunden.
        warnings: Nicht-kritische Fehlermeldungen während des Scans.
    """

    scan_id: str
    timestamp: datetime
    os_info: OSInfo
    software_list: list[InstalledSoftware] = field(default_factory=list)
    security_components: list[SecurityComponent] = field(default_factory=list)
    hardening_checks: list[HardeningCheck] = field(default_factory=list)
    scan_duration_s: float = 0.0
    warnings: list[str] = field(default_factory=list)

    @property
    def security_software(self) -> list[InstalledSoftware]:
        """Gibt nur die sicherheitsrelevante Software zurück.

        Returns:
            Gefilterte Liste sicherheitsrelevanter Programme.
        """
        return [s for s in self.software_list if s.is_security_relevant]

    def to_dict(self) -> dict[str, Any]:
        """Serialisiert das Scan-Ergebnis vollständig als Dict (JSON-exportierbar).

        Returns:
            Dict-Repräsentation.
        """
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "os_info": self.os_info.to_dict(),
            "software_list": [s.to_dict() for s in self.software_list],
            "security_components": [c.to_dict() for c in self.security_components],
            "hardening_checks": [h.to_dict() for h in self.hardening_checks],
            "scan_duration_s": self.scan_duration_s,
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanResult:
        """Deserialisiert ein Dict in ein ScanResult.

        Args:
            d: Dict-Repräsentation.

        Returns:
            ScanResult-Instanz.
        """
        return cls(
            scan_id=d.get("scan_id", ""),
            timestamp=datetime.fromisoformat(d["timestamp"]),
            os_info=OSInfo.from_dict(d.get("os_info", {})),
            software_list=[
                InstalledSoftware.from_dict(s) for s in d.get("software_list", [])
            ],
            security_components=[
                SecurityComponent.from_dict(c) for c in d.get("security_components", [])
            ],
            hardening_checks=[
                HardeningCheck.from_dict(h) for h in d.get("hardening_checks", [])
            ],
            scan_duration_s=d.get("scan_duration_s", 0.0),
            warnings=d.get("warnings", []),
        )
