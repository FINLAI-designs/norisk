"""core.scan_prefill.models — DTOs für gemessene Audit-Vorbefüllung.

Das *AuditPrefill* ist die tool-übergreifende Brücke, über die der
``security_scoring``-Adapter **gemessene** Hardening-/Netzwerk-/OS-Werte an den
``customer_audit``-SELF-Wizard liefert — jeweils mit **Herkunft** (welcher Check,
welches Tool, wann gemessen). Damit erfüllt die Dimensions-Trennung:
diese DTOs tragen ausschließlich ``measured``-Daten; die ``self_declared``-Antwort
bleibt die Fragebogen-Eingabe des Wizards.

Bewusste Leitplanken §Datenmodell, im Adapter erzwungen):

* **Keine PII** — kein Firmenname/Kontakt (Mandantengeheimnis). Nur technische
  Mess-Fakten über das *eigene* System des Beraters.
* **Transient** — kein DB-Format, keine Serialisierung auf Disk, keine Score-
  History (das DTO wird pro Wizard-Lauf frisch erzeugt und verworfen).
* **SELF-only** — die Mess-Werte beschreiben den eigenen Beraterrechner; ein
  Konsument darf sie NIE in ein Kunden-Audit (``AuditMode.CUSTOMER``) einspeisen
  (Gate auf Use-Case-Ebene/`mode_gate`).

Schichtzugehörigkeit: core/ — reine, unveränderliche Datenklassen, keine I/O.

Author: Patrick Riederich
Version: 1.0 Phase 2, 2026-06-27)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MeasuredField:
    """Ein einzelner gemessener Vorbefüll-Wert samt Herkunft.

    Frozen + slots — unveränderbar, speicherarm. Genau ein solcher Eintrag pro
    vorausgefülltem Wizard-Feld; ``None`` an der:class:`AuditPrefill`-Stelle
    bedeutet „nicht gemessen" → der Wizard lässt das Feld auf seinem Default.

    Attributes:
        value: Der gemessene Wert. ``bool`` für Status-Flags (``firewall_active``,
            ``remote_access_rdp``, ``disk_encryption_active``, ``patch_ok``,
            ``open_ports_scanned``), ``str`` für Bezeichner (``os_name``). Welcher
            Typ je:class:`AuditPrefill`-Feld gilt, steht dort dokumentiert.
        check_id: Stabile Herkunfts-ID für den Badge, z. B. ``"SH-001"``
            (Hardening-Check), ``"network_scanner"`` oder ``"os_info"``.
        source_tool: Tool, das gemessen hat (``"system_scanner"`` /
            ``"network_scanner"``). Speist den Herkunfts-Badge im Wizard.
        measured_at: ISO-8601-Zeitstempel (UTC) der Messung — für „gemessen via
            SH-001, 2026-06-27" im Badge.
        detail: Menschenlesbarer Kontext (z. B. ``"Domain-Profil aktiv"``),
            optional. Aus dem zugrunde liegenden Check übernommen.
    """

    value: bool | str
    check_id: str
    source_tool: str
    measured_at: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class AuditPrefill:
    """Gebündelte gemessene Vorbefüll-Werte für den SELF-Audit-Wizard.

    Frozen + slots. Jedes Feld ist ein:class:`MeasuredField` ODER ``None``
    (= nicht gemessen / nicht messbar → kein Prefill). Der ``customer_audit``-
    Wizard Phase 3) bildet die gesetzten Felder auf seine Eingabefelder
    ab (read-only Badge + Bestätigungs-Checkbox, überschreibbar).

    Feld → Wizard-Mapping (Phase 3) + Mess-Quelle:

    * ``firewall_active`` (``bool``) → ``InfrastructureData.firewall_status`` —
      SH-001 (``True`` = Firewall in allen Profilen aktiv).
    * ``remote_access_rdp`` (``bool``) → ``InfrastructureData.remote_access_tools``
      — SH-003 (``True`` = RDP erreichbar/in Nutzung → „RDP" ergänzen).
    * ``disk_encryption_active`` (``bool``) →
      ``InfrastructureData.verschluesselung`` — SH-010 (``True`` = BitLocker auf
      C: aktiv → „BitLocker" ergänzen).
    * ``patch_ok`` (``bool``) → ``InfrastructureData.os_patch_stand`` — SH-004
      (``True`` = Windows-Update funktionsfähig + frisch).
    * ``os_name`` (``str``) → ``InfrastructureData.betriebssysteme`` —
      system_scanner OS-Info (z. B. ``"Windows 11"``).
    * ``open_ports_scanned`` (``bool``) → ``NetworkData.offene_ports_bekannt`` —
      network_scanner (``True`` = mindestens ein Netzwerk-Scan liegt vor).

    Attributes:
        firewall_active: SH-001-Messung oder ``None``.
        remote_access_rdp: SH-003-Messung oder ``None``.
        disk_encryption_active: SH-010-Messung oder ``None``.
        patch_ok: SH-004-Messung oder ``None``.
        os_name: OS-Eckdaten oder ``None``.
        open_ports_scanned: Netzwerk-Scan-Präsenz oder ``None``.
        generated_at: ISO-8601-Zeitstempel (UTC) der DTO-Erzeugung.
    """

    firewall_active: MeasuredField | None = None
    remote_access_rdp: MeasuredField | None = None
    disk_encryption_active: MeasuredField | None = None
    patch_ok: MeasuredField | None = None
    os_name: MeasuredField | None = None
    open_ports_scanned: MeasuredField | None = None
    generated_at: str = ""

    @property
    def has_measurements(self) -> bool:
        """``True`` wenn mindestens ein Feld gemessen wurde.

        Erlaubt dem Konsumenten, den Prefill-Block samt Badge ganz auszublenden,
        wenn nichts messbar war (z. B. Non-Windows / kein Scan).
        """
        return any(
            field is not None
            for field in (
                self.firewall_active,
                self.remote_access_rdp,
                self.disk_encryption_active,
                self.patch_ok,
                self.os_name,
                self.open_ports_scanned,
            )
        )
