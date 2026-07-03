"""
avv_service — UseCases fuer AVV-Tracker (Auftragsverarbeitungsvertraege).

Iter 2c:

- ``upload_avv(vendor_id, source_path, valid_from, valid_until, notes)``
  → verschluesselt die PDF nach ``~/.finlai/avv/<vendor_id>/<uuid>.pdf.enc``
  (Fernet, DEK-abgeleitet), berechnet SHA-256 des Klartexts, legt
:class:`AvvDocument` + Default-Checkliste (10 Art-28-Eintraege) an.
- ``open_decrypted(avv_id)`` → entschluesselt in eine Temp-Datei zum Oeffnen.
- ``list_for_vendor`` / ``list_all``
- ``update_checklist`` ueberschreibt die Checkliste atomar.
- ``list_expiring(within_days)`` fuer den KI-Todo-Emitter (Iter 2c-ii).
- ``delete_avv`` raeumt PDF + DB-Eintrag + Checklist auf.

Schichtzugehoerigkeit: application/ — darf domain + data + core
importieren, keine gui-Importe.

Author: Patrick Riederich
Version: 0.1
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from core.finlai_paths import finlai_dir
from core.logger import get_logger
from core.storytelling.ki_todo_emitter import KiTodoEmitter
from tools.supply_chain_monitor.data.avv_pdf_cipher import (
    ENCRYPTED_SUFFIX,
    AvvPdfCipher,
    AvvPdfCipherError,
    AvvPdfDecryptError,
)
from tools.supply_chain_monitor.data.avv_repository import AvvRepository
from tools.supply_chain_monitor.domain.models import (
    MAX_AVV_FILE_SIZE_BYTES,
    RENEWAL_WARNING_DAYS_DEFAULT,
    Art28Check,
    AvvChecklistEntry,
    AvvDocument,
    AvvDocumentStatus,
    RenewalStatus,
)

_log = get_logger(__name__)

_DEFAULT_AVV_DIR = finlai_dir() / "avv"

#: Re-Export der Cipher-Exceptions, damit die GUI sie schicht-konform
#: aus der application-Ebene importiert statt direkt aus data/ (coding-rules R5).
__all__ = [
    "AvvPdfCipherError",
    "AvvPdfDecryptError",
    "AvvService",
    "ExpiringAvv",
]


@dataclass(frozen=True)
class ExpiringAvv:
    """Compact-Tupel fuer Renewal-Listen (z. B. fuer KI-Todo-Emitter).

    Attributes:
        avv: Das AVV-Dokument.
        days_remaining: Tage bis zum ``valid_until``-Datum (negativ wenn
                       schon abgelaufen).
        status: ``EXPIRING_SOON`` oder ``OVERDUE``.
    """

    avv: AvvDocument
    days_remaining: int
    status: RenewalStatus


class AvvService:
    """Service-Layer fuer den AVV-Tracker."""

    def __init__(
        self,
        *,
        repository: AvvRepository | None = None,
        storage_root: Path | None = None,
        ki_todo_emitter: KiTodoEmitter | None = None,
        cipher: AvvPdfCipher | None = None,
    ) -> None:
        self._repo = repository or AvvRepository()
        self._storage_root = storage_root or _DEFAULT_AVV_DIR
        # Lazy-Emitter: hat im Test einen No-op-Service, in Produktion
        # die echte mainpage-Bridge. ``emit`` schluckt Exceptions, also
        # darf das hier keinen Tool-Pfad brechen.
        self._ki_emitter = ki_todo_emitter or KiTodoEmitter()
        # Lazy-Cipher: erst beim ersten Upload/Oeffnen aus dem aktiven
        # DEK gebaut — fail-closed, falls dann kein Schluessel verfuegbar ist.
        self._cipher = cipher

    def _cipher_or_default(self) -> AvvPdfCipher:
        """Liefert den (lazy gebauten) AVV-PDF-Cipher; fail-closed ohne DEK."""
        if self._cipher is None:
            self._cipher = AvvPdfCipher.from_active_key_manager()
        return self._cipher

    def _open_temp_dir(self) -> Path:
        """User-schreibbare Ablage fuer kurzzeitig entschluesselte AVV-PDFs."""
        return self._storage_root / ".open_tmp"

    # ------------------------------------------------------------------
    # Upload + Speicherung
    # ------------------------------------------------------------------

    def upload_avv(
        self,
        vendor_id: int,
        source_path: Path,
        valid_from: datetime,
        valid_until: datetime,
        notes: str = "",
    ) -> AvvDocument:
        """Importiert eine PDF, legt den AVV an und initialisiert die
        Art-28-Default-Checkliste.

        Speicherung: PDF wird **verschluesselt** (Fernet, DEK-
        abgeleitet) nach ``<storage_root>/<vendor_id>/<uuid>.pdf.enc`` abgelegt
        — das Original beim User bleibt unangetastet. Die DB speichert nur
        Pfad + SHA256 (des Klartexts) + Metadaten. Fail-closed: ohne DEK
        wird kein AVV angelegt (``AvvPdfCipherError``).

        Args:
            vendor_id: FK zu:class:`Vendor`.
            source_path: Pfad zur PDF-Datei beim User.
            valid_from: Vertragsbeginn (UTC).
            valid_until: Vertragsende (UTC).
            notes: Optionale Notiz.

        Returns:
            Das persistierte:class:`AvvDocument` mit gesetzter ID.

        Raises:
            FileNotFoundError: Wenn ``source_path`` nicht existiert.
            ValueError: Bei Domain-Validierungsfehlern (:class:`AvvDocument.__post_init__`) oder zu grosser PDF.
        """
        if not source_path.exists() or not source_path.is_file():
            raise FileNotFoundError(f"AVV-PDF nicht gefunden: {source_path}")
        size = source_path.stat().st_size
        if size > MAX_AVV_FILE_SIZE_BYTES:
            raise ValueError(
                f"AVV-PDF ist zu gross ({size} Bytes; Max "
                f"{MAX_AVV_FILE_SIZE_BYTES} Bytes)."
            )

        sha256 = _compute_sha256(source_path)
        target_dir = self._storage_root / str(int(vendor_id))
        target_dir.mkdir(parents=True, exist_ok=True)
        target_filename = f"{uuid.uuid4().hex}{ENCRYPTED_SUFFIX}"
        target_path = target_dir / target_filename
        # Ciphertext ablegen (Fernet, DEK-abgeleitet) statt Klartext-
        # Kopie. SHA256 (oben) bleibt der Klartext-Hash = Integritaet des
        # Originals. Fail-closed: _cipher_or_default wirft ohne DEK.
        self._cipher_or_default().encrypt_file(source_path, target_path)
        try:
            target_path.chmod(0o600)
        except OSError:
            # Windows kennt das nicht — kein Fehler, nur best-effort.
            pass

        doc = AvvDocument(
            id=None,
            vendor_id=int(vendor_id),
            file_path=str(target_path.resolve()),
            sha256=sha256,
            size_bytes=size,
            original_filename=source_path.name,
            valid_from=valid_from,
            valid_until=valid_until,
            status=AvvDocumentStatus.ACTIVE,
            notes=notes,
            uploaded_at=datetime.now(UTC),
        )
        new_id = self._repo.add(doc)
        # Default-Checkliste anlegen (10 Eintraege, alle is_present=None).
        defaults = [
            AvvChecklistEntry(
                id=None,
                avv_id=new_id,
                is_present=None,
                art28_check=check,
            )
            for check in Art28Check
        ]
        self._repo.replace_checklist(new_id, defaults)
        return AvvDocument(
            id=new_id,
            vendor_id=doc.vendor_id,
            file_path=doc.file_path,
            sha256=doc.sha256,
            size_bytes=doc.size_bytes,
            original_filename=doc.original_filename,
            valid_from=doc.valid_from,
            valid_until=doc.valid_until,
            status=doc.status,
            notes=doc.notes,
            uploaded_at=doc.uploaded_at,
        )

    # ------------------------------------------------------------------
    # Listing + Renewal
    # ------------------------------------------------------------------

    def list_for_vendor(self, vendor_id: int) -> list[AvvDocument]:
        return self._repo.list_for_vendor(vendor_id)

    def list_all(self) -> list[AvvDocument]:
        return self._repo.list_all()

    def get(self, avv_id: int) -> AvvDocument | None:
        return self._repo.get_by_id(avv_id)

    # ------------------------------------------------------------------
    # Oeffnen (Temp-Decrypt / D10)
    # ------------------------------------------------------------------

    def open_decrypted(self, avv_id: int) -> Path:
        """Entschluesselt das AVV-PDF in eine Temp-Datei und gibt deren Pfad zurueck.

        Die GUI oeffnet die zurueckgegebene Temp-Datei im System-Viewer. Vor dem
        Entschluesseln werden alte Temp-PDFs geloescht (:meth:`purge_open_temp`),
        sodass nie mehr als das gerade geoeffnete PDF im Klartext liegt.

        Args:
            avv_id: ID des zu oeffnenden AVV-Dokuments.

        Returns:
            Pfad zur entschluesselten Temp-PDF unter ``<storage>/.open_tmp/``.

        Raises:
            ValueError: Kein AVV mit dieser ID.
            FileNotFoundError: Hinterlegte Ciphertext-Datei fehlt (extern geloescht).
            AvvPdfDecryptError: Datei nicht entschluesselbar (altes Klartext-Format).
            AvvPdfCipherError: Kein DEK verfuegbar (fail-closed).
        """
        avv = self._repo.get_by_id(avv_id)
        if avv is None:
            raise ValueError(f"Kein AVV mit id={avv_id}.")
        source = Path(avv.file_path)
        if not source.exists():
            raise FileNotFoundError(source)
        self.purge_open_temp()
        tmp_dir = self._open_temp_dir()
        tmp_dir.mkdir(parents=True, exist_ok=True)
        # Nur der Basisname — schuetzt vor Pfad-Anteilen im original_filename.
        target = tmp_dir / Path(avv.original_filename).name
        self._cipher_or_default().decrypt_file(source, target)
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return target

    def purge_open_temp(self) -> None:
        """Loescht alle zuvor entschluesselten Temp-PDFs (best-effort).

        Wird vor jedem Oeffnen und beim Schliessen des AVV-Tabs aufgerufen.
        Ein extern noch geoeffnetes PDF kann auf Windows gesperrt sein
        (Unlink schlaegt fehl) — dann bleibt es bis zum naechsten Versuch liegen.
        """
        tmp_dir = self._open_temp_dir()
        if not tmp_dir.exists():
            return
        for entry in tmp_dir.iterdir():
            if not entry.is_file():
                continue
            try:
                entry.unlink()
            except OSError as exc:
                _log.warning("AVV-Open-Temp nicht loeschbar (%s): %s", entry, exc)

    def list_expiring(
        self,
        within_days: int = RENEWAL_WARNING_DAYS_DEFAULT,
        *,
        now: datetime | None = None,
        include_overdue: bool = True,
    ) -> list[ExpiringAvv]:
        """Listet AVVs, die innerhalb ``within_days`` ablaufen ODER bereits
        abgelaufen sind (wenn ``include_overdue=True``).

        Sortierung: kritischste zuerst (negative days_remaining oben).

        Returns:
            Liste von:class:`ExpiringAvv`.
        """
        reference = now or datetime.now(UTC)
        result: list[ExpiringAvv] = []
        for doc in self._repo.list_all():
            if doc.status is AvvDocumentStatus.DRAFT:
                continue
            status = doc.renewal_status(now=reference, warning_days=within_days)
            if status is RenewalStatus.OK:
                continue
            if status is RenewalStatus.OVERDUE and not include_overdue:
                continue
            days = (doc.valid_until - reference).days
            result.append(ExpiringAvv(avv=doc, days_remaining=days, status=status))
        result.sort(key=lambda x: x.days_remaining)
        return result

    # ------------------------------------------------------------------
    # Checklist
    # ------------------------------------------------------------------

    def get_checklist(self, avv_id: int) -> list[AvvChecklistEntry]:
        return self._repo.list_checklist(avv_id)

    def update_checklist(
        self,
        avv_id: int,
        entries: list[AvvChecklistEntry],
    ) -> None:
        """Ersetzt die komplette Checkliste atomar."""
        self._repo.replace_checklist(avv_id, entries)

    # ------------------------------------------------------------------
    # Update + Delete
    # ------------------------------------------------------------------

    def update_dates(
        self,
        avv_id: int,
        valid_from: datetime,
        valid_until: datetime,
    ) -> AvvDocument:
        """Aktualisiert nur die Gueltigkeitsdaten + Status (Re-Berechnung).

        Wenn ``valid_until`` jetzt in der Vergangenheit liegt, wird der
        Status NICHT automatisch auf ``EXPIRED`` gesetzt — das uebernimmt
        die UI (User-Entscheidung "ist abgelaufen oder verlaengert").
        """
        existing = self._repo.get_by_id(avv_id)
        if existing is None:
            raise ValueError(f"Kein AVV mit id={avv_id}.")
        updated = AvvDocument(
            id=existing.id,
            vendor_id=existing.vendor_id,
            file_path=existing.file_path,
            sha256=existing.sha256,
            size_bytes=existing.size_bytes,
            original_filename=existing.original_filename,
            valid_from=valid_from,
            valid_until=valid_until,
            status=existing.status,
            notes=existing.notes,
            uploaded_at=existing.uploaded_at,
        )
        self._repo.update(updated)
        return updated

    def set_status(
        self,
        avv_id: int,
        new_status: AvvDocumentStatus,
    ) -> AvvDocument:
        existing = self._repo.get_by_id(avv_id)
        if existing is None:
            raise ValueError(f"Kein AVV mit id={avv_id}.")
        updated = AvvDocument(
            id=existing.id,
            vendor_id=existing.vendor_id,
            file_path=existing.file_path,
            sha256=existing.sha256,
            size_bytes=existing.size_bytes,
            original_filename=existing.original_filename,
            valid_from=existing.valid_from,
            valid_until=existing.valid_until,
            status=new_status,
            notes=existing.notes,
            uploaded_at=existing.uploaded_at,
        )
        self._repo.update(updated)
        return updated

    # ------------------------------------------------------------------
    # KI-Todo-Emitter-Hook (Iter 2c-ii)
    # ------------------------------------------------------------------

    def emit_renewal_findings(
        self,
        *,
        vendor_name_lookup: dict[int, str] | None = None,
        within_days: int = RENEWAL_WARNING_DAYS_DEFAULT,
    ) -> int:
        """Schickt actionable Renewal-Findings an den:class:`KiTodoEmitter`.

        Idempotent: der nachgelagerte ``KiTodoService`` dedupt auf
        ``evidence_id`` (``f"avv:{avv_id}"``) — wiederholte Calls erzeugen
        keine doppelten Tasks.

        Args:
            vendor_name_lookup: Optionales Mapping vendor_id → name (:func:`storytelling_adapter.expiring_avvs_to_findings`).
            within_days: Schwelle fuer ``EXPIRING_SOON``-Filter.

        Returns:
            Anzahl der emittierten Findings (Status OVERDUE oder
            EXPIRING_SOON nach Adapter-Filter).
        """
        # Lokaler Import — verhindert Zirkular-Import-Risiko zwischen
        # avv_service und storytelling_adapter.
        from tools.supply_chain_monitor.application.storytelling_adapter import (  # noqa: PLC0415
            expiring_avvs_to_findings,
        )

        expiring = self.list_expiring(within_days=within_days)
        findings = expiring_avvs_to_findings(
            expiring, vendor_name_lookup=vendor_name_lookup
        )
        if findings:
            self._ki_emitter.emit(findings)
        return len(findings)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_avv(self, avv_id: int) -> bool:
        """Loescht AVV-Eintrag + zugehoerige PDF + Checkliste."""
        existing = self._repo.get_by_id(avv_id)
        if existing is None:
            return False
        path = Path(existing.file_path)
        try:
            if path.exists():
                path.unlink()
        except OSError as exc:
            _log.warning(
                "delete_avv: PDF konnte nicht geloescht werden (%s): %s",
                path,
                exc,
            )
        # Repository raeumt Checkliste cascading mit auf.
        return self._repo.delete(avv_id)


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
