"""
customer_avv_service — UseCases fuer KUNDEN-AVVs, zweite Perspektive).

Gegenstueck zu:mod:`avv_service`: WIR sind Auftragsverarbeiter, der Kunde ist
Verantwortlicher. Ein Kunden-AVV haengt an einer ``subject_id`` (kanonische
Kunden-Identitaet ``Subject``/``kind=KUNDE``) statt an einem ``vendor_id``.

- ``upload_avv_for_customer(subject_id, source_path, valid_from, valid_until, notes)``
  → validiert den Kunden ueber den ``SubjectStore``-Port (fail-closed gegen
  Phantom-Referenzen), verschluesselt die PDF nach
  ``~/.finlai/avv/customers/<subject_id>/<uuid>.pdf.enc`` (Fernet, DEK-abgeleitet,
  gleicher DEK wie Lieferanten-AVVs), legt:class:`CustomerAvvDocument`
  + Default-Checkliste (10 Art-28-Eintraege) an.
- ``open_decrypted`` / ``purge_open_temp`` — Temp-Decrypt zum Oeffnen (eigener
  ``customers/.open_tmp``-Namespace).
- ``list_for_customer`` / ``list_all`` / ``list_expiring``.
- ``get_checklist`` / ``update_checklist``.
- ``delete_avv`` raeumt PDF + DB-Eintrag + Checkliste auf.
- ``has_customer_avvs`` fuer den DSGVO-Loesch-Block E4).

Schichtzugehoerigkeit: application/ — darf domain + data + core importieren,
keine gui-Importe. Namensaufloesung NUR ueber den core ``SubjectStore``-Port
(nie ein direkter ``tools.security_scoring``-Import).

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
from core.security_subject.ports import SubjectStore
from core.security_subject.resolver import create_subject_store
from core.storytelling.ki_todo_emitter import KiTodoEmitter
from tools.supply_chain_monitor.data.avv_pdf_cipher import (
    ENCRYPTED_SUFFIX,
    AvvPdfCipher,
    AvvPdfCipherError,
    AvvPdfDecryptError,
)
from tools.supply_chain_monitor.data.customer_avv_repository import (
    CustomerAvvRepository,
)
from tools.supply_chain_monitor.domain.models import (
    MAX_AVV_FILE_SIZE_BYTES,
    RENEWAL_WARNING_DAYS_DEFAULT,
    Art28Check,
    AvvChecklistEntry,
    AvvDocumentStatus,
    CustomerAvvDocument,
    RenewalStatus,
)

_log = get_logger(__name__)

_DEFAULT_AVV_DIR = finlai_dir() / "avv"
#: Namespace-Unterordner fuer Kunden-AVVs — trennt sie von den numerischen
#: Vendor-Ordnern E5), kollisionsfrei + eindeutig fuer Backups.
_CUSTOMER_NS = "customers"

#: Re-Export der Cipher-Exceptions fuer die schicht-konforme GUI-Nutzung.
__all__ = [
    "AvvPdfCipherError",
    "AvvPdfDecryptError",
    "CustomerAvvService",
    "ExpiringCustomerAvv",
]


@dataclass(frozen=True)
class ExpiringCustomerAvv:
    """Compact-Tupel fuer Renewal-Listen der Kunden-Perspektive.

    Attributes:
        avv: Das Kunden-AVV-Dokument.
        days_remaining: Tage bis ``valid_until`` (negativ wenn abgelaufen).
        status: ``EXPIRING_SOON`` oder ``OVERDUE``.
    """

    avv: CustomerAvvDocument
    days_remaining: int
    status: RenewalStatus


class CustomerAvvService:
    """Service-Layer fuer die Kunden-Perspektive des AVV-Trackers."""

    def __init__(
        self,
        *,
        repository: CustomerAvvRepository | None = None,
        storage_root: Path | None = None,
        ki_todo_emitter: KiTodoEmitter | None = None,
        cipher: AvvPdfCipher | None = None,
        subject_store: SubjectStore | None = None,
    ) -> None:
        self._repo = repository or CustomerAvvRepository()
        self._storage_root = storage_root or _DEFAULT_AVV_DIR
        self._ki_emitter = ki_todo_emitter or KiTodoEmitter()
        # Lazy-Cipher: erst beim ersten Upload/Oeffnen aus dem aktiven
        # DEK gebaut — fail-closed, falls dann kein Schluessel verfuegbar ist.
        self._cipher = cipher
        # SubjectStore-Port E2): validiert subject_id beim Upload. Lazy
        # ueber den core-Resolver bezogen (fail-soft None) — der Upload wird
        # fail-closed, wenn keine Validierung moeglich ist.
        self._subject_store = subject_store or create_subject_store()

    def _cipher_or_default(self) -> AvvPdfCipher:
        """Liefert den (lazy gebauten) AVV-PDF-Cipher; fail-closed ohne DEK."""
        if self._cipher is None:
            self._cipher = AvvPdfCipher.from_active_key_manager()
        return self._cipher

    def _customer_dir(self, subject_id: str) -> Path:
        """Ablage-Verzeichnis fuer die PDFs eines Kunden (eigener Namespace)."""
        return self._storage_root / _CUSTOMER_NS / subject_id

    def _open_temp_dir(self) -> Path:
        """User-schreibbare Ablage fuer kurzzeitig entschluesselte Kunden-PDFs."""
        return self._storage_root / _CUSTOMER_NS / ".open_tmp"

    # ------------------------------------------------------------------
    # Upload + Speicherung
    # ------------------------------------------------------------------

    def upload_avv_for_customer(
        self,
        subject_id: str,
        source_path: Path,
        valid_from: datetime,
        valid_until: datetime,
        notes: str = "",
    ) -> CustomerAvvDocument:
        """Importiert eine PDF als Kunden-AVV und legt die Art-28-Checkliste an.

        Validiert ZUERST den Kunden ueber den ``SubjectStore``-Port (fail-closed):
        ohne erreichbaren Store oder bei unbekannter ``subject_id`` wird KEIN PDF
        verschluesselt und KEINE DB-Zeile geschrieben. Danach wie die Lieferanten-
        Sicht: SHA-256 des Klartexts, Fernet-Verschluesselung (DEK-abgeleitet) nach
        ``<storage_root>/customers/<subject_id>/<uuid>.pdf.enc``.

        Args:
            subject_id: UUID des Kunden-``Subject`` (kind=KUNDE).
            source_path: Pfad zur PDF-Datei beim User.
            valid_from: Vertragsbeginn (UTC).
            valid_until: Vertragsende (UTC).
            notes: Optionale Notiz.

        Returns:
            Das persistierte:class:`CustomerAvvDocument` mit gesetzter ID.

        Raises:
            FileNotFoundError: Wenn ``source_path`` nicht existiert.
            ValueError: Unbekannter Kunde, SubjectStore nicht verfuegbar,
                zu grosse PDF oder Domain-Validierungsfehler.
        """
        # Fail-closed-Validierung VOR jedem Seiteneffekt E2).
        if self._subject_store is None:
            raise ValueError(
                "Kunden-AVV kann nicht angelegt werden: Kunden-Verwaltung "
                "(SubjectStore) ist nicht verfuegbar."
            )
        subject = self._subject_store.get(subject_id)
        if subject is None:
            # Bewusst ohne subject_id in der Meldung (Datensparsamkeit) — die
            # GUI zeigt diese Meldung direkt an.
            raise ValueError(
                "Der ausgewaehlte Kunde ist nicht (mehr) verfuegbar. Bitte "
                "waehlen Sie einen gueltigen Kunden."
            )

        if not source_path.exists() or not source_path.is_file():
            raise FileNotFoundError(f"AVV-PDF nicht gefunden: {source_path}")
        size = source_path.stat().st_size
        if size > MAX_AVV_FILE_SIZE_BYTES:
            raise ValueError(
                f"AVV-PDF ist zu gross ({size} Bytes; Max "
                f"{MAX_AVV_FILE_SIZE_BYTES} Bytes)."
            )

        sha256 = _compute_sha256(source_path)
        target_dir = self._customer_dir(subject_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        target_filename = f"{uuid.uuid4().hex}{ENCRYPTED_SUFFIX}"
        target_path = target_dir / target_filename
        # Ciphertext ablegen (Fernet, DEK-abgeleitet) statt Klartext-Kopie.
        # Fail-closed: _cipher_or_default wirft ohne DEK.
        self._cipher_or_default().encrypt_file(source_path, target_path)
        try:
            target_path.chmod(0o600)
        except OSError:
            # Windows kennt das nicht — kein Fehler, nur best-effort.
            pass

        doc = CustomerAvvDocument(
            id=None,
            subject_id=subject_id,
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
            AvvChecklistEntry(id=None, avv_id=new_id, is_present=None, art28_check=check)
            for check in Art28Check
        ]
        self._repo.replace_checklist(new_id, defaults)
        return self._repo.get_by_id(new_id) or doc

    # ------------------------------------------------------------------
    # Listing + Renewal
    # ------------------------------------------------------------------

    def list_for_customer(self, subject_id: str) -> list[CustomerAvvDocument]:
        return self._repo.list_for_customer(subject_id)

    def list_all(self) -> list[CustomerAvvDocument]:
        return self._repo.list_all()

    def get(self, avv_id: int) -> CustomerAvvDocument | None:
        return self._repo.get_by_id(avv_id)

    def has_customer_avvs(self, subject_id: str) -> bool:
        """True, wenn fuer das Subjekt Kunden-AVVs archiviert sind.

        Grundlage des DSGVO-Loesch-Blocks E4): solange True, darf das
        Kunden-``Subject`` nicht geloescht werden.
        """
        return self._repo.has_references(subject_id)

    # ------------------------------------------------------------------
    # Oeffnen (Temp-Decrypt)
    # ------------------------------------------------------------------

    def open_decrypted(self, avv_id: int) -> Path:
        """Entschluesselt das Kunden-AVV-PDF in eine Temp-Datei und gibt den Pfad zurueck.

        Vor dem Entschluesseln werden alte Temp-PDFs geloescht
        (:meth:`purge_open_temp`), sodass nie mehr als das gerade geoeffnete PDF
        im Klartext liegt.

        Args:
            avv_id: ID des zu oeffnenden Kunden-AVV-Dokuments.

        Returns:
            Pfad zur entschluesselten Temp-PDF unter ``<storage>/customers/.open_tmp/``.

        Raises:
            ValueError: Kein Kunden-AVV mit dieser ID.
            FileNotFoundError: Hinterlegte Ciphertext-Datei fehlt (extern geloescht).
            AvvPdfDecryptError: Datei nicht entschluesselbar.
            AvvPdfCipherError: Kein DEK verfuegbar (fail-closed).
        """
        avv = self._repo.get_by_id(avv_id)
        if avv is None:
            raise ValueError(f"Kein Kunden-AVV mit id={avv_id}.")
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
        """Loescht alle zuvor entschluesselten Kunden-Temp-PDFs (best-effort)."""
        tmp_dir = self._open_temp_dir()
        if not tmp_dir.exists():
            return
        for entry in tmp_dir.iterdir():
            if not entry.is_file():
                continue
            try:
                entry.unlink()
            except OSError as exc:
                _log.warning("Kunden-AVV-Open-Temp nicht loeschbar (%s): %s", entry, exc)

    def list_expiring(
        self,
        within_days: int = RENEWAL_WARNING_DAYS_DEFAULT,
        *,
        now: datetime | None = None,
        include_overdue: bool = True,
        docs: list[CustomerAvvDocument] | None = None,
    ) -> list[ExpiringCustomerAvv]:
        """Listet Kunden-AVVs, die ablaufen ODER bereits abgelaufen sind.

        Sortierung: kritischste zuerst (negative days_remaining oben).

        Args:
            within_days: Schwelle fuer ``EXPIRING_SOON``.
            now: Referenz-Zeitpunkt (Default ``datetime.now(UTC)``).
            include_overdue: Ueberfaellige mitlisten.
            docs: Optional bereits geladene Dokumente — vermeidet einen
                erneuten ``list_all``-DB-Aufruf (Perf, kein dreifaches Laden beim
                GUI-Reload/Perf-Tier-1).

        Returns:
            Liste von:class:`ExpiringCustomerAvv`.
        """
        reference = now or datetime.now(UTC)
        source = docs if docs is not None else self._repo.list_all()
        result: list[ExpiringCustomerAvv] = []
        for doc in source:
            if doc.status is AvvDocumentStatus.DRAFT:
                continue
            status = doc.renewal_status(now=reference, warning_days=within_days)
            if status is RenewalStatus.OK:
                continue
            if status is RenewalStatus.OVERDUE and not include_overdue:
                continue
            days = (doc.valid_until - reference).days
            result.append(
                ExpiringCustomerAvv(avv=doc, days_remaining=days, status=status)
            )
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
    ) -> CustomerAvvDocument:
        """Aktualisiert nur die Gueltigkeitsdaten (Status bleibt User-Entscheidung)."""
        existing = self._repo.get_by_id(avv_id)
        if existing is None:
            raise ValueError(f"Kein Kunden-AVV mit id={avv_id}.")
        updated = CustomerAvvDocument(
            id=existing.id,
            subject_id=existing.subject_id,
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
    ) -> CustomerAvvDocument:
        existing = self._repo.get_by_id(avv_id)
        if existing is None:
            raise ValueError(f"Kein Kunden-AVV mit id={avv_id}.")
        updated = CustomerAvvDocument(
            id=existing.id,
            subject_id=existing.subject_id,
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
    # KI-Todo-Emitter-Hook (eigener evidence_id-Namespace)
    # ------------------------------------------------------------------

    def emit_renewal_findings(
        self,
        *,
        subject_name_lookup: dict[str, str] | None = None,
        within_days: int = RENEWAL_WARNING_DAYS_DEFAULT,
        expiring: list[ExpiringCustomerAvv] | None = None,
    ) -> int:
        """Schickt actionable Kunden-AVV-Renewal-Findings an den KiTodoEmitter.

        Idempotent: dedupt auf ``evidence_id = f"avv_customer:{avv_id}"`` — ein
        eigener Namespace, der die Lieferanten-Findings (``avv:{id}``) nicht
        beruehrt.

        Args:
            subject_name_lookup: Optionales Mapping ``subject_id → Kundenname``.
            within_days: Schwelle fuer ``EXPIRING_SOON``-Filter.
            expiring: Optional bereits berechnete Renewal-Liste —
                vermeidet einen erneuten ``list_expiring``/``list_all`` (Perf).

        Returns:
            Anzahl der emittierten Findings.
        """
        # Lokaler Import — verhindert Zirkular-Import-Risiko mit storytelling_adapter.
        from tools.supply_chain_monitor.application.storytelling_adapter import (  # noqa: PLC0415
            expiring_customer_avvs_to_findings,
        )

        items = expiring if expiring is not None else self.list_expiring(
            within_days=within_days
        )
        findings = expiring_customer_avvs_to_findings(
            items, subject_name_lookup=subject_name_lookup
        )
        if findings:
            self._ki_emitter.emit(findings)
        return len(findings)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_avv(self, avv_id: int) -> bool:
        """Loescht Kunden-AVV-Eintrag + zugehoerige PDF + Checkliste."""
        existing = self._repo.get_by_id(avv_id)
        if existing is None:
            return False
        path = Path(existing.file_path)
        try:
            if path.exists():
                path.unlink()
        except OSError as exc:
            _log.warning(
                "delete_avv: Kunden-PDF konnte nicht geloescht werden (%s): %s",
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
