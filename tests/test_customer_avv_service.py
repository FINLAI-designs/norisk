"""
test_customer_avv_service.

End-to-End-Tests fuer CustomerAvvService (Kunden-Perspektive). Verwendet
In-Memory-DB + tmp_path fuer PDF-Storage + einen Fake-SubjectStore fuer die
Kunden-Validierung. Der globale KeyManager-Bootstrap (conftest) stellt den DEK
fuer die echte Fernet-Verschluesselung bereit.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from core.security_subject.models import Subject, SubjectKind
from tools.supply_chain_monitor.application.customer_avv_service import (
    CustomerAvvService,
    ExpiringCustomerAvv,
)
from tools.supply_chain_monitor.data.customer_avv_repository import (
    CustomerAvvRepository,
)
from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvDocumentStatus,
    CustomerAvvDocument,
    RenewalStatus,
)

_SUBJ_ID = "subj-1"


class _FakeConnContext:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_a) -> None:
        return None


class _InMemoryDB:
    def __init__(self) -> None:
        self._conn = sqlite3.connect(":memory:")

    def connection(self) -> _FakeConnContext:
        return _FakeConnContext(self._conn)


class _FakeSubjectStore:
    """Minimaler SubjectStore-Stub — der Service ruft nur ``get`` / ``list_all``."""

    def __init__(self, subjects: dict[str, Subject]) -> None:
        self._subjects = subjects

    def get(self, subject_id: str) -> Subject | None:
        return self._subjects.get(subject_id)

    def list_all(self) -> list[Subject]:
        return list(self._subjects.values())


class _CapturingEmitter:
    def __init__(self) -> None:
        self.captured: list = []

    def emit(self, findings) -> None:  # noqa: ANN001
        self.captured.extend(findings)


@pytest.fixture
def customer_service(tmp_path: Path) -> CustomerAvvService:
    repo = CustomerAvvRepository(db=_InMemoryDB())
    store = _FakeSubjectStore(
        {_SUBJ_ID: Subject(subject_id=_SUBJ_ID, kind=SubjectKind.KUNDE, name="Mandant Mueller")}
    )
    return CustomerAvvService(
        repository=repo, storage_root=tmp_path, subject_store=store
    )


def _create_dummy_pdf(path: Path, size: int = 1024) -> Path:
    path.write_bytes(b"X" * size)
    return path


class TestCustomerUpload:
    def test_upload_validiert_kunde_und_verschluesselt(
        self, customer_service: CustomerAvvService, tmp_path: Path
    ) -> None:
        source = _create_dummy_pdf(tmp_path / "Kunden-DPA.pdf", size=2048)
        now = datetime.now(UTC)
        avv = customer_service.upload_avv_for_customer(
            subject_id=_SUBJ_ID,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=365),
            notes="Kunden-AVV",
        )
        assert avv.id is not None
        assert avv.subject_id == _SUBJ_ID
        assert avv.original_filename == "Kunden-DPA.pdf"

        stored = Path(avv.file_path)
        assert stored.exists()
        assert stored.name.endswith(".pdf.enc")
        # Eigener customers/<subject_id>/-Namespace E5).
        assert stored.parent.name == _SUBJ_ID
        assert stored.parent.parent.name == "customers"
        # Ciphertext != Klartext, Original bleibt erhalten.
        assert source.exists()
        assert stored.read_bytes() != source.read_bytes()

        checklist = customer_service.get_checklist(avv.id)
        assert len(checklist) == 10
        assert {e.art28_check for e in checklist} == set(Art28Check)

    def test_upload_unbekannter_kunde_wirft_und_schreibt_nichts(
        self, customer_service: CustomerAvvService, tmp_path: Path
    ) -> None:
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="gueltigen Kunden"):
            customer_service.upload_avv_for_customer(
                subject_id="gibt-es-nicht",
                source_path=source,
                valid_from=now,
                valid_until=now + timedelta(days=1),
            )
        # Fail-closed VOR Seiteneffekt: kein customers/-Verzeichnis angelegt.
        assert not (tmp_path / "customers" / "gibt-es-nicht").exists()
        assert customer_service.list_all() == []

    def test_upload_ohne_subject_store_wirft(
        self, customer_service: CustomerAvvService, tmp_path: Path
    ) -> None:
        # Store nicht verfuegbar simulieren (fail-closed-Pfad).
        customer_service._subject_store = None  # noqa: SLF001
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="SubjectStore"):
            customer_service.upload_avv_for_customer(
                subject_id=_SUBJ_ID,
                source_path=source,
                valid_from=now,
                valid_until=now + timedelta(days=1),
            )


class TestCustomerListingAndOpen:
    def test_open_decrypted_roundtrip(
        self, customer_service: CustomerAvvService, tmp_path: Path
    ) -> None:
        content = b"PDF-INHALT-KUNDE" * 64
        source = tmp_path / "DPA.pdf"
        source.write_bytes(content)
        now = datetime.now(UTC)
        avv = customer_service.upload_avv_for_customer(
            subject_id=_SUBJ_ID,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )
        assert avv.id is not None
        opened = customer_service.open_decrypted(avv.id)
        assert opened.exists()
        assert opened.read_bytes() == content

    def test_has_customer_avvs(
        self, customer_service: CustomerAvvService, tmp_path: Path
    ) -> None:
        assert customer_service.has_customer_avvs(_SUBJ_ID) is False
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        customer_service.upload_avv_for_customer(
            subject_id=_SUBJ_ID,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )
        assert customer_service.has_customer_avvs(_SUBJ_ID) is True

    def test_delete_entfernt_pdf_und_db(
        self, customer_service: CustomerAvvService, tmp_path: Path
    ) -> None:
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        avv = customer_service.upload_avv_for_customer(
            subject_id=_SUBJ_ID,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )
        assert avv.id is not None
        stored = Path(avv.file_path)
        assert stored.exists()
        assert customer_service.delete_avv(avv.id) is True
        assert not stored.exists()
        assert customer_service.get(avv.id) is None


class TestCustomerRenewal:
    def test_list_expiring_mit_docs_param_umgeht_repo(
        self, customer_service: CustomerAvvService, tmp_path: Path
    ) -> None:
        # Repo enthaelt einen ueberfaelligen AVV...
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        customer_service.upload_avv_for_customer(
            subject_id=_SUBJ_ID,
            source_path=source,
            valid_from=now - timedelta(days=400),
            valid_until=now - timedelta(days=5),
        )
        #... aber mit explizit leerer docs-Liste wird der Repo-Read uebersprungen
        # (Perf: kein erneutes list_all beim GUI-Reload).
        assert customer_service.list_expiring(docs=[]) == []
        # Ohne docs greift der Repo-Read und findet den ueberfaelligen AVV.
        expiring = customer_service.list_expiring()
        assert len(expiring) == 1
        assert expiring[0].status is RenewalStatus.OVERDUE

    def test_list_expiring_filtert_draft_im_docs_pfad(
        self, customer_service: CustomerAvvService
    ) -> None:
        # Ueberfaellig, aber DRAFT -> auch ueber den docs=-Pfad herausgefiltert.
        now = datetime.now(UTC)
        draft = CustomerAvvDocument(
            id=1,
            subject_id=_SUBJ_ID,
            file_path="/x.pdf.enc",
            sha256="a" * 64,
            size_bytes=10,
            original_filename="x.pdf",
            valid_from=now - timedelta(days=400),
            valid_until=now - timedelta(days=5),
            status=AvvDocumentStatus.DRAFT,
        )
        assert customer_service.list_expiring(docs=[draft]) == []

    def test_emit_renewal_findings_eigener_namespace(
        self, tmp_path: Path
    ) -> None:
        emitter = _CapturingEmitter()
        repo = CustomerAvvRepository(db=_InMemoryDB())
        store = _FakeSubjectStore(
            {_SUBJ_ID: Subject(subject_id=_SUBJ_ID, kind=SubjectKind.KUNDE, name="Mandant Mueller")}
        )
        service = CustomerAvvService(
            repository=repo,
            storage_root=tmp_path,
            subject_store=store,
            ki_todo_emitter=emitter,
        )
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        avv = service.upload_avv_for_customer(
            subject_id=_SUBJ_ID,
            source_path=source,
            valid_from=now - timedelta(days=400),
            valid_until=now - timedelta(days=5),
        )
        count = service.emit_renewal_findings(
            subject_name_lookup={_SUBJ_ID: "Mandant Mueller"}
        )
        assert count == 1
        assert len(emitter.captured) == 1
        finding = emitter.captured[0]
        # Eigener evidence_id-Namespace, beruehrt Lieferanten-Findings (avv:) nicht.
        assert finding.evidence_id == f"avv_customer:{avv.id}"
        assert finding.finding_type == "avv_customer_renewal_overdue"
        assert finding.subject == "Mandant Mueller"


class TestExpiringCustomerAvvDataclass:
    def test_dataclass_felder(self) -> None:
        now = datetime.now(UTC)
        doc = CustomerAvvDocument(
            id=1,
            subject_id=_SUBJ_ID,
            file_path="/tmp/x.pdf.enc",
            sha256="a" * 64,
            size_bytes=10,
            original_filename="x.pdf",
            valid_from=now - timedelta(days=10),
            valid_until=now - timedelta(days=1),
            status=AvvDocumentStatus.ACTIVE,
        )
        item = ExpiringCustomerAvv(
            avv=doc, days_remaining=-1, status=RenewalStatus.OVERDUE
        )
        assert item.avv.subject_id == _SUBJ_ID
        assert item.days_remaining == -1
