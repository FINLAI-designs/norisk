"""
test_supply_chain_avv_service.

End-to-End-Tests fuer AvvService + SubprocessorService.
Verwendet In-Memory-DB + tmp_path fuer PDF-Storage.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tools.supply_chain_monitor.application.avv_service import (
    AvvPdfDecryptError,
    AvvService,
)
from tools.supply_chain_monitor.application.subprocessor_service import (
    CONCENTRATION_WARNING_THRESHOLD,
    SubprocessorService,
)
from tools.supply_chain_monitor.data.avv_repository import AvvRepository
from tools.supply_chain_monitor.data.subprocessor_repository import (
    SubprocessorRepository,
)
from tools.supply_chain_monitor.domain.models import (
    Art28Check,
    AvvDocumentStatus,
    RenewalStatus,
    VendorCategory,
)


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


@pytest.fixture
def avv_service(tmp_path: Path) -> AvvService:
    db = _InMemoryDB()
    repo = AvvRepository(db=db)
    return AvvService(repository=repo, storage_root=tmp_path)


@pytest.fixture
def sub_service() -> SubprocessorService:
    return SubprocessorService(repository=SubprocessorRepository(db=_InMemoryDB()))


def _create_dummy_pdf(path: Path, size: int = 1024) -> Path:
    path.write_bytes(b"X" * size)
    return path


# ---------------------------------------------------------------------------
# AvvService — Upload
# ---------------------------------------------------------------------------


class TestAvvUpload:
    def test_upload_verschluesselt_pdf_und_legt_default_checkliste_an(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        source = _create_dummy_pdf(tmp_path / "DPA.pdf", size=2048)
        now = datetime.now(UTC)
        avv = avv_service.upload_avv(
            vendor_id=42,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=365),
            notes="Test-AVV",
        )
        assert avv.id is not None
        assert avv.vendor_id == 42
        assert avv.original_filename == "DPA.pdf"
        assert avv.size_bytes == 2048

        # PDF wurde VERSCHLUESSELT abgelegt, Original bleibt erhalten.
        assert source.exists()
        stored = Path(avv.file_path)
        assert stored.exists()
        assert stored.name.endswith(".pdf.enc")
        assert stored.parent.name == "42"  # vendor_id-Subdir
        # Ciphertext != Klartext.
        assert stored.read_bytes() != source.read_bytes()

        # Default-Checkliste mit 10 Eintraegen.
        checklist = avv_service.get_checklist(avv.id)
        assert len(checklist) == 10
        assert all(e.is_present is None for e in checklist)
        art28_set = {e.art28_check for e in checklist}
        assert art28_set == set(Art28Check)

    def test_upload_unbekannte_datei_wirft(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            avv_service.upload_avv(
                vendor_id=1,
                source_path=tmp_path / "does_not_exist.pdf",
                valid_from=datetime.now(UTC),
                valid_until=datetime.now(UTC) + timedelta(days=30),
            )

    def test_upload_zu_grosse_pdf_wirft(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        from tools.supply_chain_monitor.domain.models import (
            MAX_AVV_FILE_SIZE_BYTES,  # noqa: PLC0415
        )

        big = _create_dummy_pdf(tmp_path / "big.pdf", size=MAX_AVV_FILE_SIZE_BYTES + 1)
        with pytest.raises(ValueError, match="zu gross"):
            avv_service.upload_avv(
                vendor_id=1,
                source_path=big,
                valid_from=datetime.now(UTC),
                valid_until=datetime.now(UTC) + timedelta(days=30),
            )


class TestAvvEncryption:
    """ — At-Rest-Verschluesselung + Temp-Decrypt beim Oeffnen."""

    def _upload(self, svc: AvvService, source: Path) -> int:
        now = datetime.now(UTC)
        avv = svc.upload_avv(
            vendor_id=7,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=365),
        )
        assert avv.id is not None
        return avv.id

    def test_open_decrypted_round_trip(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        content = b"%PDF-1.7 echte-AVV-bytes \x00\x01\x02 mit Umlaut-Pfad"
        source = tmp_path / "DPA.pdf"
        source.write_bytes(content)
        avv_id = self._upload(avv_service, source)

        temp = avv_service.open_decrypted(avv_id)
        assert temp.exists()
        assert temp.name == "DPA.pdf"  # nutzerfreundlicher Originalname
        assert temp.read_bytes() == content  # round-trip Klartext

    def test_open_decrypted_legacy_plaintext_raises(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        # Bestehende verschluesselte Datei durch Klartext ersetzen = alter Bestand.
        avv_id = self._upload(avv_service, _create_dummy_pdf(tmp_path / "x.pdf"))
        avv = avv_service.get(avv_id)
        assert avv is not None
        Path(avv.file_path).write_bytes(b"kein-fernet-token")
        with pytest.raises(AvvPdfDecryptError):
            avv_service.open_decrypted(avv_id)

    def test_open_decrypted_missing_ciphertext_raises(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        avv_id = self._upload(avv_service, _create_dummy_pdf(tmp_path / "x.pdf"))
        avv = avv_service.get(avv_id)
        assert avv is not None
        Path(avv.file_path).unlink()
        with pytest.raises(FileNotFoundError):
            avv_service.open_decrypted(avv_id)

    def test_purge_open_temp_removes_decrypted_files(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        avv_id = self._upload(avv_service, _create_dummy_pdf(tmp_path / "x.pdf"))
        temp = avv_service.open_decrypted(avv_id)
        assert temp.exists()
        avv_service.purge_open_temp()
        assert not temp.exists()

    def test_open_decrypted_purges_previous(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        # Zweites Oeffnen raeumt das Temp-PDF des ersten weg (nur eines im Klartext).
        id_a = self._upload(avv_service, _create_dummy_pdf(tmp_path / "a.pdf"))
        id_b = self._upload(avv_service, _create_dummy_pdf(tmp_path / "b.pdf"))
        first = avv_service.open_decrypted(id_a)
        assert first.exists()
        second = avv_service.open_decrypted(id_b)
        assert second.exists()
        assert not first.exists()  # vorheriges Temp wurde gepurged


class TestAvvLifecycle:
    def test_update_dates_aendert_nur_gueltigkeit(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        avv = avv_service.upload_avv(
            vendor_id=1,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )
        assert avv.id is not None
        new_until = now + timedelta(days=400)
        updated = avv_service.update_dates(
            avv.id, valid_from=now, valid_until=new_until
        )
        assert updated.valid_until.date() == new_until.date()
        # SHA256 + file_path bleiben.
        assert updated.sha256 == avv.sha256
        assert updated.file_path == avv.file_path

    def test_set_status_expired(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        avv = avv_service.upload_avv(
            vendor_id=1,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )
        assert avv.id is not None
        updated = avv_service.set_status(avv.id, AvvDocumentStatus.EXPIRED)
        assert updated.status is AvvDocumentStatus.EXPIRED

    def test_delete_entfernt_avv_und_pdf(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        source = _create_dummy_pdf(tmp_path / "x.pdf")
        now = datetime.now(UTC)
        avv = avv_service.upload_avv(
            vendor_id=1,
            source_path=source,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )
        assert avv.id is not None
        stored = Path(avv.file_path)
        assert stored.exists()

        assert avv_service.delete_avv(avv.id) is True
        assert not stored.exists()
        assert avv_service.get(avv.id) is None


class TestAvvRenewalListing:
    def _upload_with_until(
        self,
        svc: AvvService,
        tmp_path: Path,
        sha_char: str,
        days_until: int,
        vendor_id: int = 1,
    ) -> None:
        src = _create_dummy_pdf(tmp_path / f"{sha_char}.pdf")
        now = datetime.now(UTC)
        svc.upload_avv(
            vendor_id=vendor_id,
            source_path=src,
            valid_from=now - timedelta(days=30),
            valid_until=now + timedelta(days=days_until),
        )

    def test_list_expiring_filtert_und_sortiert(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        self._upload_with_until(avv_service, tmp_path, "a", days_until=400)  # OK
        self._upload_with_until(avv_service, tmp_path, "b", days_until=45)  # EXPIRING
        self._upload_with_until(avv_service, tmp_path, "c", days_until=-5)  # OVERDUE
        self._upload_with_until(avv_service, tmp_path, "d", days_until=10)  # EXPIRING

        expiring = avv_service.list_expiring(within_days=90)
        assert len(expiring) == 3  # a faellt raus (OK)
        # Sortiert nach days_remaining asc — OVERDUE zuerst.
        assert expiring[0].status is RenewalStatus.OVERDUE
        assert expiring[0].days_remaining < 0
        assert expiring[1].days_remaining < expiring[2].days_remaining

    def test_list_expiring_ohne_overdue(
        self, avv_service: AvvService, tmp_path: Path
    ) -> None:
        self._upload_with_until(avv_service, tmp_path, "a", days_until=45)
        self._upload_with_until(avv_service, tmp_path, "b", days_until=-5)
        only_soon = avv_service.list_expiring(include_overdue=False)
        assert len(only_soon) == 1
        assert only_soon[0].status is RenewalStatus.EXPIRING_SOON


# ---------------------------------------------------------------------------
# SubprocessorService
# ---------------------------------------------------------------------------


class TestSubprocessorService:
    def test_add_und_list(self, sub_service: SubprocessorService) -> None:
        sub = sub_service.add_subprocessor(
            name="AWS", country="US", category=VendorCategory.CLOUD
        )
        assert sub.id is not None
        assert sub_service.list_subprocessors() == [sub]

    def test_concentration_findings_warning_threshold(
        self, sub_service: SubprocessorService
    ) -> None:
        aws = sub_service.add_subprocessor(
            name="AWS", country="US", category=VendorCategory.CLOUD
        )
        cf = sub_service.add_subprocessor(
            name="Cloudflare", country="US", category=VendorCategory.MSP
        )
        assert aws.id is not None
        assert cf.id is not None

        # AWS hat 3 distinct vendoren → concentrated
        sub_service.link(vendor_id=1, subprocessor_id=aws.id, role="Storage")
        sub_service.link(vendor_id=2, subprocessor_id=aws.id)
        sub_service.link(vendor_id=3, subprocessor_id=aws.id)
        # Cloudflare nur 1 → nicht concentrated
        sub_service.link(vendor_id=1, subprocessor_id=cf.id)

        findings = sub_service.concentration_findings()
        # Sortiert nach vendor_count desc → AWS zuerst.
        assert findings[0].subprocessor.name == "AWS"
        assert findings[0].vendor_count == 3
        assert findings[0].is_concentrated is True
        assert findings[1].subprocessor.name == "Cloudflare"
        assert findings[1].vendor_count == 1
        assert findings[1].is_concentrated is False
        assert CONCENTRATION_WARNING_THRESHOLD == 3
