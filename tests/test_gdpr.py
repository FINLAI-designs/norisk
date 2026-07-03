"""
Tests für den GDPRManager.

Testet DSGVO-Zustimmungsverwaltung und Löschrecht
für Audit-Logs (ohne GUI-Dialog-Tests).

Author: Patrick Riederich
Version: 1.0
"""

import json

import pytest

from core.gdpr import GDPRManager


class TestGDPRManager:
    """Tests für DSGVO-Verwaltung."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.finlai_dir = tmp_path
        self.audit_dir = tmp_path / "audit"
        self.gdpr_file = tmp_path / "gdpr.json"

        monkeypatch.setattr("core.gdpr._FINLAI_DIR", self.finlai_dir)
        monkeypatch.setattr("core.gdpr._AUDIT_DIR", self.audit_dir)
        monkeypatch.setattr("core.gdpr._GDPR_FILE", self.gdpr_file)

    def test_creates_finlai_dir(self):
        GDPRManager()
        assert self.finlai_dir.is_dir()

    def test_not_accepted_initially(self):
        mgr = GDPRManager()
        assert mgr._is_already_accepted() is False

    def test_accepted_after_save(self):
        mgr = GDPRManager()
        mgr._save_acceptance("2026-04-19T12:00:00")
        assert mgr._is_already_accepted() is True

    def test_acceptance_file_content(self):
        mgr = GDPRManager()
        mgr._save_acceptance("2026-04-19T12:00:00")

        data = json.loads(self.gdpr_file.read_text(encoding="utf-8"))
        assert data["accepted"] is True
        assert data["accepted_at"] == "2026-04-19T12:00:00"
        assert data["version"] == "1.0"

    def test_corrupt_gdpr_file_returns_false(self):
        self.gdpr_file.write_text("not json", encoding="utf-8")
        mgr = GDPRManager()
        assert mgr._is_already_accepted() is False

    def test_gdpr_file_accepted_false(self):
        self.gdpr_file.write_text(json.dumps({"accepted": False}), encoding="utf-8")
        mgr = GDPRManager()
        assert mgr._is_already_accepted() is False

    def test_get_audit_log_path(self):
        mgr = GDPRManager()
        assert mgr.get_audit_log_path() == str(self.audit_dir)

    def test_delete_audit_logs_no_dir(self):
        """Löschung ohne Audit-Verzeichnis soll keinen Fehler werfen."""
        mgr = GDPRManager()
        mgr.delete_audit_logs()  # Kein Fehler

    def test_delete_audit_logs(self):
        mgr = GDPRManager()
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        (self.audit_dir / "audit_202603.log").write_text("entry1\n")
        (self.audit_dir / "audit_202602.log").write_text("entry2\n")

        mgr.delete_audit_logs()

        remaining = list(self.audit_dir.glob("audit_*.log"))
        assert len(remaining) == 0

    def test_delete_audit_logs_keeps_dir(self):
        """Das Audit-Verzeichnis selbst bleibt erhalten."""
        mgr = GDPRManager()
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        (self.audit_dir / "audit_202603.log").write_text("data\n")

        mgr.delete_audit_logs()
        assert self.audit_dir.is_dir()

    def test_delete_audit_logs_ignores_non_log_files(self):
        """Nur audit_*.log Dateien werden gelöscht."""
        mgr = GDPRManager()
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        other = self.audit_dir / "config.json"
        other.write_text("{}")
        (self.audit_dir / "audit_202603.log").write_text("data\n")

        mgr.delete_audit_logs()
        assert other.exists()  # config.json bleibt
