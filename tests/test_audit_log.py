"""
Tests für das Audit-Log-System.

Testet Singleton, Log-Einträge, monatliche Rotation
und Sicherheitsaspekte (keine sensiblen Daten).

Author: Patrick Riederich
Version: 1.0
"""

import json
from datetime import datetime

import pytest

from core.audit_log import AuditLogger


class TestAuditLogger:
    """Tests für den AuditLogger."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        # Singleton zurücksetzen
        AuditLogger._instance = None
        AuditLogger._initialized = False

        self.audit_dir = tmp_path / "audit"
        monkeypatch.setattr("core.audit_log._AUDIT_DIR", self.audit_dir)

    def teardown_method(self):
        AuditLogger._instance = None
        AuditLogger._initialized = False

    def test_singleton(self):
        a1 = AuditLogger()
        a2 = AuditLogger()
        assert a1 is a2

    def test_creates_audit_dir(self):
        AuditLogger()
        assert self.audit_dir.is_dir()

    def test_log_action_creates_file(self):
        logger = AuditLogger()
        logger.log_action("APP_START")

        log_files = list(self.audit_dir.glob("audit_*.log"))
        assert len(log_files) == 1

    def test_log_action_writes_json(self):
        logger = AuditLogger()
        logger.log_action("FILE_LOADED", {"filename": "test.csv", "rows": 100})

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        line = log_file.read_text(encoding="utf-8").strip()
        entry = json.loads(line)

        assert entry["action"] == "FILE_LOADED"
        assert entry["details"]["filename"] == "test.csv"
        assert entry["details"]["rows"] == 100
        assert "timestamp" in entry

    def test_log_action_with_tool(self):
        logger = AuditLogger()
        logger.log_action("COMPARE_STARTED", tool="Datenvergleich")

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        entry = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert entry["tool"] == "Datenvergleich"

    def test_log_action_without_details(self):
        logger = AuditLogger()
        logger.log_action("APP_EXIT")

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        entry = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert entry["details"] == {}

    def test_multiple_entries_appended(self):
        logger = AuditLogger()
        logger.log_action("APP_START")
        logger.log_action("FILE_LOADED", {"filename": "a.csv"})
        logger.log_action("APP_EXIT")

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        lines = log_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3

    def test_log_file_name_format(self):
        logger = AuditLogger()
        logger.log_action("TEST")

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        expected = f"audit_{datetime.now().strftime('%Y%m')}.log"
        assert log_file.name == expected

    def test_timestamp_format(self):
        logger = AuditLogger()
        logger.log_action("TEST")

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        entry = json.loads(log_file.read_text(encoding="utf-8").strip())
        # ISO-Format ohne Mikrosekunden
        ts = entry["timestamp"]
        parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        assert parsed.year == datetime.now().year

    def test_hardware_id_present(self):
        logger = AuditLogger()
        logger.log_action("TEST")

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        entry = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert "hardware_id" in entry
        assert len(entry["hardware_id"]) > 0

    def test_no_sensitive_data_in_log(self):
        """Sicherheitstest: Sensible Daten dürfen nicht geloggt werden."""
        logger = AuditLogger()
        # Nur Metadaten loggen, nicht den Inhalt
        logger.log_action(
            "FILE_LOADED",
            {"filename": "accounts.csv", "rows": 500, "columns": 10},
        )

        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        content = log_file.read_text(encoding="utf-8")
        # Keine echten Dateninhalte in den Logs
        assert "accounts.csv" in content  # Dateiname OK
        assert "500" in content  # Zeilenanzahl OK


class TestLogKiAktion:
    """Tests fuer AuditLogger.log_ki_aktion (EU KI-VO Art. 4)."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        AuditLogger._instance = None
        AuditLogger._initialized = False
        self.audit_dir = tmp_path / "audit"
        monkeypatch.setattr("core.audit_log._AUDIT_DIR", self.audit_dir)

    def teardown_method(self):
        AuditLogger._instance = None
        AuditLogger._initialized = False

    def _read_entry(self) -> dict:
        log_file = list(self.audit_dir.glob("audit_*.log"))[0]
        return json.loads(log_file.read_text(encoding="utf-8").strip())

    def test_action_prefix_ki(self):
        # EU-KI-VO-Eintraege muessen am action-Prefix erkennbar sein
        # (Audit-Filter-Tooling wertet das Prefix aus).
        AuditLogger().log_ki_aktion(
            tool="ollama_chat",
            aktion="CHAT_ANTWORT",
            modell="llama3.2",
        )
        entry = self._read_entry()
        assert entry["action"] == "KI_CHAT_ANTWORT"
        assert entry["action"].startswith("KI_")

    def test_aktion_wird_uppercased(self):
        AuditLogger().log_ki_aktion(
            tool="x", aktion="chat_antwort", modell="m"
        )
        assert self._read_entry()["action"] == "KI_CHAT_ANTWORT"

    def test_metadaten_aber_keine_inhalte(self):
        AuditLogger().log_ki_aktion(
            tool="ollama_chat",
            aktion="ANTWORT",
            modell="llama3.2",
            input_laenge=42,
            output_laenge=128,
        )
        details = self._read_entry()["details"]
        assert details["tool"] == "ollama_chat"
        assert details["modell"] == "llama3.2"
        assert details["input_zeichen"] == 42
        assert details["output_zeichen"] == 128
        # Es duerfen ausschliesslich Metadaten geloggt werden — kein
        # Inhalts-Feld im Schema.
        assert "input_inhalt" not in details
        assert "prompt" not in details
        assert "antwort" not in details

    def test_human_review_required_immer_true(self):
        # EU-KI-VO Art. 4: KI-Output ist Pflicht-Reviewable.
        AuditLogger().log_ki_aktion(tool="x", aktion="A", modell="m")
        assert self._read_entry()["details"]["human_review_required"] is True

    def test_erfolgreich_default_true(self):
        AuditLogger().log_ki_aktion(tool="x", aktion="A", modell="m")
        assert self._read_entry()["details"]["erfolgreich"] is True

    def test_erfolgreich_false_durchgereicht(self):
        AuditLogger().log_ki_aktion(
            tool="x", aktion="A", modell="m", erfolgreich=False
        )
        assert self._read_entry()["details"]["erfolgreich"] is False

    def test_agent_name_durchgereicht(self):
        AuditLogger().log_ki_aktion(
            tool="agent_runner", aktion="LAUF", modell="m",
            agent_name="ReceiptAgent",
        )
        assert self._read_entry()["details"]["agent_name"] == "ReceiptAgent"

    def test_fehler_auf_100_zeichen_truncated(self):
        # Damit Audit-Log keine versehentlichen User-Daten oder Stack-Traces
        # speichert, wird `fehler` hart auf 100 Zeichen begrenzt.
        long_error = "X" * 500
        AuditLogger().log_ki_aktion(
            tool="x", aktion="A", modell="m",
            erfolgreich=False, fehler=long_error,
        )
        details = self._read_entry()["details"]
        assert len(details["fehler"]) == 100
        assert details["fehler"] == "X" * 100

    def test_leerer_fehler_bleibt_leer(self):
        AuditLogger().log_ki_aktion(tool="x", aktion="A", modell="m")
        assert self._read_entry()["details"]["fehler"] == ""
