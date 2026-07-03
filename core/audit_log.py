"""
audit_log — Audit-Log-System für FINLAI

Protokolliert Benutzeraktionen als JSON-Einträge in monatlich rotierende
Dateien unter ``~/.finlai/audit/audit_YYYYMM.log``.

Singleton: Es existiert genau eine AuditLogger-Instanz pro Prozess.

WICHTIG: Es werden ausschließlich Metadaten geloggt (Dateiname, Zeilenanzahl,
Spaltenanzahl). Dateninhalte werden niemals in das Audit-Log geschrieben.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from core.finlai_paths import finlai_dir
from core.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------
_FINLAI_DIR = finlai_dir()
_AUDIT_DIR = _FINLAI_DIR / "audit"


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------
class AuditLogger:
    """Singleton-Logger für Benutzeraktionen in FINLAI.

    Schreibt strukturierte JSON-Einträge (eine Zeile pro Aktion) in
    monatlich rotierende Dateien unter ``~/.finlai/audit/``.

    Folgende Aktionen sind vorgesehen:
        - APP_START / APP_EXIT
        - FILE_LOADED (Dateiname, Größe, Zeilen — kein Inhalt)
        - COMPARE_STARTED / COMPARE_FINISHED
        - EXPORT_CREATED
        - MAPPING_SAVED / MAPPING_LOADED
        - LICENSE_VALIDATED / LICENSE_INVALID

    Beispiel::

        logger = AuditLogger
        logger.log_action("FILE_LOADED", {"filename": "daten.csv", "rows": 500})
    """

    _instance: AuditLogger | None = None
    _initialized: bool = False

    def __new__(cls) -> AuditLogger:
        """Stellt sicher, dass nur eine Instanz existiert (Singleton)."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialisiert den AuditLogger (wird nur beim ersten Aufruf ausgeführt)."""
        if self._initialized:
            return
        self.__class__._initialized = True

        _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        log.debug("AuditLogger initialisiert — Audit-Verzeichnis: %s", _AUDIT_DIR)

    # ------------------------------------------------------------------
    def log_action(
        self,
        action: str,
        details: dict | None = None,
        tool: str | None = None,
    ) -> None:
        """Schreibt einen Audit-Log-Eintrag.

        Der Eintrag enthält Zeitstempel, Aktion, optionales Tool,
        Details-Metadaten und die Hardware-ID des Geräts. Dateiinhalte
        werden niemals geloggt.

        Args:
            action: Aktionsbezeichner (z.B. "FILE_LOADED", "APP_START").
            details: Optionales Dict mit Metadaten (Dateiname, Zeilenanzahl
                     etc.). Niemals Dateiinhalte übergeben!
            tool: Optionaler Name des aufrufenden Tools.
        """
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "action": action,
            "tool": tool,
            "details": details or {},
            "hardware_id": _get_hardware_id_short(),
        }

        log_file = self._current_log_file()
        try:
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            log.debug("Audit: %s — %s", action, details)
        except OSError as exc:
            log.error("Audit-Log konnte nicht geschrieben werden: %s", exc)

    # ------------------------------------------------------------------
    def log_ki_aktion(
        self,
        tool: str,
        aktion: str,
        modell: str,
        input_laenge: int = 0,
        output_laenge: int = 0,
        erfolgreich: bool = True,
        agent_name: str = "",
        fehler: str = "",
        *,
        geblockt: bool = False,
        schutzschicht: str = "",
        scope_methode: str = "",
        injection_signale: int = 0,
        output_gefiltert: bool = False,
    ) -> None:
        """Loggt eine KI-Aktion als Audit-Eintrag (nur Metadaten).

        Pflicht nach EU KI-VO Art. 4 für lückenlose Nachvollziehbarkeit.
        Es werden ausschließlich Metadaten gespeichert — niemals Inhalte.
        Die zusätzlichen Schutzschicht-Felder dienen dem Sorgfaltsnachweis
        (DE/AT-Delikt, PLD-Beweislast) und enthalten ausschließlich
        Metadaten (keine Nutzer-/Off-Topic-Texte, DSGVO-Datenminimierung).

        Args:
            tool: Name des aufrufenden Tools (z.B. "ollama_chat").
            aktion: Art der Aktion (z.B. "CHAT_ANTWORT").
            modell: Verwendetes KI-Modell (z.B. "llama3.2").
            input_laenge: Zeichenanzahl des Inputs (kein Inhalt!).
            output_laenge: Zeichenanzahl des Outputs (kein Inhalt!).
            erfolgreich: True wenn Aktion fehlerfrei abgeschlossen.
            agent_name: Name des Agenten (nur bei Agent-Läufen).
            fehler: Gekürzte Fehlermeldung (max. 100 Zeichen, kein Inhalt).
            geblockt: True, wenn eine Schutzschicht die Anfrage abgewiesen hat.
            schutzschicht: Welche Schicht griff (z.B. "scope_gate").
            scope_methode: Entscheidungsmethode des Scope-Gates
                ("llm"/"heuristic"/"default").
            injection_signale: Anzahl erkannter Injection-Heuristik-Signale.
            output_gefiltert: True, wenn der Output-Filter etwas redigiert hat.
        """
        self.log_action(
            f"KI_{aktion.upper()}",
            {
                "tool": tool,
                "modell": modell,
                "input_zeichen": input_laenge,
                "output_zeichen": output_laenge,
                "erfolgreich": erfolgreich,
                "agent_name": agent_name,
                "fehler": fehler[:100] if fehler else "",
                "geblockt": geblockt,
                "schutzschicht": schutzschicht,
                "scope_methode": scope_methode,
                "injection_signale": injection_signale,
                "output_gefiltert": output_gefiltert,
                "human_review_required": True,
            },
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _current_log_file() -> Path:
        """Gibt den Pfad zur aktuellen monatlichen Audit-Log-Datei zurück.

        Returns:
            Pfad im Format ``~/.finlai/audit/audit_YYYYMM.log``.
        """
        month_str = datetime.now().strftime("%Y%m")
        return _AUDIT_DIR / f"audit_{month_str}.log"


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def _get_hardware_id_short() -> str:
    """Gibt eine kurze Hardware-ID zurück (gecacht nach erstem Aufruf).

    Verwendet get_hardware_fingerprint aus core.hardware_fingerprint und
    kürzt den 64-stelligen SHA-256-Hash auf 16 Zeichen — identische Länge
    wie das frühere LicenseManager.get_hardware_id.

    Returns:
        16-stellige hexadezimale Hardware-ID, oder 'unknown' bei Fehler.
    """
    try:
        from core.hardware_fingerprint import get_hardware_fingerprint  # noqa: PLC0415

        return get_hardware_fingerprint()[:16]
    except (ImportError, OSError, RuntimeError):
        import hashlib  # noqa: PLC0415
        import uuid  # noqa: PLC0415

        return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()[:16]
