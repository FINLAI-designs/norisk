"""network_monitor.application.conversation_service — Wer-mit-Wem Phase 5).

Schmale Use-Case-Schicht über der Verbindungs-Historie: liefert die zu
(Prozess, Ziel-IP)-Konversationen aggregierten Socket-Snapshots. Optional reichert
sie pro Konversation das **ETW-Byte-Volumen** (Gesendet/Empfangen) aus den
Per-Flow-Daten an (``ProcessTrafficRepository``) — das ist nur mit laufendem
elevated Collector befüllt; ohne ETW bleiben die Bytes 0. Kein Capture.

Schichtzugehörigkeit: ``application/`` (hält den ``data/``-Import in dieser Schicht).

Author: Patrick Riederich
Version: 1.1 — ETW-Byte-Anreicherung)
"""

from __future__ import annotations

import time
from dataclasses import replace

from core.logger import get_logger
from tools.network_monitor.domain.interfaces import (
    IConnectionRepository,
    IProcessTrafficRepository,
)
from tools.network_monitor.domain.models import Conversation

_log = get_logger(__name__)


class ConversationService:
    """Aggregiert die Verbindungs-Historie zu Konversationen (Pro-Feature)."""

    def __init__(
        self,
        repository: IConnectionRepository | None = None,
        traffic_repository: IProcessTrafficRepository | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            repository: Connection-History-Repository. ``None`` konstruiert das echte
                SQLCipher-Repo (benötigt ``KeyManager``); Tests injizieren ein Fake.
            traffic_repository: Optionales Per-Flow-Repo für die Byte-Anreicherung.
                ``None`` = keine Bytes (Connection-History-only). Die Factory reicht
                hier das echte ``ProcessTrafficRepository`` durch.
        """
        if repository is None:
            from tools.network_monitor.data.connection_repository import (  # noqa: PLC0415
                ConnectionHistoryRepository,
            )

            repository = ConnectionHistoryRepository()
        self._repo = repository
        self._traffic_repo = traffic_repository

    def aggregate(self, hours: int = 24) -> list[Conversation]:
        """Liefert die (Prozess, Ziel-IP)-Konversationen der letzten ``hours`` Stunden.

        Reichert — falls ein Traffic-Repo vorhanden ist — pro Konversation die
        gesendeten/empfangenen Bytes aus den ETW-Flow-Daten an (fail-soft: bei
        Fehler oder ohne ETW bleiben die Bytes 0).
        """
        conversations = self._repo.aggregate_conversations(hours)
        if self._traffic_repo is None:
            return conversations
        bytes_by_key = self._load_bytes(hours)
        if not bytes_by_key:
            return conversations
        return [
            replace(
                conv,
                bytes_sent=bytes_by_key.get((conv.process_name, conv.remote_ip), (0, 0))[0],
                bytes_recv=bytes_by_key.get((conv.process_name, conv.remote_ip), (0, 0))[1],
            )
            for conv in conversations
        ]

    def _load_bytes(self, hours: int) -> dict[tuple[str, str], tuple[int, int]]:
        """Summiert ETW-Bytes je (Prozess, Ziel-IP) über alle PIDs (fail-soft)."""
        cutoff = time.time() - (hours * 3600)
        try:
            rows = self._traffic_repo.traffic_per_remote_ip_since(cutoff)
        except Exception as exc:  # noqa: BLE001 — DB-/Lesefehler nie hart
            _log.warning("Byte-Anreicherung fehlgeschlagen: %s", type(exc).__name__)
            return {}
        out: dict[tuple[str, str], tuple[int, int]] = {}
        for row in rows:
            key = (row.process_name, row.remote_ip)
            sent, recv = out.get(key, (0, 0))
            out[key] = (sent + row.bytes_sent, recv + row.bytes_recv)
        return out
