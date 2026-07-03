"""network_monitor.data.monitor_exporter — CSV-Export der Verbindungs-History.

Pro-Feature: schreibt die letzten 24h aus ``ConnectionHistoryRepository``
als CSV (UTF-8 mit BOM für Excel-Kompatibilität).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from core.logger import get_logger
from tools.network_monitor.domain.interfaces import IConnectionRepository

_CSV_HEADER = [
    "timestamp",
    "remote_ip",
    "remote_port",
    "local_port",
    "pid",
    "process_name",
    "status",
    "suspicious",
    "suspicious_reason",
]


def export_history_csv(
    repo: IConnectionRepository,
    target_path: Path,
    hours: int = 24,
) -> int:
    """Exportiert Verbindungshistorie als CSV.

    Args:
        repo: Geöffnetes Connection-History-Repository.
        target_path: Ziel-Pfad der CSV-Datei.
        hours: Zeitfenster in Stunden. Default 24.

    Returns:
        Anzahl geschriebener Zeilen (ohne Header).
    """
    log = get_logger(__name__)
    rows = repo.load_recent(hours)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # utf-8-sig schreibt BOM, damit Excel die CSV korrekt als UTF-8 öffnet.
    with target_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh, delimiter=";")
        writer.writerow(_CSV_HEADER)
        for ts, conn in rows:
            writer.writerow(
                [
                    datetime.fromtimestamp(ts).isoformat(timespec="seconds"),
                    conn.remote_ip,
                    conn.remote_port,
                    conn.local_port,
                    conn.pid,
                    conn.process_name,
                    conn.status,
                    "ja" if conn.suspicious else "nein",
                    conn.suspicious_reason,
                ]
            )
    log.info("CSV-Export: %d Zeilen → %s", len(rows), target_path)
    return len(rows)
