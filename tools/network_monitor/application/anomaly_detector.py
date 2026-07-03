"""network_monitor.application.anomaly_detector — Threshold-Alerts D).

Reine Regel-Logik (kein DB-/ETW-Zugriff): nimmt aggregierte Traffic-Daten
(Domain-Value-Objects) und liefert:class:`~tools.network_monitor.domain.models.Anomaly`.
Die Daten holt der:class:`AnomalyService` ueber das Repository-Interface.

Umgesetzte Regeln (Brain-Spec Phase 2):
  1. Volume-Spike — >1 GB Upload/Prozess in 1h (HIGH)
  2. Off-Hours — >100 MB Outbound/Prozess 22–07 Uhr (MEDIUM)
  4. Unknown-Path — Prozess aus %TEMP%/%APPDATA% >10 MB Outbound (HIGH);
     ``image_path`` kommt vom Kernel-Process-Provider.
  6. High-Volume-Single-IP — >10 GB an EINE externe IP/24h (HIGH)
  3. Game-CDN — ein DNS-Query-Name matcht eine Game-/Download-CDN-Domain
     (LOW); ``DnsRateAggregate.game_cdn`` wird vom DNS-Aggregator gesetzt.
  5. DNS-Tunneling — >1000 DNS-Queries/Min pro Prozess (HIGH).

Alle sechs Regeln aktiv (Datenquellen: Kernel-Network, Kernel-Process,
DNS-Client). Eingaben liefert der:class:`AnomalyService` ueber die Repositories.

Whitelist: ~20 vertrauenswuerdige Prozesse (Cloud-Sync, Update, Backup, AV)
unterdruecken die Byte-Volumen-Regeln (1/2/4/6) gegen False-Positives.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Final

from tools.network_monitor.domain.interfaces import (
    IDnsQueryRepository,
    IProcessTrafficRepository,
)
from tools.network_monitor.domain.models import (
    Anomaly,
    AnomalySeverity,
    AnomalyType,
    DnsRateAggregate,
    ProcessOutbound,
    RemoteIpTraffic,
)

# Schwellwerte (dezimal, vgl. Spec).
VOLUME_SPIKE_BYTES: Final[int] = 1_000_000_000  # 1 GB
OFFHOURS_BYTES: Final[int] = 100_000_000  # 100 MB
UNKNOWN_PATH_BYTES: Final[int] = 10_000_000  # 10 MB
SINGLE_IP_BYTES: Final[int] = 10_000_000_000  # 10 GB
#: DNS-Tunneling: >1000 Queries pro Prozess in einem 60s-Intervall (≈/Min).
DNS_QUERY_RATE_PER_MIN: Final[int] = 1000

_SECONDS_PER_HOUR: Final[int] = 3_600
_SECONDS_PER_DAY: Final[int] = 86_400

#: ~20 vertrauenswuerdige Prozesse (default-an, User-erweiterbar). Lowercase.
DEFAULT_TRUSTED_PROCESSES: Final[frozenset[str]] = frozenset(
    {
        "svchost.exe",
        "msmpeng.exe",
        "nissrv.exe",
        "mpdefendercoreservice.exe",
        "onedrive.exe",
        "dropbox.exe",
        "googledrivefs.exe",
        "nextcloud.exe",
        "wuauclt.exe",
        "usocoreworker.exe",
        "mousocoreworker.exe",
        "backgroundtransferhost.exe",
        "backgroundtaskhost.exe",
        "trustedinstaller.exe",
        "compattelrunner.exe",
        "smartscreen.exe",
        "veeamagent.exe",
        "backup.exe",
        "teams.exe",
        "ms-teams.exe",
    }
)

#: Pfad-Marker fuer Unknown-Path (case-insensitive Teilstrings).
_SUSPECT_PATH_MARKERS: Final[tuple[str, ...]] = ("\\temp\\", "\\appdata\\")


class AnomalyDetector:
    """Wendet die Threshold-Regeln auf aggregierte Traffic-Daten an."""

    def __init__(
        self,
        *,
        trusted_processes: frozenset[str] | set[str] | None = None,
    ) -> None:
        """Initialisiert den Detektor.

        Args:
            trusted_processes: Whitelist (Prozessnamen). Default:
:data:`DEFAULT_TRUSTED_PROCESSES`.
        """
        source = (
            trusted_processes
            if trusted_processes is not None
            else DEFAULT_TRUSTED_PROCESSES
        )
        self._trusted = frozenset(name.lower() for name in source)

    def _is_trusted(self, process_name: str) -> bool:
        return process_name.lower() in self._trusted

    @staticmethod
    def _is_external_ip(ip: str) -> bool:
        """True wenn ``ip`` eine oeffentliche (nicht private/lokale) Adresse ist."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )

    @staticmethod
    def _is_suspect_path(image_path: str) -> bool:
        if not image_path:
            return False
        low = image_path.lower()
        return any(marker in low for marker in _SUSPECT_PATH_MARKERS)

    # ------------------------------------------------------------------
    # Einzelregeln
    # ------------------------------------------------------------------

    def detect_volume_spike(
        self, outbound_1h: list[ProcessOutbound]
    ) -> list[Anomaly]:
        """Regel 1: >1 GB Upload pro Prozess in 1h."""
        return [
            Anomaly(
                anomaly_type=AnomalyType.VOLUME_SPIKE,
                severity=AnomalySeverity.HIGH,
                pid=p.pid,
                process_name=p.process_name,
                value_bytes=p.bytes_sent,
                threshold_bytes=VOLUME_SPIKE_BYTES,
            )
            for p in outbound_1h
            if p.bytes_sent > VOLUME_SPIKE_BYTES and not self._is_trusted(p.process_name)
        ]

    def detect_off_hours(
        self, offhours_outbound: list[ProcessOutbound]
    ) -> list[Anomaly]:
        """Regel 2: >100 MB Outbound pro Prozess in den Nacht-Stunden (22–07)."""
        return [
            Anomaly(
                anomaly_type=AnomalyType.OFF_HOURS,
                severity=AnomalySeverity.MEDIUM,
                pid=p.pid,
                process_name=p.process_name,
                value_bytes=p.bytes_sent,
                threshold_bytes=OFFHOURS_BYTES,
            )
            for p in offhours_outbound
            if p.bytes_sent > OFFHOURS_BYTES and not self._is_trusted(p.process_name)
        ]

    def detect_unknown_path(
        self, outbound_24h: list[ProcessOutbound]
    ) -> list[Anomaly]:
        """Regel 4: Prozess aus %TEMP%/%APPDATA% mit >10 MB Outbound."""
        return [
            Anomaly(
                anomaly_type=AnomalyType.UNKNOWN_PATH,
                severity=AnomalySeverity.HIGH,
                pid=p.pid,
                process_name=p.process_name,
                value_bytes=p.bytes_sent,
                threshold_bytes=UNKNOWN_PATH_BYTES,
                detail=p.image_path,
            )
            for p in outbound_24h
            if p.bytes_sent > UNKNOWN_PATH_BYTES
            and self._is_suspect_path(p.image_path)
            and not self._is_trusted(p.process_name)
        ]

    def detect_single_ip(
        self, per_ip_24h: list[RemoteIpTraffic]
    ) -> list[Anomaly]:
        """Regel 6: >10 GB an EINE externe IP in 24h."""
        return [
            Anomaly(
                anomaly_type=AnomalyType.SINGLE_IP,
                severity=AnomalySeverity.HIGH,
                pid=t.pid,
                process_name=t.process_name,
                value_bytes=t.bytes_sent,
                threshold_bytes=SINGLE_IP_BYTES,
                remote_ip=t.remote_ip,
            )
            for t in per_ip_24h
            if t.bytes_sent > SINGLE_IP_BYTES
            and self._is_external_ip(t.remote_ip)
            and not self._is_trusted(t.process_name)
        ]

    def detect_game_cdn(
        self, dns_rates: list[DnsRateAggregate]
    ) -> list[Anomaly]:
        """Regel 3: ein DNS-Query-Name matchte eine Game-/Download-CDN-Domain.

        Hostname-basiert (Spec) ueber die DNS-Daten — ``game_cdn`` wird vom
        DNS-Aggregator gegen:data:`game_cdn.GAME_CDN_DOMAINS` gesetzt.
        """
        return [
            Anomaly(
                anomaly_type=AnomalyType.GAME_CDN,
                severity=AnomalySeverity.LOW,
                pid=r.pid,
                process_name=r.process_name,
                value_bytes=0,
                threshold_bytes=0,
                detail=r.game_cdn,
            )
            for r in dns_rates
            if r.game_cdn
        ]

    def detect_dns_tunneling(
        self, dns_rates: list[DnsRateAggregate]
    ) -> list[Anomaly]:
        """Regel 5: >1000 DNS-Queries/Min pro Prozess (DGA-/Tunneling-Hinweis).

        Kern-Schwelle ist die Query-Rate; die Label-Laenge/-Entropie aus dem
        Aggregat wandern als Kontext in ``detail``.
        """
        out: list[Anomaly] = []
        for r in dns_rates:
            if r.peak_query_count <= DNS_QUERY_RATE_PER_MIN:
                continue
            if self._is_trusted(r.process_name):
                continue
            out.append(
                Anomaly(
                    anomaly_type=AnomalyType.DNS_TUNNELING,
                    severity=AnomalySeverity.HIGH,
                    pid=r.pid,
                    process_name=r.process_name,
                    value_bytes=r.peak_query_count,
                    threshold_bytes=DNS_QUERY_RATE_PER_MIN,
                    detail=(
                        f"{r.sample_query} (max-Label {r.max_label_len}, "
                        f"Entropie {r.max_label_entropy:.1f})"
                    ),
                )
            )
        return out

    # ------------------------------------------------------------------
    # Orchestrierung
    # ------------------------------------------------------------------

    def detect_all(
        self,
        *,
        outbound_1h: list[ProcessOutbound],
        offhours_outbound: list[ProcessOutbound],
        outbound_24h: list[ProcessOutbound],
        per_ip_24h: list[RemoteIpTraffic],
        dns_rates: list[DnsRateAggregate] | None = None,
    ) -> list[Anomaly]:
        """Wendet alle implementierten Regeln an und sammelt die Anomalien."""
        rates = dns_rates or []
        return [
            *self.detect_volume_spike(outbound_1h),
            *self.detect_off_hours(offhours_outbound),
            *self.detect_unknown_path(outbound_24h),
            *self.detect_single_ip(per_ip_24h),
            *self.detect_game_cdn(rates),
            *self.detect_dns_tunneling(rates),
        ]


class AnomalyService:
    """Verdrahtet Repository + Detektor: holt Aggregate, liefert Anomalien."""

    def __init__(
        self,
        repository: IProcessTrafficRepository,
        detector: AnomalyDetector | None = None,
        dns_repository: IDnsQueryRepository | None = None,
    ) -> None:
        self._repo = repository
        self._detector = detector if detector is not None else AnomalyDetector()
        self._dns_repo = dns_repository

    def detect(self, now: float | None = None) -> list[Anomaly]:
        """Berechnet die aktuellen Anomalien aus der Traffic-/DNS-History.

        Args:
            now: Optionaler Zeitstempel (Tests); Default ``time.time``.

        Returns:
            Liste erkannter Anomalien.
        """
        ts = now if now is not None else time.time()
        cutoff_1h = ts - _SECONDS_PER_HOUR
        cutoff_24h = ts - _SECONDS_PER_DAY
        dns_rates = (
            self._dns_repo.peak_rate_per_process(cutoff_24h)
            if self._dns_repo is not None
            else []
        )
        return self._detector.detect_all(
            outbound_1h=self._repo.outbound_per_process_since(cutoff_1h),
            offhours_outbound=self._repo.offhours_outbound_per_process(cutoff_24h),
            outbound_24h=self._repo.outbound_per_process_since(cutoff_24h),
            per_ip_24h=self._repo.traffic_per_remote_ip_since(cutoff_24h),
            dns_rates=dns_rates,
        )

    def detect_and_emit(
        self, now: float | None = None, emitter: object | None = None
    ) -> tuple[list[Anomaly], int]:
        """Detektiert Anomalien und speist sie als KI-Todos ein (Stop-Step E).

        Args:
            now: Optionaler Zeitstempel (Tests).
            emitter: Optionaler KiTodoEmitter (Tests); Default lazy-erzeugt.

        Returns:
            ``(anomalien, anzahl_emittierter_findings)``.
        """
        from tools.network_monitor.application.storytelling_adapter import (
            emit_anomalies,
        )

        anomalies = self.detect(now)
        emitted = emit_anomalies(anomalies, emitter)
        return anomalies, emitted
