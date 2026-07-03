"""
scan_service — Orchestriert Parser + Router für E-Mail-Scans.

Der Service ist GUI-frei, damit er in Tests ohne Qt läuft. Er
öffnet.eml/.msg-Dateien, lässt die Parser einen ``ParsedMail``
liefern, schickt jedes Attachment durch den ``AttachmentRouter`` und
aggregiert die Einzel-Reports zu einem ``MailReport``.

Fehler (unlesbare Mail, Größen-Limit überschritten, kaputter MSG-Container)
werden **nicht** als Exception nach oben durchgereicht — sie landen im
``MailReport.fehler``-Feld. So bleibt eine Batch-Verarbeitung mit
``scan_many`` stabil, auch wenn eine einzelne Mail scheitert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path

from core.logger import get_logger
from tools.email_scanner.application.attachment_router import AttachmentRouter
from tools.email_scanner.application.parsers.eml_parser import (
    EmlParseError,
    parse_eml,
)
from tools.email_scanner.application.parsers.msg_parser import (
    MsgParseError,
    parse_msg,
)
from tools.email_scanner.data.repository import EmailScannerRepository
from tools.email_scanner.domain.models import (
    AttachmentReport,
    MailReport,
    MailScanStatus,
    ParsedMail,
    aggregate_status,
)

_log = get_logger(__name__)


class EmailScannerService:
    """Koordiniert Parser und Router für.eml/.msg-Dateien."""

    def __init__(
        self,
        router: AttachmentRouter | None = None,
        repository: EmailScannerRepository | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            router: Optionaler Attachment-Router (für Tests injizierbar).
            repository: Optionales Repository fuer Persistenz (Reports +
                Quarantaene). (RUN2-GUI): Service kapselt das
                Repository, damit die GUI keinen ``data/``-Direktimport
                mehr braucht. ``None`` ist erlaubt — Persistenz-Aufrufe
                liefern dann ``RuntimeError``.
        """
        self._router = router or AttachmentRouter()
        self._repository = repository

    def scan(self, path: Path) -> MailReport:
        """Scannt eine einzelne.eml- oder.msg-Datei.

        Args:
            path: Pfad zur Mail-Datei.

        Returns:
            ``MailReport`` mit aggregiertem Status. Fehler erzeugen
            einen Report mit Status WARN und gefülltem ``fehler``-Feld.
        """
        start = time.perf_counter()
        try:
            mail = self._parse(path)
        except FileNotFoundError as exc:
            return _fehler_report(path, f"Datei nicht gefunden: {exc}")
        except (EmlParseError, MsgParseError) as exc:
            return _fehler_report(path, str(exc))
        except Exception as exc:  # noqa: BLE001 — Parser dritter Stufe
            _log.warning("Unerwarteter Parser-Fehler bei %s: %s", path, exc)
            return _fehler_report(path, f"Parser-Fehler: {exc}")

        top_reports = self._route_attachments(mail)
        nested_reports = self._scan_nested(mail, path)
        status = _combine_status(top_reports, nested_reports)
        risk_score = _max_risk(top_reports, nested_reports)

        duration_ms = (time.perf_counter() - start) * 1000
        _log.info(
            "Mail %s | status=%s, score=%d, attachments=%d, nested=%d, %.1f ms",
            path.name,
            status.value,
            risk_score,
            len(top_reports),
            len(nested_reports),
            duration_ms,
        )
        return MailReport(
            source_path=str(path),
            mail=mail,
            attachment_reports=top_reports,
            nested_reports=nested_reports,
            status=status,
            risk_score=risk_score,
        )

    def scan_many(self, paths: Iterable[Path]) -> list[MailReport]:
        """Batch-Variante von ``scan``.

        Args:
            paths: Iterable über Mail-Dateien.

        Returns:
            Liste der Reports in Eingangsreihenfolge.
        """
        return [self.scan(p) for p in paths]

    # ------------------------------------------------------------------
    # Persistenz-Wrapper RUN2-GUI)
    # ------------------------------------------------------------------

    def speichere_report(self, report: MailReport) -> int:
        """Persistiert einen Mail-Report (Service-Wrapper um Repository).

        Args:
            report: Der zu speichernde Report.

        Returns:
            Datensatz-ID des gespeicherten Reports.

        Raises:
            RuntimeError: Wenn kein Repository injiziert wurde.
        """
        if self._repository is None:
            raise RuntimeError(
                "EmailScannerService ohne Repository instanziiert — "
                "speichere_report nicht verfuegbar."
            )
        return self._repository.speichere_report(report)

    def quarantaene_speichern(self, attachment_report: AttachmentReport) -> str:
        """Sichert ein Attachment in die Quarantaene.

        Args:
            attachment_report: Der zu quarantierende Anhang-Report.

        Returns:
            SHA-256-Hash des gespeicherten Blobs.

        Raises:
            RuntimeError: Wenn kein Repository injiziert wurde.
        """
        if self._repository is None:
            raise RuntimeError(
                "EmailScannerService ohne Repository instanziiert — "
                "quarantaene_speichern nicht verfuegbar."
            )
        return self._repository.quarantaene_speichern(attachment_report)

    def _parse(self, path: Path) -> ParsedMail:
        """Wählt den passenden Parser anhand der Datei-Endung."""
        suffix = path.suffix.lower()
        if suffix == ".msg":
            return parse_msg(path)
        if suffix == ".eml":
            return parse_eml(path)
        # Kein explizites Format → als.eml versuchen (RFC-5322).
        return parse_eml(path)

    def _route_attachments(self, mail: ParsedMail) -> list[AttachmentReport]:
        """Routet alle Top-Level-Anhänge durch den Router."""
        return [self._router.route(att) for att in mail.attachments]

    def _scan_nested(self, mail: ParsedMail, source_path: Path) -> list[MailReport]:
        """Scant rekursiv verschachtelte Mails (message/rfc822, embedded.msg)."""
        reports: list[MailReport] = []
        for nested in mail.nested_mails:
            nested_att = [self._router.route(a) for a in nested.attachments]
            deeper = self._scan_nested(nested, source_path)
            status = _combine_status(nested_att, deeper)
            reports.append(
                MailReport(
                    source_path=str(source_path),
                    mail=nested,
                    attachment_reports=nested_att,
                    nested_reports=deeper,
                    status=status,
                    risk_score=_max_risk(nested_att, deeper),
                )
            )
        return reports


def _fehler_report(path: Path, msg: str) -> MailReport:
    """Erzeugt einen Error-Report mit Status WARN."""
    return MailReport(
        source_path=str(path),
        mail=None,
        status=MailScanStatus.WARN,
        fehler=msg,
    )


def _combine_status(
    attachments: list[AttachmentReport],
    nested: list[MailReport],
) -> MailScanStatus:
    """Bildet den schwersten Status über Anhänge + verschachtelte Mails."""
    top = aggregate_status(attachments)
    nested_levels = [r.status for r in nested]
    if top is MailScanStatus.BLOCK or MailScanStatus.BLOCK in nested_levels:
        return MailScanStatus.BLOCK
    if top is MailScanStatus.WARN or MailScanStatus.WARN in nested_levels:
        return MailScanStatus.WARN
    return MailScanStatus.SAFE


def _max_risk(
    attachments: list[AttachmentReport],
    nested: list[MailReport],
) -> int:
    """Maximaler Risk-Score über alle Reports."""
    scores = [r.validation.risk_score for r in attachments]
    scores.extend(r.risk_score for r in nested)
    return max(scores, default=0)
