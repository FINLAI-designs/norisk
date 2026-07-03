"""
msg_parser — Outlook.msg-Dateien parsen.

Verwendet ``extract-msg`` als Compound-File-Parser. ``extract-msg`` ist
für malformed MSGs bekannt, daher kapseln wir jeden Zugriff in einem
defensiven Handler und liefern ``MsgParseError`` statt Stacktrace.

Sicherheitsgarantien
--------------------
- HTML-Body wird nur als Quelltext zurückgegeben.
- Keine Ausführung von ``SignedAttachment``-Inhalten — wir lesen nur
  ``data``-Bytes.
- ``MAX_MSG_SIZE_BYTES`` deckelt die Dateigröße.
- ``MAX_ATTACHMENTS_PER_MAIL`` verhindert absichtlich aufgeblähte Mails.
- ``MAX_NESTED_DEPTH`` begrenzt verschachtelte Mails (``msg-embedded``).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from core.logger import get_logger
from tools.email_scanner.application.parsers.eml_parser import (
    MAX_ATTACHMENTS_PER_MAIL,
    MAX_NESTED_DEPTH,
)
from tools.email_scanner.domain.models import Attachment, ParsedMail

_log = get_logger(__name__)

MAX_MSG_SIZE_BYTES: int = 100 * 1024 * 1024


class MsgParseError(ValueError):
    """Wird geworfen, wenn die.msg-Datei nicht geparst werden konnte."""


def parse_msg(path: Path) -> ParsedMail:
    """Parst eine Outlook.msg-Datei.

    Args:
        path: Pfad zur.msg-Datei.

    Returns:
        ``ParsedMail`` mit Metadaten und Attachments.

    Raises:
        FileNotFoundError: Wenn die Datei nicht existiert.
        MsgParseError: Bei Größenüberschreitung oder Parser-Fehlern.
    """
    if not path.is_file():
        raise FileNotFoundError(f".msg-Datei nicht gefunden: {path}")

    size = path.stat().st_size
    if size > MAX_MSG_SIZE_BYTES:
        raise MsgParseError(
            f"MSG überschreitet Größen-Limit ({size} > {MAX_MSG_SIZE_BYTES})"
        )

    import extract_msg  # noqa: PLC0415 — nur laden wenn Tool aktiv ist

    try:
        with extract_msg.openMsg(str(path)) as msg:
            return _extract_mail(msg, tiefe=0)
    except MsgParseError:
        raise
    except Exception as exc:  # noqa: BLE001 — extract-msg wirft diverse Fehler
        raise MsgParseError(f"MSG-Parser-Fehler: {exc}") from exc


def _extract_mail(msg: Any, tiefe: int) -> ParsedMail:
    """Extrahiert Metadaten und Anhänge aus einer extract-msg-Message.

    Args:
        msg: ``extract_msg.Message``-Instanz.
        tiefe: Aktuelle Verschachtelungs-Tiefe.

    Returns:
        ``ParsedMail``.
    """
    subject = _safe_str(getattr(msg, "subject", ""))
    from_addr = _safe_str(getattr(msg, "sender", ""))
    to_raw = _safe_str(getattr(msg, "to", ""))
    to_addrs = [addr.strip() for addr in to_raw.split(";") if addr.strip()]

    date = getattr(msg, "date", None)
    if not isinstance(date, datetime):
        date = None

    body_text = _safe_str(getattr(msg, "body", ""))
    body_html = _html_quelltext(msg)

    attachments, nested = _extract_attachments(msg, tiefe)

    return ParsedMail(
        subject=subject,
        from_addr=from_addr,
        to_addrs=to_addrs,
        date=date,
        body_text=body_text,
        body_html_source=body_html,
        attachments=attachments,
        nested_mails=nested,
        tiefe=tiefe,
    )


def _html_quelltext(msg: Any) -> str:
    """Gibt den HTML-Body als Quelltext zurück — niemals rendern."""
    raw = getattr(msg, "htmlBody", None)
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace")
    return str(raw)


def _safe_str(value: Any) -> str:
    """Wandelt None/Bytes/Str robust in einen String."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _extract_attachments(
    msg: Any, tiefe: int
) -> tuple[list[Attachment], list[ParsedMail]]:
    """Liest Anhänge und rekursiv verschachtelte.msg-Anhänge."""
    attachments: list[Attachment] = []
    nested: list[ParsedMail] = []

    for raw in getattr(msg, "attachments", []) or []:
        if len(attachments) + len(nested) >= MAX_ATTACHMENTS_PER_MAIL:
            _log.warning(
                "Max-Attachments-Limit erreicht (%d)", MAX_ATTACHMENTS_PER_MAIL
            )
            break

        # extract-msg kennzeichnet eingebettete Mails via
        # ``att.type == AttachmentType.MSG`` (Enum). Statt darauf
        # zuzugreifen prüfen wir, ob ``data`` ein Message-Objekt ist —
        # das ist robust gegen API-Wechsel.
        data = getattr(raw, "data", None)
        if hasattr(data, "attachments") and hasattr(data, "subject"):
            if tiefe + 1 > MAX_NESTED_DEPTH:
                _log.debug("Max-Nested-Depth erreicht, überspringe embedded .msg")
                continue
            nested.append(_extract_mail(data, tiefe=tiefe + 1))
            continue

        filename = (
            _safe_str(getattr(raw, "longFilename", ""))
            or _safe_str(getattr(raw, "shortFilename", ""))
            or ""
        )
        mimetype = _safe_str(getattr(raw, "mimetype", "")) or (
            "application/octet-stream"
        )
        blob = data if isinstance(data, bytes) else b""

        attachments.append(
            Attachment.from_bytes(
                filename=filename,
                content_type=mimetype,
                data=blob,
            )
        )

    return attachments, nested
