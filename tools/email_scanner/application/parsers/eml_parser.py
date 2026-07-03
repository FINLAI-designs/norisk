"""
eml_parser — RFC-5322-Mails (.eml) parsen.

Verwendet ausschließlich ``email`` aus der Standardbibliothek mit der
``email.policy.default``-Policy. Die Policy stellt Modern-Header-Parsing
sicher (z. B. ``getaddresses`` für ``To``-Adressen).

Sicherheitsgarantien
--------------------
- HTML-Bodies werden **nur als Quelltext** extrahiert. Es erfolgt keine
  Verarbeitung von ``cid:``-Referenzen, keine Bildauflösung.
- Anhänge werden als Bytes zurückgegeben; der Aufrufer entscheidet,
  wohin die Daten fließen.
- Max-Größe ``MAX_EML_SIZE_BYTES`` verhindert Speicher-DoS.
- Verschachtelte ``message/rfc822``-Mails werden rekursiv bis zu
  ``MAX_NESTED_DEPTH`` Stufen geparst.
- Max-Attachments-pro-Mail ``MAX_ATTACHMENTS_PER_MAIL`` verhindert
  absichtlich aufgeblähte Mails.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from core.logger import get_logger
from tools.email_scanner.domain.models import Attachment, ParsedMail

_log = get_logger(__name__)

# Maximale Mail-Größe (Rohbytes). 100 MB entspricht den üblichen
# Provider-Limits und bleibt im Single-Pass-Speicher handhabbar.
MAX_EML_SIZE_BYTES: int = 100 * 1024 * 1024

# Maximale Attachments pro Mail — mehr deutet auf absichtliche
# Aufblähung hin.
MAX_ATTACHMENTS_PER_MAIL: int = 50

# Maximale Verschachtelungs-Tiefe bei ``message/rfc822``.
MAX_NESTED_DEPTH: int = 3


class EmlParseError(ValueError):
    """Wird geworfen, wenn die.eml-Datei nicht geparst werden konnte."""


def parse_eml(path: Path) -> ParsedMail:
    """Parst eine.eml-Datei.

    Args:
        path: Pfad zur.eml-Datei.

    Returns:
        ``ParsedMail`` mit extrahierten Metadaten und Attachments.

    Raises:
        FileNotFoundError: Wenn die Datei nicht existiert.
        EmlParseError: Bei Größenüberschreitung oder Parser-Fehlern.
    """
    if not path.is_file():
        raise FileNotFoundError(f".eml-Datei nicht gefunden: {path}")

    size = path.stat().st_size
    if size > MAX_EML_SIZE_BYTES:
        raise EmlParseError(
            f"EML überschreitet Größen-Limit ({size} > {MAX_EML_SIZE_BYTES})"
        )

    try:
        with path.open("rb") as fh:
            msg = BytesParser(policy=policy.default).parse(fh)
    except Exception as exc:  # noqa: BLE001 -- stdlib email-Parser kennt viele interne Fehler, als EmlParseError wrappen
        raise EmlParseError(f"EML-Parser-Fehler: {exc}") from exc

    return _extract_mail(msg, tiefe=0)


def _extract_mail(msg: EmailMessage, tiefe: int) -> ParsedMail:
    """Extrahiert Metadaten, Bodies und Attachments aus einer Mail.

    Args:
        msg: Geparste Mail (Top-Level oder rekursiv).
        tiefe: Aktuelle Verschachtelungs-Tiefe.

    Returns:
        ``ParsedMail``.
    """
    subject = str(msg.get("Subject", "")).strip()
    from_addr = str(msg.get("From", "")).strip()

    to_addrs = [
        addr for _name, addr in getaddresses(msg.get_all("To", []) or []) if addr
    ]

    date = None
    date_raw = msg.get("Date")
    if date_raw:
        try:
            date = parsedate_to_datetime(str(date_raw))
        except (TypeError, ValueError):
            date = None

    body_text, body_html = _extract_bodies(msg)
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


def _extract_bodies(msg: EmailMessage) -> tuple[str, str]:
    """Liefert Plaintext- und HTML-Body einer Mail.

    Args:
        msg: Geparste Mail.

    Returns:
        Tupel ``(plaintext, html_source)``. HTML wird als Quelltext
        weitergereicht, niemals gerendert.
    """
    text = ""
    html = ""
    try:
        text_part = msg.get_body(preferencelist=("plain",))
        if text_part is not None:
            text = text_part.get_content()
        html_part = msg.get_body(preferencelist=("html",))
        if html_part is not None:
            html = html_part.get_content()
    except (LookupError, KeyError):
        text = ""
        html = ""
    except Exception as exc:  # noqa: BLE001 -- Content-Codecs (Charset, base64 etc.) koennen unspezifizierte Errors werfen
        _log.debug("Body-Extraktion fehlgeschlagen: %s", exc)
    return text or "", html or ""


def _extract_attachments(
    msg: EmailMessage, tiefe: int
) -> tuple[list[Attachment], list[ParsedMail]]:
    """Extrahiert alle Anhänge und rekursiv verschachtelte Mails.

    Inline-Parts werden ignoriert (sonst würden ``cid:``-Grafiken als
    Attachments gemeldet, was für den Risk-Report irreführend ist).

    Args:
        msg: Geparste Mail.
        tiefe: Aktuelle Rekursions-Tiefe.

    Returns:
        Tupel ``(attachments, nested_parsed_mails)``.
    """
    attachments: list[Attachment] = []
    nested: list[ParsedMail] = []

    for part in msg.iter_attachments():
        if len(attachments) + len(nested) >= MAX_ATTACHMENTS_PER_MAIL:
            _log.warning(
                "Max-Attachments-Limit erreicht (%d)", MAX_ATTACHMENTS_PER_MAIL
            )
            break

        content_type = part.get_content_type()
        if content_type == "message/rfc822":
            if tiefe + 1 > MAX_NESTED_DEPTH:
                _log.debug("Max-Nested-Depth erreicht, überspringe inline mail")
                continue
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else payload
            if isinstance(inner, EmailMessage):
                nested.append(_extract_mail(inner, tiefe=tiefe + 1))
            continue

        filename = part.get_filename() or ""
        try:
            data = part.get_payload(decode=True) or b""
        except (ValueError, AttributeError, LookupError) as exc:
            _log.debug("Attachment-Payload nicht decodierbar: %s", exc)
            data = b""
        if not isinstance(data, bytes):
            data = bytes(data)

        attachments.append(
            Attachment.from_bytes(
                filename=filename,
                content_type=content_type,
                data=data,
            )
        )

    return attachments, nested
