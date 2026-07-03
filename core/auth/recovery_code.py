"""
recovery_code — Generierung und Verifikation von Wiederherstellungs-Codes.

Ein Recovery-Code ist ein 16-Zeichen-Schlüssel aus einem reduzierten
Base32-Zeichensatz (ohne die leicht verwechselbaren Zeichen ``0``, ``O``,
``1``, ``I``, ``L``, ``8``, ``B``). Formatiert wird er in vier Gruppen à
vier Zeichen, durch Bindestriche getrennt — z. B. ``HRC9-K2ZY-4FM7-XQDA``.

Die Entropie ergibt sich aus ``len(alphabet)**16`` bei 25 möglichen
Zeichen → ca. 74 Bit, was für Offline-Reset mehr als ausreichend ist.

Der Code wird dem Benutzer einmalig angezeigt und anschließend nur noch
als bcrypt-Hash (Cost-Factor 12) in ``users.json`` gespeichert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import secrets

import bcrypt

# Base32 ohne 0, O, 1, I, L, 8, B (sieben verwechselbare Zeichen entfernt).
# Startpunkt ist das RFC-4648-Base32-Alphabet; die sieben Ausschlüsse werden
# explizit entfernt, damit der Code bei einer Übertragung per Telefon oder
# per Hand minimal fehleranfällig bleibt.
_BASE32_FULL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_CONFUSABLES = set("OIL8B")  # 0/1 sind im Base32-Alphabet ohnehin nicht enthalten.
RECOVERY_ALPHABET = "".join(c for c in _BASE32_FULL if c not in _CONFUSABLES)

CODE_LENGTH = 16
GROUP_SIZE = 4
BCRYPT_COST = 12

_FORMAT_RE = re.compile(r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")


def generate_recovery_code() -> str:
    """Erzeugt einen neuen Recovery-Code im Format ``XXXX-XXXX-XXXX-XXXX``.

    Verwendet:class:`secrets.SystemRandom` für kryptographisch starke
    Zufallswerte.

    Returns:
        Formatierter 19-Zeichen-String (16 Code-Zeichen + 3 Bindestriche).
    """
    rng = secrets.SystemRandom()
    raw = "".join(rng.choice(RECOVERY_ALPHABET) for _ in range(CODE_LENGTH))
    groups = [raw[i : i + GROUP_SIZE] for i in range(0, CODE_LENGTH, GROUP_SIZE)]
    return "-".join(groups)


def normalize_recovery_code(code: str) -> str:
    """Normalisiert eine Nutzereingabe auf das Standard-Format.

    Leerzeichen werden entfernt, alles wird großgeschrieben. Fehlende
    Bindestriche werden nach je 4 Zeichen eingefügt. Häufige OCR-
    Verwechslungen (``O``→``0`` tritt im Alphabet nicht mehr auf, aber
    Kleinschreibung und Leerzeichen im Copy-Paste schon).

    Args:
        code: Rohe Nutzereingabe (beliebige Groß-/Kleinschreibung, mit/ohne
            Bindestriche).

    Returns:
        Normalisierter String — nicht zwingend gültig, nur einheitlich.
    """
    cleaned = re.sub(r"[\s\-_]", "", code).upper()
    if len(cleaned) != CODE_LENGTH:
        return cleaned
    groups = [cleaned[i : i + GROUP_SIZE] for i in range(0, CODE_LENGTH, GROUP_SIZE)]
    return "-".join(groups)


def is_valid_format(code: str) -> bool:
    """Prüft, ob ``code`` syntaktisch gültig ist (nur Format, nicht Hash)."""
    return bool(_FORMAT_RE.match(code))


def hash_recovery_code(code: str) -> str:
    """Hasht den (normalisierten) Klartextcode mit bcrypt Cost 12.

    Args:
        code: Normalisierter Recovery-Code.

    Returns:
        bcrypt-Hash als UTF-8-String (wie bei Passwörtern).
    """
    normalized = normalize_recovery_code(code)
    salt = bcrypt.gensalt(rounds=BCRYPT_COST)
    return bcrypt.hashpw(normalized.encode("utf-8"), salt).decode("utf-8")


def verify_recovery_code(code: str, stored_hash: str) -> bool:
    """Prüft einen Recovery-Code gegen einen gespeicherten Hash.

    Args:
        code: Nutzereingabe (beliebige Formatierung erlaubt — wird normalisiert).
        stored_hash: bcrypt-Hash aus ``users.json``.

    Returns:
        ``True`` wenn der Code zum Hash passt, sonst ``False``. Bei leerem
        Hash oder Format-Fehler wird ``False`` zurückgegeben (nie Exception).
    """
    if not stored_hash:
        return False
    normalized = normalize_recovery_code(code)
    if not is_valid_format(normalized):
        return False
    try:
        return bcrypt.checkpw(normalized.encode("utf-8"), stored_hash.encode("utf-8"))
    except ValueError:
        return False
