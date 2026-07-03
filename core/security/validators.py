"""
validators — Zentralisierte Eingabe-Validierung für FINLAI (S1).

Alle Validator-Funktionen folgen dem Prinzip:
  - Gültige Eingabe → gibt den (ggf. normalisierten) Wert zurück
  - Ungültige Eingabe → wirft ValueError mit verständlicher Meldung

Diese Funktionen sind die EINZIGE Quelle der Wahrheit für
Eingabe-Validierung in FINLAI. Keine eigenen Regex in
anderen Modulen — immer diese Funktionen verwenden.

Sicherheits-Garantien:
  - validate_uuid: verhindert Path-Traversal über Session-IDs
  - validate_model_name: verhindert Shell-Injection über Modellnamen
  - validate_url: verhindert SSRF über konfigurierbare URLs
  - validate_file_path: verhindert Directory-Traversal bei Dateioperationen
  - validate_lang_code: verhindert Injection über DeepL-Sprachcodes

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

from core.exceptions import ValidationError

# ---------------------------------------------------------------------------
# Kompilierte Muster (einmalig, thread-safe)
# ---------------------------------------------------------------------------

# Ollama-Modellnamen: alphanumerisch +:. _ -
MODEL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9:._-]{1,100}$")

# UUID v4 — exakte Prüfung inklusive version- und variant-Bits
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}"
    r"-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# DeepL-Sprachcodes: "DE", "EN-US", "ZH" usw.
LANG_CODE_PATTERN = re.compile(r"^[A-Z]{2}(-[A-Z]{2})?$")

# Glossar-IDs (DeepL verwendet UUID-Format)
GLOSSARY_ID_PATTERN = UUID_PATTERN

# Dateinamen ohne Pfad-Komponenten
FILENAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9\u00e4\u00f6\u00fc\u00c4\u00d6\u00dc\u00df._\- ]{1,255}$"
)

# Erlaubte Hosts für lokale Services (SSRF-Schutz)
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# ---------------------------------------------------------------------------
# Input-Normalisierung (Prompt-Injection-Schutz, Layer 1)
# ---------------------------------------------------------------------------
# Hintergrund: Unsichtbare Zeichen und Unicode-Tricks werden genutzt, um
# Prompt-Injection an Klassifikatoren und Filtern vorbeizuschmuggeln
# ("Character Smuggling", arXiv:2504.11168 — Emoji-/Unicode-Tag-Smuggling
# erreicht bis ~100 % gegen getestete Klassifikatoren). Deshalb MUSS die
# Normalisierung als ERSTE Stufe vor allen weiteren Filtern laufen — sonst
# sind diese wirkungslos. Die Funktion ist rein deterministisch und damit
# selbst nicht durch Prompt-Tricks umgehbar.

#: Zero-Width-/unsichtbare Layout-Zeichen (Smuggling, Wort-Splitting).
#: Als \\u-Escapes notiert — KEINE literalen unsichtbaren Zeichen im Quellcode
#: (sonst flaggt bandit B613 "Trojan Source", und cp1252-Konsolen brechen).
_ZERO_WIDTH_CHARS: frozenset[str] = frozenset(
    chr(_c)
    for _c in (
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x00AD,  # SOFT HYPHEN
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
    )
)

#: Bidirektionale Steuerzeichen (RLO/LRO-Spoofing, versteckte Reihenfolge).
_BIDI_CONTROL_CHARS: frozenset[str] = frozenset(
    chr(_c)
    for _c in (
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    )
)

#: Häufige homoglyphe Verwechsler (kyrillisch/griechisch → lateinisch).
#: Bewusst KLEIN gehalten (kein vollständiges Confusables-Mapping), um
#: legitime nicht-lateinische Inhalte nicht zu zerstören — neutralisiert
#: Spoofing (z. B. kyrillisches A statt lateinischem a). \\u-Escapes statt
#: literaler Nicht-ASCII-Zeichen (cp1252-/Linter-Robustheit).
_HOMOGLYPH_MAP: dict[str, str] = {
    chr(0x0430): "a",  # CYRILLIC SMALL LETTER A
    chr(0x0435): "e",  # CYRILLIC SMALL LETTER IE
    chr(0x043E): "o",  # CYRILLIC SMALL LETTER O
    chr(0x0440): "p",  # CYRILLIC SMALL LETTER ER
    chr(0x0441): "c",  # CYRILLIC SMALL LETTER ES
    chr(0x0445): "x",  # CYRILLIC SMALL LETTER HA
    chr(0x0443): "y",  # CYRILLIC SMALL LETTER U
    chr(0x0456): "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    chr(0x0501): "d",  # CYRILLIC SMALL LETTER KOMI DE
    chr(0x03BF): "o",  # GREEK SMALL LETTER OMICRON
    chr(0x0391): "A",  # GREEK CAPITAL LETTER ALPHA
    chr(0x0410): "A",  # CYRILLIC CAPITAL LETTER A
    chr(0x0415): "E",  # CYRILLIC CAPITAL LETTER IE
    chr(0x041E): "O",  # CYRILLIC CAPITAL LETTER O
    chr(0x0420): "P",  # CYRILLIC CAPITAL LETTER ER
    chr(0x0421): "C",  # CYRILLIC CAPITAL LETTER ES
}

#: Maximale Eingabelänge (Zeichen) gegen Token-/Kontext-DoS und Many-Shot.
MAX_USER_INPUT_CHARS = 16_000


# ---------------------------------------------------------------------------
# Öffentliche Validator-Funktionen
# ---------------------------------------------------------------------------


def validate_model_name(name: str) -> str:
    """Validiert einen Ollama-Modellnamen gegen die Allowlist.

    Erlaubte Zeichen: [a-zA-Z0-9:._-], max. 100 Zeichen.
    Verhindert Shell-Injection und API-Parameter-Manipulation.

    Args:
        name: Zu validierender Modellname.

    Returns:
        Unveränderter Modellname wenn gültig.

    Raises:
        ValueError: Bei ungültigem Format.
    """
    if not isinstance(name, str) or not MODEL_NAME_PATTERN.match(name):
        raise ValidationError(
            f"Ungültiger Modellname {name!r}. "
            "Nur [a-zA-Z0-9:._-] erlaubt, max. 100 Zeichen."
        )
    return name


def validate_uuid(value: str, field: str = "ID") -> str:
    """Validiert eine UUID v4 gegen das exakte Muster.

    Verhindert Path-Traversal-Angriffe über manipulierte IDs
    (z. B. ``../../etc/passwd`` als Session-ID).

    Args:
        value: Zu prüfende UUID.
        field: Feldname für die Fehlermeldung.

    Returns:
        UUID in Kleinschreibung wenn gültig.

    Raises:
        ValueError: Bei ungültigem UUID-Format.
    """
    if not isinstance(value, str) or not UUID_PATTERN.match(value.lower()):
        raise ValidationError(f"Ungültige {field} {value!r}. Erwartet: UUID v4-Format.")
    return value.lower()


def validate_lang_code(code: str) -> str:
    """Validiert einen DeepL-Sprachcode (ISO 639-1 ± Regionalcode).

    Beispiele: "DE", "EN-US", "ZH", "PT-BR".

    Args:
        code: Zu prüfender Sprachcode.

    Returns:
        Sprachcode in Großschreibung wenn gültig.

    Raises:
        ValueError: Bei ungültigem Format.
    """
    upper = code.upper().strip() if isinstance(code, str) else ""
    if not upper or not LANG_CODE_PATTERN.match(upper):
        raise ValidationError(
            f"Ungültiger Sprachcode {code!r}. Format: 'DE', 'EN-US', 'ZH' usw."
        )
    return upper


def validate_url(url: str, allow_non_localhost: bool = False) -> str:
    """Validiert eine URL und schützt vor SSRF-Angriffen.

    Für lokale Services (Ollama) ist standardmäßig nur localhost erlaubt.
    Für externe Services (DeepL API) muss ``allow_non_localhost=True``
    explizit gesetzt werden.

    Args:
        url: Zu prüfende URL.
        allow_non_localhost: True erlaubt externe Hosts (z. B. DeepL API).

    Returns:
        URL ohne abschließenden Slash wenn gültig.

    Raises:
        ValueError: Bei ungültigem Schema oder SSRF-Risiko.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("URL darf nicht leer sein.")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            f"Ungültiges URL-Schema {parsed.scheme!r}. Nur 'http' und 'https' erlaubt."
        )

    host = (parsed.hostname or "").lower()
    if not host:
        raise ValidationError("URL enthält keinen gültigen Host.")

    is_local = host in _LOCAL_HOSTS
    if not is_local and not allow_non_localhost:
        raise ValidationError(
            f"SSRF-Schutz: Host '{host}' ist nicht localhost. "
            "Nur localhost/127.0.0.1 erlaubt für lokale Services."
        )

    return url.rstrip("/")


def validate_file_path(
    path: str | Path,
    allowed_extensions: list[str],
) -> str:
    """Validiert einen Dateipfad und verhindert Path-Traversal.

    Prüft:
    - Keine '..'-Komponenten im Pfad
    - Dateiendung in der Allowlist

    Args:
        path: Zu prüfender Dateipfad.
        allowed_extensions: Erlaubte Endungen ohne Punkt (z. B. ["pdf", "docx"]).

    Returns:
        Absolut aufgelöster Pfad als String.

    Raises:
        ValueError: Bei Path-Traversal oder unerlaubter Dateiendung.
    """
    raw = Path(path)

    # Kein '..' in Pfadteilen (Path-Traversal-Schutz)
    if ".." in raw.parts:
        raise ValidationError(
            f"Path-Traversal erkannt: '..' nicht erlaubt in Pfad {str(path)!r}."
        )

    resolved = raw.resolve()
    suffix = resolved.suffix.lower().lstrip(".")

    if allowed_extensions and suffix not in [e.lower() for e in allowed_extensions]:
        raise ValidationError(
            f"Ungültige Dateiendung {suffix!r}. Erlaubt: {allowed_extensions}"
        )

    return str(resolved)


def _is_tag_char(ch: str) -> bool:
    """True für Unicode-Tag-Zeichen (U+E0000–U+E007F).

    Dieser Block kann Text unsichtbar mit Instruktionen "taggen" und wird
    für Prompt-Injection-Smuggling missbraucht. Er hat keine legitime
    Verwendung in Nutzer-Eingaben.
    """
    return "\U000e0000" <= ch <= "\U000e007f"


def _is_variation_selector(ch: str) -> bool:
    """True für Variation Selectors (U+FE00–U+FE0F, U+E0100–U+E01EF).

    Werden u. a. für Emoji-Smuggling genutzt, um Payloads unsichtbar an
    Trägerzeichen zu hängen.
    """
    return (0xFE00 <= ord(ch) <= 0xFE0F) or (0xE0100 <= ord(ch) <= 0xE01EF)


def normalize_user_input(text: str, *, fold_homoglyphs: bool = True) -> str:
    """Normalisiert Nutzer-Eingaben gegen Prompt-Injection-Verschleierung.

    Muss als ERSTE Verarbeitungsstufe (Layer 1) vor allen weiteren Filtern
    und vor dem LLM-Aufruf laufen — sonst sind nachgelagerte Filter durch
    Character-Smuggling umgehbar (arXiv:2504.11168).

    Arbeitsschritte (in dieser Reihenfolge):
        1. Unicode-NFKC-Normalisierung (Kompatibilitäts-Faltung, z. B.
           Voll-/Halbbreite, Ligaturen, hochgestellte Ziffern).
        2. Entfernen unsichtbarer/steuernder Zeichen: Zero-Width,
           Bidi-Steuerzeichen, Unicode-Tag-Block, Variation Selectors,
           sonstige ``Cf``/``Cc``-Zeichen (außer ``\\n``, ``\\t``, ``\\r``).
        3. Optionales Falten häufiger homoglypher Verwechsler
           (kyrillisch/griechisch → lateinisch), um Spoofing zu neutralisieren.

    Args:
        text: Roh-Eingabe des Nutzers.
        fold_homoglyphs: Wenn True, werden bekannte homoglyphe Zeichen auf
            ihr lateinisches Pendant gefaltet. Default True. Auf False
            setzen, wenn legitime nicht-lateinische Inhalte erhalten bleiben
            müssen.

    Returns:
        Die bereinigte Eingabe. Bei leerer/ungültiger Eingabe ein leerer
        String.
    """
    if not isinstance(text, str) or not text:
        return ""

    # 1. NFKC — entfaltet Kompatibilitäts-Varianten zu kanonischer Form.
    text = unicodedata.normalize("NFKC", text)

    # 2. Unsichtbare/steuernde Zeichen entfernen.
    cleaned: list[str] = []
    for ch in text:
        if ch in ("\n", "\t", "\r"):
            cleaned.append(ch)
            continue
        if ch in _ZERO_WIDTH_CHARS or ch in _BIDI_CONTROL_CHARS:
            continue
        if _is_tag_char(ch) or _is_variation_selector(ch):
            continue
        # Übrige Format-/Steuerzeichen (Cf, Cc) verwerfen — kein legitimer
        # Nutzen in Freitext-Eingaben, aber Smuggling-Träger.
        if unicodedata.category(ch) in ("Cf", "Cc"):
            continue
        cleaned.append(ch)
    text = "".join(cleaned)

    # 3. Homoglyphe Verwechsler falten (Spoofing neutralisieren).
    if fold_homoglyphs and text:
        text = text.translate(str.maketrans(_HOMOGLYPH_MAP))

    return text
