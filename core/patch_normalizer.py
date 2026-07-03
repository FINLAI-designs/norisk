"""
patch_normalizer — Software-Namen + Versionen fuer Policy-Match aufbereiten.

Verbesserung 2 (PM-1.1a Nachbesserung). Vorbedingung fuer
:mod:`core.patch_policy` (PM-1.3) — ohne saubere Normalisierung
matcht die Policy-DB falsch (z.B. "Microsoft Edge WebView2 Runtime"
wird als "Microsoft Edge"-Browser erkannt).

Hauptfunktionen:

*:func:`normalize_name` — Anzeigename → kanonisches lowercase
  ohne Versionen, Architektur-Suffix und Noise-Terme.
*:func:`normalize_version` — Versions-String fuer Vergleiche.
*:func:`is_runtime_noise` — Erkennt Redistributable/Runtime-Pakete.
*:func:`find_policy_key` — Bester Policy-Key-Match mit
  Confidence-Score; Hard-Overrides + Longest-Match.

Matching-Strategie::

    User-Override > Hard-Override > Exakter Match > Laengster Substring
"""

from __future__ import annotations

import re

# Noise-Terme: Wort-Tokens, die im Software-Namen kein semantischer
# Kern sind und vor dem Policy-Match entfernt werden. Reihenfolge:
# laengste/spezifischste Phrasen zuerst, damit z.B. "service pack"
# vor moeglichen Konflikten greift.
# Semantik-Tokens — Worte, die der Software-Variante zwar zugeordnet
# sind ("Runtime" vs "SDK" vs "Server"), fuer das **Policy-Matching**
# aber irrelevant sind. ``normalize_name`` LAESST sie stehen
# (Anzeige-Wert), ``normalize_for_matching`` entfernt sie (Lookup-Wert).
# So landen z.B. ".NET SDK" und ".NET Runtime" im selben Policy-Key.
_SEMANTIC_TOKENS: tuple[str, ...] = (
    "runtime",
    "sdk",
    "jdk",
    "jre",
    "server",
    "client",
    "plugin",
    "extension",
    "driver",
)


_NOISE_TERMS: tuple[str, ...] = (
    "service pack",
    "redistributable",
    "professional",
    "standalone",
    "enterprise",
    "application",
    "for windows",
    "environment",
    "community",
    "installer",
    "portable",
    "software",
    "launcher",
    "package",
    "runtime",
    "edition",
    "desktop",
    "for pc",
    "update",
    "64-bit",
    "32-bit",
    "setup",
    "sp1",
    "sp2",
    "- windows",
)

# Versions-Patterns (in Reihenfolge gematcht):
# - " v?1.2.3.4" / " v?1.2.3" / " v?1.2"
# - " 2015-2022" Microsoft-Style Jahresbereiche
# - " 2024" einzelne 4-stellige Jahresangabe
# - " v123" einzelne v-Versions-Nummer
_VERSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\s+v?\d+(?:\.\d+){1,3}\b"),
    re.compile(r"\s+v?\d+\.\d+\b"),
    re.compile(r"\s+\d{4}-\d{4}\b"),
    re.compile(r"\s+\d{4}\b"),
    re.compile(r"\s+v\d+\b"),
)

# Klammer-Block mit fuehrendem Whitespace: " (x64)", " (de en)" etc.
# Klammer ohne Leerzeichen davor (z.B. ``Java(TM)``) bleibt unangetastet —
# bewusst konservativ.
_PAREN_PATTERN: re.Pattern[str] = re.compile(r"\s+\([^)]*\)")


def normalize_name(raw: str) -> str:
    """Bereinigt einen Software-Anzeigenamen fuer das Policy-Matching.

    Reihenfolge:

    1. ``lower``
    2. Whitespace + Klammer-Block entfernen (``" (x64)"``,
       ``" (de en)"``)
    3. Versionsnummern entfernen (``"3.12.0"``, ``"2015-2022"``,
       ``"v2.1"``)
    4. Noise-Terme entfernen (``"runtime"``, ``"installer"``, …)
    5. Mehrfach-Whitespace → einzelnes Leerzeichen
    6. ``strip``

    Beispiele::

        normalize_name("Python 3.12.0 (64-bit)")
            -> "python"
        normalize_name(
            "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
) -> "microsoft visual c++"
        normalize_name("Google Chrome")
            -> "google chrome"
        normalize_name("Mozilla Firefox (x64 de)")
            -> "mozilla firefox"
        normalize_name("Java(TM) SE Runtime Environment")
            -> "java(tm) se" (konservativ, (TM) bleibt)
        normalize_name("7-Zip 24.08 (x64 edition)")
            -> "7-zip"
        normalize_name("Microsoft Edge WebView2 Runtime")
            -> "microsoft edge webview2"

    Args:
        raw: Original-Anzeigename. Beliebige Schreibweise.

    Returns:
        Kanonischer lowercase-String ohne Trailing-Whitespace.
        ``""`` fuer ``None``/leerer Input.
    """
    if not raw:
        return ""

    s = raw.lower()
    s = _PAREN_PATTERN.sub("", s)

    for pat in _VERSION_PATTERNS:
        s = pat.sub("", s)

    for term in _NOISE_TERMS:
        s = re.sub(r"\b" + re.escape(term) + r"\b", "", s)

    s = re.sub(r"\s+", " ", s)
    return s.strip()


def normalize_for_matching(raw: str) -> str:
    """Wie:func:`normalize_name`, entfernt zusaetzlich
:data:`_SEMANTIC_TOKENS`.

    Wird in:func:`find_policy_key` (und damit in
:class:`core.patch_policy.PolicyDB.get`) statt
:func:`normalize_name` verwendet, damit Software-Varianten
    wie ``"Microsoft.NET SDK"`` und ``"Microsoft.NET Runtime"``
    auf dem gleichen Policy-Key landen — beide muessen patch_only
    sein, aber die Anzeige-Form bleibt unterschiedlich.

    Beispiele::

        normalize_for_matching("Microsoft.NET Runtime 8.0")
            -> "microsoft.net"
        normalize_for_matching("Microsoft.NET SDK 8.0")
            -> "microsoft.net"
        normalize_for_matching("Apache HTTP Server 2.4")
            -> "apache http"
        normalize_for_matching("My Cool Driver Pro")
            -> "my cool"

    Args:
        raw: Original-Anzeigename.

    Returns:
        Lookup-tauglicher Match-String. ``""`` fuer leeren Input.
    """
    s = normalize_name(raw)
    if not s:
        return ""

    stripped = s
    for term in _SEMANTIC_TOKENS:
        stripped = re.sub(r"\b" + re.escape(term) + r"\b", "", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()

    # Defensive: wenn das Strippen den Match-Wert unter 3 Zeichen
    # drueckt, behaelt der Fallback den ``normalize_name``-Wert.
    # Beispiel: ``"eM Client"`` → ``"em client"`` → strip ``"client"``
    # = ``"em"``. Ein 2-Zeichen-Match-String waere via Substring auf
    # jedes lange Policy-Key-Token mit ``"em"`` darin gematcht
    # (``"eclipse foundation.temurin"``, ``"imagemagick"`` usw.) —
    # die Match-Qualitaet waere komplett kaputt.
    if len(stripped) < 3:
        return s
    return stripped


def normalize_version(raw: str | None) -> str | None:
    """Bereinigt einen Versions-String fuer Vergleiche.

    Behandlung:

    * 4-Komponenten-Versionen mit trailing ``".0"`` werden gekuerzt
      (``"3.12.0.0"`` → ``"3.12.0"``).
    * Java-Style Suffix mit ``+`` wird abgeschnitten
      (``"11.0.2+9"`` → ``"11.0.2"``).
    * Sentinels (``"unknown"``, ``"unbekannt"``, ``"n/a"``,
      ``"none"``, ``"-"``, leer, ``None``) → ``None``.

    Beispiele::

        normalize_version("3.12.0.0") -> "3.12.0"
        normalize_version("121.0.6167.85") -> "121.0.6167.85"
        normalize_version("11.0.2+9") -> "11.0.2"
        normalize_version("unknown") -> None
        normalize_version("unbekannt") -> None
        normalize_version("") -> None
        normalize_version(None) -> None

    Args:
        raw: Versions-String, Sentinel, leerer String oder ``None``.

    Returns:
        Bereinigte Version, oder ``None`` wenn nicht parsbar.
    """
    if not raw:
        return None
    s = str(raw).strip().lower()
    if s in ("unknown", "unbekannt", "n/a", "none", "-"):
        return None

    s = s.split("+")[0]

    parts = s.split(".")
    while len(parts) > 3 and parts[-1] == "0":
        parts.pop()

    return ".".join(parts) if parts else None


# Tokens, die "ist Runtime / Redistributable" signalisieren.
# Werden in:func:`is_runtime_noise` gegen den lowercase-Original-Namen
# (NICHT normalisiert) geprueft — wir wollen die Information erhalten,
# bevor:func:`normalize_name` sie wegputzt.
_RUNTIME_NOISE_TOKENS: tuple[str, ...] = (
    "redistributable",
    "vc++",
    "windowsappruntime",
    "windows app runtime",
    "directx",
    ".net runtime",
    "dotnet runtime",
    "vcredist",
)


def is_runtime_noise(raw: str) -> bool:
    """True wenn der Name eine Runtime-/Redistributable-Komponente ist.

    Solche Software wird vom Policy-Resolver auf ``patch_only`` gemappt
    — sie ist System-Abhaengigkeit, kein direkter User-Patch-Kandidat.

    Beispiele::

        is_runtime_noise("Microsoft Visual C++ 2022 Redistributable")
            -> True
        is_runtime_noise("DirectX for Windows") -> True
        is_runtime_noise("Mozilla Firefox") -> False

    Args:
        raw: Original-Anzeigename.

    Returns:
        True bei Runtime/Redistributable-Indikator, sonst False.
    """
    if not raw:
        return False
    s = raw.lower()
    return any(tok in s for tok in _RUNTIME_NOISE_TOKENS)


# Hard-Overrides: wenn ``trigger`` im normalisierten Namen vorkommt,
# wird zwingend das ``target`` als Policy-Key gewaehlt — VOR dem
# normalen Substring-Match. Schuetzt vor mehrdeutigen Substring-
# Treffern (z.B. "webview2" vs "edge", "vcredist" vs "visual studio").
_HARD_OVERRIDES: dict[str, str] = {
    "webview2": "microsoft edge webview2",
    "vcredist": "microsoft visual c++",
    "dotnet": "microsoft .net",
    "java": "java runtime",
}


def _token_overlap(s1: str, s2: str) -> float:
    """Anteil gemeinsamer Wort-Tokens (Jaccard-aehnlich, max-skaliert).

    Spaltet beide Strings an Whitespace, vergleicht die Token-Mengen.

    Args:
        s1: Erster Vergleichs-String.
        s2: Zweiter Vergleichs-String.

    Returns:
        ``len(t1 ∩ t2) / max(len(t1), len(t2))`` aus ``[0.0, 1.0]``.
        ``0.0`` wenn eine der Token-Mengen leer ist.
    """
    t1 = set(s1.split())
    t2 = set(s2.split())
    if not t1 or not t2:
        return 0.0
    return len(t1 & t2) / max(len(t1), len(t2))


def find_policy_key(
    normalized: str,
    policy_keys: list[str],
) -> tuple[str, float] | None:
    """Sucht den besten Policy-Key fuer einen normalisierten Namen.

    Strategie (in dieser Reihenfolge):

    1. **Hard-Override** (:data:`_HARD_OVERRIDES`):
       Wenn ein ``trigger`` als Substring im ``normalized`` vorkommt
       UND das ``target`` in ``policy_keys`` ist → ``(target, 0.85)``.
    2. **Exakter Match** (``normalized in policy_keys``):
       ``(normalized, 0.9)``.
    3. **Score-basierter Substring-Match** unter allen Kandidaten,
       die in irgendeiner Richtung mit ``normalized`` matchen
       (``k in normalized`` ODER ``normalized in k``):

       * ``substring_ratio = len(key) / max(len(normalized), 1)``
       * ``token_ratio = _token_overlap(normalized, key)``
       * ``score = 0.7 * substring_ratio + 0.3 * token_ratio``

       Tie-Break-Reihenfolge (jeweils absteigend):

       1. ``score`` (groesster gewinnt)
       2. Anzahl Tokens im Key (``len(key.split)`` —
          mehr Tokens ⇒ spezifischer)
       3. Stringlaenge (``len(key)``)
       4. Key alphabetisch (deterministisch — alphabetisch
          groesserer gewinnt, fuer Reproduzierbarkeit)

    4. **Kein Match**: ``None``.

    Confidence im Rueckgabewert ist gleich ``score`` fuer Substring-
    Matches (gerundet auf 2 Nachkommastellen) bzw. ``0.85`` /
    ``0.9`` fuer Hard-Override / Exact-Match.

    Args:
        normalized: Normalisierter Software-Name (aus
:func:`normalize_for_matching`). Leerer String / None →
            ``None``.
        policy_keys: Liste verfuegbarer Policy-Schluessel
            (lowercase, vorbereitet).

    Returns:
        ``(best_key, confidence)``, oder ``None`` wenn nichts greift.
    """
    if not normalized:
        return None

    for trigger, target in _HARD_OVERRIDES.items():
        if trigger in normalized and target in policy_keys:
            return (target, 0.85)

    if normalized in policy_keys:
        return (normalized, 0.9)

    matches = [
        k for k in policy_keys
        if k in normalized or normalized in k
    ]
    if not matches:
        return None

    def _score(key: str) -> float:
        substring_ratio = len(key) / max(len(normalized), 1)
        token_ratio = _token_overlap(normalized, key)
        return 0.7 * substring_ratio + 0.3 * token_ratio

    scored = [(_score(k), k) for k in matches]
    best_score, best_key = max(
        scored,
        key=lambda sk: (sk[0], len(sk[1].split()), len(sk[1]), sk[1]),
    )
    return (best_key, round(best_score, 2))
