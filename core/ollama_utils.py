"""
ollama_utils — Wiederverwendbare Ollama-Hilfsfunktionen.

Stellt `is_ollama_running` und `ensure_ollama_running` bereit — nutzbar
von jedem Tool das Ollama benötigt (cyber_dashboard, ki_integration usw.).

Sicherheitsdesign:
  - Nur localhost (127.0.0.1:11434) wird kontaktiert — kein Remote-Aufruf
  - subprocess.Popen startet nur `ollama serve` — kein Shell-Injection möglich
    da args als Liste übergeben werden (shell=False ist Standard)

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

import requests
from packaging.version import InvalidVersion, Version

from core.config import OLLAMA_HOST, OLLAMA_STARTUP_TIMEOUT
from core.logger import get_logger

_log = get_logger(__name__)

_OLLAMA_URL = f"{OLLAMA_HOST}/api/version"

# Sicherheits-Mindestversion des Ollama-Servers. Begründung: mehrere
# file-getriggerte GGUF-/Endpoint-CVEs (u. a. "Probllama" CVE-2024-37032,
# ZipSlip CVE-2024-7773, GGUF-DoS) werden durch die localhost-Bindung NICHT
# entschärft — der Trigger ist der Datei-/Modell-Import. Daher Versions-Pin.
# HINWEIS: Vor einer harten "refuse-to-run"-Grenze ist die exakte Fixversion
# gegen NVD/Ollama-Releases zu verifizieren (Plan: "vor Implementierung
# verifizieren"); Default-Verhalten ist daher Warnung, nicht Blockade.
MIN_OLLAMA_VERSION: str = "0.17.1"

# TTL-Cache fuer ``is_ollama_running`` + ``get_available_models``.
# Security-Chat-Tool-Init machte 3 sequentielle
# HTTP-Calls zum Ollama-Server (Health-Check + Modell-Liste 2x) im
# UI-Thread — 6+ Sekunden Ladezeit. Mit Cache: erster Aufruf laeuft
# normal, die naechsten ``_CACHE_TTL_SECONDS`` Sekunden liefern aus
# dem Cache (Modell-Liste aendert sich selten).
_CACHE_TTL_SECONDS = 30.0
_HEALTH_CACHE: tuple[float, bool] | None = None  # (gemessen_at, is_running)
_MODELS_CACHE: tuple[float, list[str]] | None = None  # (gemessen_at, modelle)


def _cache_valid(stamp: float) -> bool:
    return (time.monotonic() - stamp) < _CACHE_TTL_SECONDS


def invalidate_ollama_caches() -> None:
    """Loescht beide Caches — manuell aufrufbar bei Tests oder nach
    ``ensure_ollama_running``-Trigger."""
    global _HEALTH_CACHE, _MODELS_CACHE
    _HEALTH_CACHE = None
    _MODELS_CACHE = None


def get_default_ollama_generate_url() -> str:
    """Default-URL für den Ollama ``/api/generate``-Endpoint.

    Konstruiert aus:data:`core.config.OLLAMA_HOST`. Wenn Patrick später
    User-konfigurierbare Ollama-URLs einführt (z. B. via UISettings),
    bleibt diese Helper-Funktion der einzige Ersatz-Punkt.

    Returns:
        z. B. ``"http://localhost:11434/api/generate"``.
    """
    return f"{OLLAMA_HOST}/api/generate"


def get_default_ollama_tags_url() -> str:
    """Default-URL für den Ollama ``/api/tags``-Endpoint.

    Returns:
        z. B. ``"http://localhost:11434/api/tags"``.
    """
    return f"{OLLAMA_HOST}/api/tags"

# ----------------------------------------------------------------------------
# Oeffentliche Konstanten (Coding Rule R1: hier ist die einzige erlaubte
# Heimat fuer Ollama-Modellnamen — Scanner whitelistet diese Datei).
# ----------------------------------------------------------------------------

# Empfohlenes Default-Ollama-Modell (REAL existierende Serie). Nutzer ohne
# installiertes Modell sehen einen "bitte gemma3 installieren"-Hinweis; die
# Generierungs-Pfade waehlen ueber get_default_model ausschliesslich aus den
# tatsaechlich auf dem Geraet INSTALLIERTEN Modellen (/api/tags) — nie ein
# hardcodiertes/fiktives Modell.: 'gemma4'/'qwen3.5' existieren als Serie
# nicht (real: gemma3 bzw. qwen3/qwen2.5) und sind hier entfernt, damit ein
# versehentlich so getaggtes (kaputtes) Modell nicht bevorzugt gewaehlt wird.
DEFAULT_OLLAMA_MODEL: str = "gemma3"

# Praefixe fuer die Gemma-Modellfamilie. Wird zur Gewichtung in
# Modell-Auswahl-Dropdowns verwendet (Gemma-Modelle nach oben sortieren).
GEMMA_MODEL_PREFIXES: tuple[str, ...] = ("gemma3", "gemma2", "gemma")

# Exakte Tags — werden einem Prefix-Match vorgezogen (Reihenfolge = Priorität).
# Nur wirksam wenn der Tag tatsächlich installiert ist; ein nicht installierter
# Tag wird uebersprungen (kein Zwang zu einem bestimmten Modell). Nur REALE Tags.
_MODEL_PREFERRED_TAGS: tuple[str, ...] = (
    f"{DEFAULT_OLLAMA_MODEL}:latest",  # gemma3:latest — staerkste Allround-Qualitaet
    "qwen3:8b",                        # 8B-Parameter, gute EStG/UStG-Qualitaet
)

# Reihenfolge der Modell-Präferenz per Präfix (Fallback wenn kein Tag-Match).
# qwen2.5 vor qwen3 (generisch) weil qwen2.5:* oft bessere Instruktionsfolgung.
_MODEL_PREFERRED_PREFIXES: tuple[str, ...] = (
    "qwen2.5",
    "qwen3",
    "qwen",
    "coder",
)

# Hosts die als "lokal" gelten — für validate_ollama_url
ALLOWED_OLLAMA_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})


def validate_ollama_url(url: str) -> bool:
    """Prüft dass die Ollama-URL nur auf localhost zeigt.

    Schützt vor unbeabsichtigter Konfiguration externer Ollama-Instanzen,
    bei der Nutzerdaten das lokale Netzwerk verlassen würden.

    Args:
        url: Zu prüfende URL, z. B. ``"http://localhost:11434"``.

    Returns:
        True wenn der Host in ``ALLOWED_OLLAMA_HOSTS`` ist, sonst False.

    Example:
        >>> validate_ollama_url("http://localhost:11434")
        True
        >>> validate_ollama_url("http://external-server.com:11434")
        False
    """
    try:
        from urllib.parse import urlparse  # noqa: PLC0415

        parsed = urlparse(url)
        is_local = parsed.hostname in ALLOWED_OLLAMA_HOSTS
        if not is_local:
            _log.warning(
                "validate_ollama_url: Nicht-localhost URL erkannt: %s — "
                "Daten könnten das Netzwerk verlassen!",
                parsed.hostname,
            )
        return is_local
    except (ValueError, AttributeError):
        return False


def is_ollama_running(timeout: float = 2.0) -> bool:
    """Prüft ob der lokale Ollama-Server erreichbar ist.

    Cache-Verhalten: Ergebnis wird fuer
    ``_CACHE_TTL_SECONDS`` (30 s) gecacht. Wer den frischen Stand
    braucht (z. B. nach ``ensure_ollama_running``), ruft vorher
:func:`invalidate_ollama_caches` auf.

    Args:
        timeout: Verbindungs-Timeout in Sekunden (nur bei Cache-Miss).

    Returns:
        True wenn Ollama auf localhost:11434 antwortet.
    """
    global _HEALTH_CACHE
    if _HEALTH_CACHE is not None and _cache_valid(_HEALTH_CACHE[0]):
        return _HEALTH_CACHE[1]
    try:
        resp = requests.get(_OLLAMA_URL, timeout=timeout)
        running = resp.status_code == 200
    except requests.RequestException:
        running = False
    _HEALTH_CACHE = (time.monotonic(), running)
    return running


def ensure_ollama_running(timeout: float = OLLAMA_STARTUP_TIMEOUT) -> bool:
    """Startet Ollama falls nicht laufend und wartet bis bereit.

    Versucht `ollama serve` im Hintergrund zu starten.
    Gibt True zurück sobald Ollama erreichbar ist.

    Args:
        timeout: Maximale Wartezeit in Sekunden.

    Returns:
        True wenn Ollama bereit ist, False wenn nicht installiert
        oder nicht innerhalb von `timeout` Sekunden erreichbar.
    """
    if is_ollama_running():
        return True

    try:
        subprocess.Popen(  # noqa: S603
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _log.info("Ollama serve gestartet — warte auf Bereitschaft")
    except FileNotFoundError:
        _log.warning("Ollama nicht installiert — 'ollama serve' nicht gefunden")
        return False
    except OSError as exc:
        _log.error("Ollama-Start fehlgeschlagen: %s", type(exc).__name__)
        return False

    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if is_ollama_running(timeout=1.0):
            _log.info("Ollama bereit nach %.1fs", time.monotonic() - start)
            return True
        time.sleep(1.0)

    _log.warning("Ollama nicht bereit nach %.0fs Wartezeit", timeout)
    return False


# ----------------------------------------------------------------------------
# Versions-Sicherheits-Check (Plan P0-1)
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class OllamaVersionStatus:
    """Ergebnis des Ollama-Versions-Sicherheits-Checks.

    Attributes:
        state: ``"ok"`` (>= Mindestversion), ``"outdated"`` (zu alt, bekannte
            CVEs offen) oder ``"unknown"`` (Version nicht ermittelbar).
        current: Erkannte Version (z. B. ``"0.30.6"``) oder ``None``.
        minimum: Geforderte Mindestversion.
    """

    state: str
    current: str | None
    minimum: str

    @property
    def is_ok(self) -> bool:
        """True, wenn die Version die Sicherheits-Mindestversion erfüllt."""
        return self.state == "ok"


def is_version_at_least(current: str, minimum: str) -> bool:
    """Prüft semantisch, ob ``current >= minimum`` ist.

    Nutzt:class:`packaging.version.Version` — KEIN String-Vergleich. Ein
    naiver String-Vergleich liefert ``"0.9.0" > "0.17.1"`` (falsch, weil "9"
    > "1"); dieser klassische Bug wird hier vermieden.

    Args:
        current: Aktuelle Versionsangabe (z. B. ``"0.30.6"``, ``"0.17.1-rc1"``).
        minimum: Geforderte Mindestversion (z. B. ``"0.17.1"``).

    Returns:
        True, wenn ``current`` größer oder gleich ``minimum`` ist. Bei
        nicht parsebarer ``current``-Angabe konservativ ``False``.
    """
    try:
        return Version(current.lstrip("vV").strip()) >= Version(minimum)
    except (InvalidVersion, AttributeError):
        _log.warning("Ollama-Version nicht parsebar: %r", current)
        return False


def get_ollama_version(timeout: float = 3.0) -> str | None:
    """Liest die Version des lokalen Ollama-Servers via ``/api/version``.

    Args:
        timeout: Verbindungs-Timeout in Sekunden.

    Returns:
        Versions-String (z. B. ``"0.30.6"``) oder ``None``, wenn der Server
        nicht erreichbar ist oder keine Version liefert.
    """
    try:
        resp = requests.get(_OLLAMA_URL, timeout=timeout)
        if resp.status_code == 200:
            version = resp.json().get("version", "")
            return str(version) or None
    except (requests.RequestException, ValueError, OSError) as exc:
        _log.debug("Ollama-Version nicht abrufbar: %s", type(exc).__name__)
    return None


def check_ollama_version(version_str: str | None = None) -> OllamaVersionStatus:
    """Prüft die Ollama-Version gegen die Sicherheits-Mindestversion.

    Args:
        version_str: Optional eine bereits bekannte Version (für Tests). Wenn
            ``None``, wird sie via:func:`get_ollama_version` ermittelt.

    Returns:
        OllamaVersionStatus mit ``state`` ``"ok"`` / ``"outdated"`` /
        ``"unknown"``.
    """
    raw = version_str if version_str is not None else get_ollama_version()
    if not raw:
        return OllamaVersionStatus("unknown", None, MIN_OLLAMA_VERSION)
    state = "ok" if is_version_at_least(raw, MIN_OLLAMA_VERSION) else "outdated"
    if state == "outdated":
        _log.warning(
            "Ollama-Version %s ist älter als die Sicherheits-Mindestversion %s.",
            raw,
            MIN_OLLAMA_VERSION,
        )
    return OllamaVersionStatus(state, raw, MIN_OLLAMA_VERSION)


def get_available_models() -> list[str]:
    """Gibt alle installierten Ollama-Modellnamen zurück.

    Fragt ``/api/tags`` ab und gibt die Modellnamen sortiert nach
    zuletzt verwendet (Ollama-Standard) zurück.

    Cache-Verhalten: Ergebnis wird fuer
    ``_CACHE_TTL_SECONDS`` (30 s) gecacht — Modelle aendern sich
    selten, der UI-Init-Pfad rief diese Funktion 2x pro Tool-Open
    auf und blockierte damit den Main-Thread. Bei Cache-Miss wird
    der Wert auch im Fehlerfall (leere Liste) gecacht, damit
    wiederholte Fehlversuche keinen 3-Sekunden-Timeout aufaddieren.

    Returns:
        Liste der Modellnamen, z. B. ``["qwen2.5-coder:7b", "qwen3:8b"]``.
        Leere Liste wenn Ollama nicht erreichbar oder kein Modell installiert.
    """
    global _MODELS_CACHE
    if _MODELS_CACHE is not None and _cache_valid(_MODELS_CACHE[0]):
        return list(_MODELS_CACHE[1])  # defensive Kopie
    result: list[str] = []
    try:
        resp = requests.get(get_default_ollama_tags_url(), timeout=3)
        if resp.status_code == 200:
            result = [
                m["name"]
                for m in resp.json().get("models", [])
                if m.get("name")
            ]
    # Cleanup-Sprint 2026-04-29: zusätzlich ``OSError`` fangen — Python's
    # built-in ``ConnectionError`` ist ein ``OSError``, nicht ein
    # ``requests.RequestException``. Der Default ist eh "leere Liste,
    # wenn nicht erreichbar", deshalb darf der Fang weit greifen.
    except (requests.RequestException, ValueError, OSError):
        pass
    _MODELS_CACHE = (time.monotonic(), result)
    return list(result)


def get_vision_model() -> str | None:
    """Gibt das beste verfügbare Vision-Modell zurück.

    Vision-Modelle unterstützen Bild-Eingaben (llava, moondream, bakllava).
    Priorität: llava > moondream > bakllava > None.

    Returns:
        Modellname oder None wenn kein Vision-Modell installiert.
    """
    _vision_prefixes = ("llava", "moondream", "bakllava")
    models = get_available_models()
    for prefix in _vision_prefixes:
        for m in models:
            if m.lower().startswith(prefix):
                _log.debug("Ollama Vision-Modell: %s", m)
                return m
    _log.debug("Kein Vision-Modell installiert (llava/moondream/bakllava)")
    return None


def hat_vision_modell() -> bool:
    """Prüft ob ein Vision-Modell installiert ist.

    Returns:
        True wenn mindestens ein Vision-Modell (llava/moondream/bakllava)
        in der Ollama-Modellliste vorhanden ist.
    """
    return get_vision_model() is not None


def get_default_model() -> str | None:
    """Gibt das beste verfügbare Ollama-Modell zurück.

    Priorität:
      1. Exakter Tag-Match aus ``_MODEL_PREFERRED_TAGS`` (z.B. gemma3:latest).
      2. Präfix-Match aus ``_MODEL_PREFERRED_PREFIXES`` (qwen2.5 > qwen3 >...).
      3. Erstes installiertes Modell laut ``/api/tags`` als letzter Fallback.
      4. ``None`` wenn Ollama nicht läuft oder kein Modell installiert ist.

    NIEMALS ein hardcodiertes Modell als Fallback — das führt bei Nutzern
    ohne das jeweilige Modell zu Fehlern.

    Returns:
        Modellname oder ``None``.
    """
    models = get_available_models()
    if not models:
        _log.debug("Kein Ollama-Modell verfügbar")
        return None

    # Stufe 1: Exakte Tag-Präferenz (z.B. gemma3:latest vor qwen3:8b)
    models_lower = {m.lower(): m for m in models}
    for tag in _MODEL_PREFERRED_TAGS:
        if tag.lower() in models_lower:
            chosen = models_lower[tag.lower()]
            _log.debug("Ollama Default-Modell (Tag '%s'): %s", tag, chosen)
            return chosen

    # Stufe 2: Präfix-Match
    for prefix in _MODEL_PREFERRED_PREFIXES:
        for m in models:
            if m.lower().startswith(prefix):
                _log.debug("Ollama Default-Modell (Präferenz '%s'): %s", prefix, m)
                return m

    _log.debug("Ollama Default-Modell (Fallback): %s", models[0])
    return models[0]
