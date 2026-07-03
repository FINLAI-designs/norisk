"""
briefing_service — KI-Briefing via Ollama.

Erzeugt zwei kompakte Meldungslisten: techstack-bezogen (links) und
allgemein (rechts). Jeder Eintrag ist sachlich, ein Satz, ohne Wertung
oder Handlungsaufforderung.

Sicherheitsdesign:
  - Meldungsinhalte werden nicht geloggt
  - Briefing wird lokal gecacht (~/.finlai/cyber_briefing.json)
  - Kein Netzwerkzugriff ohne expliziten Aufruf

Author: Patrick Riederich
Version: 2.0
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime

from core.feed_settings import load_feed_settings
from core.finlai_paths import finlai_dir
from core.guardrails.guardrails import detect_injection_signals
from core.logger import get_logger
from core.ollama_utils import (
    ensure_ollama_running,
    get_default_ollama_generate_url,
    get_default_ollama_tags_url,
    validate_ollama_url,
)
from tools.cyber_dashboard.application.consumer_feeds_service import (
    ConsumerFeedsService,
)
from tools.cyber_dashboard.domain.models import (
    ConsumerMeldung,
    ConsumerQuelle,
    CveEintrag,
    CyberMeldung,
    TechStackEintrag,
)
from tools.cyber_dashboard.domain.prompts import (
    BRIEFING_SYSTEM_PROMPT,
    PHISHING_BRIEFING_SYSTEM_PROMPT,
    PHISHING_TREND_SYSTEM_PROMPT,
)

log = get_logger(__name__)

BRIEFING_PATH = finlai_dir() / "cyber_briefing.json"
OLLAMA_URL = get_default_ollama_generate_url()
OLLAMA_TAGS_URL = get_default_ollama_tags_url()


def _ollama_egress_erlaubt() -> bool:
    """Fail-closed (Security/): kein LLM-Egress an Nicht-localhost-Ollama.

    TechStack-/CVE-/Phishing-Inhalte duerfen die Maschine nicht verlassen
    (Invariante CONFIDENTIAL=lokal). Ein per ENV (``FINLAI_OLLAMA_HOST``) auf
    eine externe IP gesetzter Host wird hier abgewiesen — der Aufrufer faellt
    dann auf die Roh-Texte zurueck statt Daten zu exfiltrieren.
    """
    if validate_ollama_url(OLLAMA_URL):
        return True
    log.warning("Ollama-Host nicht lokal (%s) — LLM-Egress unterbunden.", OLLAMA_URL)
    return False


# Streaming-Ollama: (connect, read)-Timeout für Verbindungsaufbau / erstes Byte.
# Nach dem ersten Byte streamt Ollama beliebig lange — das wird über den
# Cancel-Flag kontrolliert, nicht über einen harten Gesamt-Timeout.
#
# READ-Timeout = Zeit bis zum ERSTEN Token. Ist das Modell noch nicht im
# Speicher (``ollama ps`` leer), muss Ollama es erst kalt laden — das kann
# bei groesseren Modellen deutlich >30s dauern und liess das Briefing
# frueher in den Timeout laufen. 180s gibt dem Kaltstart Luft.
_OLLAMA_CONNECT_TIMEOUT = 5
_OLLAMA_READ_TIMEOUT = 180

# Haelt das Modell nach dem (teuren) Kaltstart im Speicher, sodass Folge-
# Briefings sofort antworten statt erneut zu laden. Top-Level-Ollama-Param.
_OLLAMA_KEEP_ALIVE = "30m"

_MAX_PRO_SPALTE = 3
_MAX_CONSUMER = 5

# TTL für den Modell-Verfügbarkeitscheck (pro BriefingService-Instanz).
_MODELL_CACHE_TTL_S = 60

# stabile Fehler-Kategorien fuer die GUI-Meldung. Single Source — die GUI
# (briefing_tab) importiert diese statt die Strings zu duplizieren, damit ein
# Rename nicht still zur generischen "Ollama nicht erreichbar"-Meldung degradiert.
FEHLER_MODELL_FEHLT = "model_not_available"
FEHLER_LEERER_STREAM = "empty_stream"
FEHLER_TIMEOUT = "Timeout"
FEHLER_HTTP_PREFIX = "HTTPError"

# Sortier-Prioritaet fuer Consumer-Eintraege: Windows-Oekosystem vor Browsern.
_CONSUMER_PRIO: dict[ConsumerQuelle, int] = {
    ConsumerQuelle.MSRC: 0,  # Windows, Office
    ConsumerQuelle.CHROME: 1,
    ConsumerQuelle.MOZILLA: 2,
    ConsumerQuelle.BSI: 3,  # Misch
}


@dataclass
class _Kandidat:
    """Intern: ein Roh-Eintrag vor der LLM-Formulierung."""

    produkt: str
    cve_id: str
    rohtext: str


@dataclass
class _ConsumerKandidat:
    """Intern: ein Roh-Consumer-Eintrag mit Quell-Badge."""

    produkt: str
    quelle: ConsumerQuelle
    rohtext: str
    veroeffentlicht: datetime


#: Tokens kürzer als dies matchen nur gegen die strukturierte CVE-Produktliste,
#: nie gegen den Freitext — verhindert Generik-Treffer wie "act" als Wort in einer
#: Beschreibung. Kurze, echte Produkte (z.B. "Git") matchen weiter über die
#: strukturierte Produktliste der CVE.
_MIN_PROSE_TOKEN_LEN = 4


def _cpe_produkt_tokens(cpe: str) -> list[str]:
    """Extrahiert Vendor- und Produkt-Token aus einem CPE-2.3-String.

    Args:
        cpe: CPE-String, z.B. ``cpe:2.3:a:apache:http_server:2.4``.

    Returns:
        Vendor-/Produkt-Token (``_`` -> Leerzeichen, lowercase); leere Liste wenn
        ``cpe`` kein parsebarer CPE-2.3-String ist.
    """
    if not cpe or not cpe.lower().startswith("cpe:"):
        return []
    parts = cpe.split(":")
    if len(parts) < 5:
        return []
    tokens: list[str] = []
    for idx in (3, 4):  # Index 3 = Vendor, 4 = Produkt
        val = parts[idx].strip().lower().replace("_", " ")
        if val and val not in ("*", "-"):
            tokens.append(val)
    return tokens


def _match_tokens(name: str, cpe: str) -> list[str]:
    """Match-Token eines Techstack-Eintrags: Anzeigename + (falls vorhanden) CPE.

    Args:
        name: Anzeigename des Eintrags.
        cpe: Optionaler CPE-String.

    Returns:
        Eindeutige, lowercase Token-Liste (Reihenfolge erhalten).
    """
    tokens: list[str] = []
    name_low = (name or "").strip().lower()
    if name_low:
        tokens.append(name_low)
    tokens.extend(_cpe_produkt_tokens(cpe or ""))
    seen: set[str] = set()
    eindeutig: list[str] = []
    for tok in tokens:
        if tok and tok not in seen:
            seen.add(tok)
            eindeutig.append(tok)
    return eindeutig


def _token_im_text(token: str, text: str) -> bool:
    r"""Wortgrenzen-Match statt Substring.

    ``act`` matcht NICHT in ``transaction``; punktuierte Produktnamen (``.net``,
    ``c++``) matchen aber korrekt — ``\b`` versagt an Nicht-Wort-Zeichen, daher
    Lookarounds auf Wort-Zeichen statt ``\b`` Review C1).
    """
    if not token or not text:
        return False
    return re.search(r"(?<!\w)" + re.escape(token) + r"(?!\w)", text) is not None


def _stream_ollama_json(
    modell: str,
    system_prompt: str,
    user_prompt: str,
    cancel_flag: Callable[[], bool] | None = None,
) -> tuple[str | None, str | None]:
    """Streamt eine ``format=json``-Antwort von Ollama (cancelbar).

    Geteilte Streaming-Mechanik (Regel 2) — bewusst OHNE den Audit-Trail des
    CVE-Pfads, damit der (historisch fragile) ``generiere_briefing``-Pfad
    UNBERUEHRT bleibt. Die Phishing-Session (c1) nutzt diese Funktion direkt.

    Args:
        modell: Ollama-Modellname.
        system_prompt: System-Prompt.
        user_prompt: User-Prompt.
        cancel_flag: Optionales Callable; ``True`` bricht zwischen Chunks ab.

    Returns:
        ``(antwort, fehler)``. ``antwort`` ist der akkumulierte Response-String
        oder ``None`` bei Fehler/Abbruch; ``fehler`` ist eine ``FEHLER_*``-
        Kategorie / ``"cancelled"`` bzw. ``None`` bei Erfolg.
    """
    import requests as req  # noqa: PLC0415

    if not _ollama_egress_erlaubt():
        return None, FEHLER_HTTP_PREFIX

    try:
        resp = req.post(
            OLLAMA_URL,
            json={
                "model": modell,
                "prompt": user_prompt,
                "system": system_prompt,
                "format": "json",
                "stream": True,
                # Reasoning-Modelle verbrauchen sonst ihr Token-Budget
                # fuers Denken und liefern leeren Stream -> direkte Antwort.
                "think": False,
                "keep_alive": _OLLAMA_KEEP_ALIVE,
                "options": {"temperature": 0.2, "num_predict": 700},
            },
            timeout=(_OLLAMA_CONNECT_TIMEOUT, _OLLAMA_READ_TIMEOUT),
            stream=True,
        )
        resp.raise_for_status()
        chunks: list[str] = []
        try:
            for line in resp.iter_lines():
                if cancel_flag is not None and cancel_flag():
                    return None, "cancelled"
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue  # Keep-Alive-Ping oder Teilzeile
                piece = payload.get("response", "")
                if piece:
                    chunks.append(piece)
                if payload.get("done"):
                    break
        finally:
            resp.close()
        antwort = "".join(chunks)
        if not antwort:
            return None, FEHLER_LEERER_STREAM
        return antwort, None
    except req.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        reason = exc.response.reason if exc.response is not None else ""
        return None, f"{FEHLER_HTTP_PREFIX}: {status} {reason}".strip()
    except req.exceptions.Timeout:
        return None, FEHLER_TIMEOUT
    except Exception as exc:  # noqa: BLE001 — Ollama-API kann unspezifiziert werfen
        return None, f"{type(exc).__name__}: {str(exc)[:100]}"


class BriefingService:
    """Generiert tägliche KI-Briefings via Ollama.

    Das Briefing wird einmal täglich generiert und lokal gecacht.
    Wenn Ollama nicht verfügbar ist, wird das letzte gecachte Briefing
    zurückgegeben.

    Streaming-Modus:
        ``generiere_briefing`` nutzt Ollama-Streaming (``stream=True``). Die
        Chunks werden im Worker-Thread akkumuliert; bei ``format="json"`` ist
        ein Partial-Parse nicht zuverlässig, deshalb wird erst bei ``done=True``
        das vollständige JSON geparst. Der Vorteil liegt in der **sofortigen
        Abbrechbarkeit** zwischen Chunks via ``cancel_flag``.
    """

    def __init__(self) -> None:
        """Initialisiert den BriefingService."""
        # Modell-Verfügbarkeitscache: {modell: (vorhanden, monotonic_ts)}
        self._modell_cache: dict[str, tuple[bool, float]] = {}
        # Grund des letzten fehlgeschlagenen generiere_briefing-Laufs
        # (z.B. "empty_stream", "Timeout") — die GUI macht daraus eine
        # spezifische Meldung statt eines generischen "Ollama nicht erreichbar".
        self._letzter_fehler: str | None = None

    def briefing_verfuegbar(self) -> bool:
        """Prüft ob bereits ein Briefing für heute vorhanden ist.

        Returns:
            True wenn heutiges Briefing gecacht ist.
        """
        if not BRIEFING_PATH.exists():
            return False
        try:
            data = json.loads(BRIEFING_PATH.read_text(encoding="utf-8"))
            return data.get("datum", "") == str(date.today())
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return False

    def lade_briefing(self) -> dict | None:
        """Lädt das gecachte Briefing.

        Returns:
            Briefing-Dict oder None wenn keins vorhanden.
        """
        if not BRIEFING_PATH.exists():
            return None
        try:
            return json.loads(BRIEFING_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    def generiere_briefing(
        self,
        meldungen: list[CyberMeldung],
        cves: list[CveEintrag],
        techstack: list[TechStackEintrag] | None = None,
        modell: str | None = None,
        consumer_meldungen: list[ConsumerMeldung] | None = None,
        cancel_flag: Callable[[], bool] | None = None,
    ) -> dict | None:
        """Generiert ein neues KI-Briefing via Ollama (streaming + cancelbar).

        Vor dem LLM-Aufruf werden die Meldungen gegen den Techstack
        gefiltert und pro Spalte auf maximal ``_MAX_PRO_SPALTE`` Einträge
        begrenzt. Der LLM reformuliert jeden Eintrag als sachlichen,
        deutschen 1-Satz-Text.

        Args:
            meldungen: Liste aktueller CyberMeldungen.
            cves: Liste aktueller CveEinträge.
            techstack: Persönlicher Tech-Stack für Relevanzfilter.
            modell: Ollama-Modellname.
            consumer_meldungen: Liste der Consumer-Software-Advisories.
                Wenn ``None`` wird der:class:`ConsumerFeedsService` mit den
                aktuellen Feed-Settings bemüht.
            cancel_flag: Optionales Callable das ``True`` zurückgibt wenn
                der Aufrufer die Generierung abbrechen möchte. Wird zwischen
                Streaming-Chunks geprüft; bei Abbruch schließt der Service
                die Verbindung und gibt ``None`` zurück.

        Returns:
            Briefing-Dict (:meth:`_bauen_briefing`) oder None wenn
            Ollama nicht erreichbar oder die Generierung abgebrochen wurde.
        """
        self._letzter_fehler = None
        if not modell:
            from core.ollama_utils import get_default_model  # noqa: PLC0415

            modell = get_default_model() or ""
            if not modell:
                log.warning("Kein Ollama-Modell verfuegbar — Briefing uebersprungen")
                self._letzter_fehler = FEHLER_MODELL_FEHLT
                return None

        if not ensure_ollama_running():
            log.warning("Ollama nicht verfuegbar — Briefing uebersprungen")
            return None

        stack = techstack or []
        techstack_kandidaten, allgemein_kandidaten = self._waehle_kandidaten(
            cves, meldungen, stack
        )
        techstack_leer = not any(e.aktiv for e in stack)

        consumer_list = (
            consumer_meldungen
            if consumer_meldungen is not None
            else self._lade_consumer_meldungen()
        )
        consumer_kandidaten = self._waehle_consumer_kandidaten(consumer_list)

        if (
            not techstack_kandidaten
            and not allgemein_kandidaten
            and not consumer_kandidaten
        ):
            return self._bauen_briefing(
                techstack_eintraege=[],
                allgemein_eintraege=[],
                consumer_eintraege=[],
                techstack_leer=techstack_leer,
                modell=modell,
            )

        # Fehlergrund fuer die GUI (None bei Erfolg); im finally an _letzter_fehler.
        fehlergrund: str | None = None
        try:
            try:
                import requests as req  # noqa: PLC0415

                if not _ollama_egress_erlaubt():
                    # Fail-closed: nicht-lokaler Ollama-Host -> kein Egress.
                    fehlergrund = FEHLER_HTTP_PREFIX
                    return None

                if not self._modell_verfuegbar(modell):
                    # Sichtbarkeitsluecke: User wollte briefen, Modell fehlt.
                    fehlergrund = FEHLER_MODELL_FEHLT
                    return None

                user_prompt = self._bauen_prompt(
                    techstack_kandidaten, allgemein_kandidaten, consumer_kandidaten
                )

                resp = req.post(
                    OLLAMA_URL,
                    json={
                        "model": modell,
                        "prompt": user_prompt,
                        "system": BRIEFING_SYSTEM_PROMPT,
                        "format": "json",
                        "stream": True,
                        # Reasoning-Modelle (z.B. qwen3*) verbrauchen unter
                        # format=json sonst ihr Token-Budget fuers Denken und liefern
                        # einen leeren response-Stream -> "think": false erzwingt
                        # direkte Antwort. Bei Nicht-Thinking-Modellen ein No-op.
                        "think": False,
                        "keep_alive": _OLLAMA_KEEP_ALIVE,
                        "options": {
                            "temperature": 0.2,
                            "num_predict": 900,
                        },
                    },
                    timeout=(_OLLAMA_CONNECT_TIMEOUT, _OLLAMA_READ_TIMEOUT),
                    stream=True,
                )
                resp.raise_for_status()

                # Chunks akkumulieren; bei format=json ist Partial-Parse unzuverlässig,
                # daher wird die vollständige Antwort erst bei done=True geparst.
                chunks: list[str] = []
                cancelled = False
                try:
                    for line in resp.iter_lines():
                        if cancel_flag is not None and cancel_flag():
                            cancelled = True
                            break
                        if not line:
                            continue
                        try:
                            payload = json.loads(line)
                        except json.JSONDecodeError:
                            continue  # Ollama-Keep-Alive-Ping oder Teilzeile
                        piece = payload.get("response", "")
                        if piece:
                            chunks.append(piece)
                        if payload.get("done"):
                            break
                finally:
                    resp.close()

                if cancelled:
                    log.info("Briefing-Generierung durch User abgebrochen")
                    fehlergrund = "cancelled"
                    return None

                antwort = "".join(chunks)
                if not antwort:
                    log.warning("Ollama lieferte leeren Stream — Modell '%s'", modell)
                    fehlergrund = FEHLER_LEERER_STREAM
                    return None

                parsed = self._parse_antwort(
                    antwort,
                    techstack_kandidaten,
                    allgemein_kandidaten,
                    consumer_kandidaten,
                )
                briefing = self._bauen_briefing(
                    techstack_eintraege=parsed["techstack_eintraege"],
                    allgemein_eintraege=parsed["allgemein_eintraege"],
                    consumer_eintraege=parsed["consumer_eintraege"],
                    techstack_leer=techstack_leer,
                    modell=modell,
                )
                self._speichere(briefing)
                log.debug("KI-Briefing generiert (Modell: %s)", modell)
                return briefing

            except req.exceptions.HTTPError as exc:  # type: ignore[union-attr]
                status = exc.response.status_code if exc.response is not None else 0
                reason = exc.response.reason if exc.response is not None else ""
                log.warning(
                    "Ollama Briefing HTTP-Fehler: %s %s — Modell '%s' verfuegbar?",
                    status,
                    reason,
                    modell,
                )
                fehlergrund = f"{FEHLER_HTTP_PREFIX}: {status} {reason}".strip()
            except req.exceptions.Timeout:  # type: ignore[union-attr]
                log.warning(
                    "Ollama Briefing Timeout (connect=%ds/read=%ds) — Ollama erreichbar?",
                    _OLLAMA_CONNECT_TIMEOUT,
                    _OLLAMA_READ_TIMEOUT,
                )
                fehlergrund = FEHLER_TIMEOUT
            except Exception as exc:  # noqa: BLE001 -- Ollama-API kann unspezifizierte Errors werfen, fail-safe None
                log.warning(
                    "Briefing-Generierung fehlgeschlagen: %s", type(exc).__name__
                )
                fehlergrund = f"{type(exc).__name__}: {str(exc)[:100]}"
            return None
        finally:
            # Grund fuer die GUI festhalten (None bei Erfolg).
            self._letzter_fehler = fehlergrund

    # ------------------------------------------------------------------
    # Phishing-Briefing (c1) — 2. Session, parallel zur CVE-Session
    # ------------------------------------------------------------------

    def generiere_phishing_briefing(
        self,
        kmu: list[CyberMeldung],
        consumer: list[CyberMeldung],
        modell: str | None = None,
        cancel_flag: Callable[[], bool] | None = None,
    ) -> dict | None:
        """Formuliert Phishing-Warnungen in zwei Zielgruppen um (c1).

        Eigene Ollama-Session, parallel zur CVE-``generiere_briefing`` aufrufbar.
        Die KMU/Consumer-Zuordnung kommt bereits DETERMINISTISCH aus
:func:`phishing_briefing.waehle_phishing_kandidaten` — das LLM formuliert
        nur um, es klassifiziert nicht. Faellt bei fehlendem/fehlerhaftem LLM auf
        die Roh-Meldungstexte zurueck (statt nichts).

        Args:
            kmu: KMU-Phishing-Kandidaten (CyberMeldung).
            consumer: Consumer-Phishing-Kandidaten.
            modell: Ollama-Modell; ``None`` zieht ``get_default_model``.
            cancel_flag: Optionales Abbruch-Callable.

        Returns:
            ``{"phishing_kmu": [...], "phishing_consumer": [...]}`` (Eintraege je
            ``{"titel","beschreibung","quelle"}``). Bei leerer Eingabe leere
            Listen.
        """
        if not kmu and not consumer:
            return {"phishing_kmu": [], "phishing_consumer": []}
        # OWASP LLM01: Feed-Inhalte vor dem Prompt auf Injection-Signale pruefen.
        kmu = self._screene_eingaben(kmu)
        consumer = self._screene_eingaben(consumer)
        if not kmu and not consumer:
            return {"phishing_kmu": [], "phishing_consumer": []}
        fallback = {
            "phishing_kmu": [self._phishing_zu_dict(m) for m in kmu],
            "phishing_consumer": [self._phishing_zu_dict(m) for m in consumer],
        }
        if not modell:
            from core.ollama_utils import get_default_model  # noqa: PLC0415

            modell = get_default_model() or ""
            if not modell:
                return fallback
        if not ensure_ollama_running() or not self._modell_verfuegbar(modell):
            return fallback
        antwort, _fehler = _stream_ollama_json(
            modell,
            PHISHING_BRIEFING_SYSTEM_PROMPT,
            self._bauen_phishing_prompt(kmu, consumer),
            cancel_flag,
        )
        if not antwort:
            return fallback
        return self._parse_phishing(antwort, kmu, consumer)

    def generiere_phishing_trend(
        self,
        kmu: list[CyberMeldung],
        consumer: list[CyberMeldung],
        modell: str | None = None,
        cancel_flag: Callable[[], bool] | None = None,
    ) -> str:
        """Kurze KI-Trend-Zusammenfassung der aktuellen Phishing-Wellen (Phase 4b).

        Aggregiert NUR die Eingabe-Meldungen (kein Erfinden, kein Klassifizieren).
        Eingaben werden injection-gescreent (LLM01), der Output ebenfalls (LLM02),
        der Egress ist fail-closed (CONFIDENTIAL=lokal). Liefert ``""`` bei
        fehlendem/fehlerhaftem LLM — der Aufrufer zeigt dann keinen Trend.
        """
        alle = [*self._screene_eingaben(kmu), *self._screene_eingaben(consumer)]
        if not alle:
            return ""
        if not modell:
            from core.ollama_utils import get_default_model  # noqa: PLC0415

            modell = get_default_model() or ""
            if not modell:
                return ""
        if not ensure_ollama_running() or not self._modell_verfuegbar(modell):
            return ""
        antwort, _fehler = _stream_ollama_json(
            modell,
            PHISHING_TREND_SYSTEM_PROMPT,
            self._bauen_trend_prompt(alle),
            cancel_flag,
        )
        if not antwort:
            return ""
        try:
            data = json.loads(antwort.strip())
        except json.JSONDecodeError:
            return ""
        trend = (
            str(data.get("trend", "") or "").strip() if isinstance(data, dict) else ""
        )
        # LLM02: injizierter Trend-Text wird verworfen (kein Weiterreichen).
        if not trend or detect_injection_signals(trend):
            return ""
        return self._entwerte_text(trend)

    @staticmethod
    def _bauen_trend_prompt(meldungen: list[CyberMeldung]) -> str:
        """User-Prompt fuer die Trend-Session: nummerierte Meldungs-Titel/Texte."""
        zeilen = [f"Datum: {date.today()}", "Aktuelle Warnungen:"]
        for i, m in enumerate(meldungen, 1):
            zeilen.append(f'  {i}. titel="{m.titel}" text="{m.beschreibung[:160]}"')
        return "\n".join(zeilen)

    def _screene_eingaben(self, meldungen: list[CyberMeldung]) -> list[CyberMeldung]:
        """Verwirft Feed-Eintraege mit Prompt-Injection-Signalen (OWASP LLM01).

        Phishing-Feeds sind ein aktiver Angriffsvektor: ein RSS-Eintrag mit
        "Ignoriere alle bisherigen Anweisungen" ist Angriff oder Datenfehler,
        kein legitimer Security-Inhalt. Solche Eintraege fliessen weder in den
        Prompt noch in den Roh-Fallback (vollstaendig verworfen + geloggt).
        """
        sicher: list[CyberMeldung] = []
        for m in meldungen:
            signale = detect_injection_signals(f"{m.titel} {m.beschreibung}")
            if signale:
                log.warning(
                    "Phishing-Eingabe verworfen (Injection-Signale %s, Quelle %s).",
                    signale,
                    getattr(m.quelle, "value", m.quelle),
                )
                continue
            sicher.append(m)
        return sicher

    def _bauen_phishing_prompt(
        self, kmu: list[CyberMeldung], consumer: list[CyberMeldung]
    ) -> str:
        """Baut den User-Prompt aus den beiden Phishing-Gruppen."""
        zeilen: list[str] = [f"Datum: {date.today()}", ""]
        for feld, gruppe in (
            ("phishing_kmu", kmu),
            ("phishing_consumer", consumer),
        ):
            zeilen.append(f"Eingabe {feld}:")
            if gruppe:
                for i, m in enumerate(gruppe, 1):
                    zeilen.append(
                        f'  {i}. titel="{m.titel}" rohtext="{m.beschreibung[:200]}"'
                    )
            else:
                zeilen.append("  (leer)")
            zeilen.append("")
        return "\n".join(zeilen).strip()

    def _parse_phishing(
        self,
        antwort: str,
        kmu: list[CyberMeldung],
        consumer: list[CyberMeldung],
    ) -> dict:
        """Parst die JSON-Antwort der Phishing-Session (Fallback: Rohtexte)."""
        try:
            data = json.loads(antwort.strip())
        except json.JSONDecodeError:
            return {
                "phishing_kmu": [self._phishing_zu_dict(m) for m in kmu],
                "phishing_consumer": [self._phishing_zu_dict(m) for m in consumer],
            }
        return {
            "phishing_kmu": self._bereinige_phishing(data.get("phishing_kmu", []), kmu),
            "phishing_consumer": self._bereinige_phishing(
                data.get("phishing_consumer", []), consumer
            ),
        }

    def _bereinige_phishing(
        self, roh: list, fallback: list[CyberMeldung]
    ) -> list[dict]:
        """Normalisiert LLM-Phishing-Eintraege; Quelle kommt aus dem Fallback.

        Das LLM kennt die Quelle nicht (nur Titel/Rohtext im Prompt) — sie wird
        positionsweise aus den Eingabe-Kandidaten uebernommen. Bei Fehlen faellt
        es auf die Roh-Kandidaten zurueck.
        """
        ergebnis: list[dict] = []
        # Nie mehr Ausgabe- als Eingabe-Eintraege zulassen — verhindert
        # halluzinierte Eintraege fuer eine LEERE Gruppe (Review P2/c1): ist
        # ``fallback`` leer, ist die Grenze 0 -> keine LLM-Eintraege.
        for idx, item in enumerate(roh[: len(fallback)]):
            if not isinstance(item, dict):
                continue
            beschreibung = str(item.get("beschreibung", "") or "").strip()
            if not beschreibung:
                continue
            # OWASP LLM02: kompromittierter LLM-Output -> Roh-Fallback statt
            # potenziell manipuliertem Text (kein Weiterreichen in die GUI).
            if detect_injection_signals(beschreibung):
                log.warning("Phishing-LLM-Output mit Injection-Signal -> Roh-Fallback.")
                beschreibung = fallback[idx].beschreibung if idx < len(fallback) else ""
                if not beschreibung:
                    continue
            quelle = fallback[idx].quelle.value if idx < len(fallback) else ""
            titel = str(item.get("titel", "") or "").strip() or (
                fallback[idx].titel if idx < len(fallback) else ""
            )
            # OWASP LLM02 auch fuer den Titel: injizierter LLM-Titel -> Roh-Titel.
            if titel and detect_injection_signals(titel):
                log.warning("Phishing-LLM-Titel mit Injection-Signal -> Roh-Fallback.")
                titel = fallback[idx].titel if idx < len(fallback) else ""
            ergebnis.append(
                {
                    "titel": titel,
                    "beschreibung": self._entwerte_text(beschreibung),
                    "quelle": quelle,
                }
            )
        if not ergebnis:
            ergebnis = [self._phishing_zu_dict(m) for m in fallback]
        return ergebnis

    @staticmethod
    def _phishing_zu_dict(meldung: CyberMeldung) -> dict:
        """Roh-Phishing-Eintrag (Fallback ohne LLM-Reformulierung)."""
        return {
            "titel": meldung.titel,
            "beschreibung": meldung.beschreibung,
            "quelle": meldung.quelle.value,
        }

    # ------------------------------------------------------------------
    # Kandidatenauswahl und Techstack-Filterung
    # ------------------------------------------------------------------

    def _waehle_kandidaten(
        self,
        cves: list[CveEintrag],
        meldungen: list[CyberMeldung],
        techstack: list[TechStackEintrag],
    ) -> tuple[list[_Kandidat], list[_Kandidat]]:
        """Filtert Roh-Meldungen in zwei Kandidatenlisten.

        Links (techstack-bezogen) enthält nur Einträge die zu einem aktiven
        Techstack-Produkt passen. Rechts (allgemein) enthält die übrigen
        Einträge — unabhängig vom Techstack — nach Relevanz priorisiert
        (KEV > übrige CVEs > RSS).

        Args:
            cves: Alle aktuellen CVEs.
            meldungen: Alle aktuellen RSS-Meldungen.
            techstack: Persönlicher Tech-Stack.

        Returns:
            (techstack_kandidaten, allgemein_kandidaten) — jeweils bis zu
            ``_MAX_PRO_SPALTE`` Einträge.
        """
        # Pro aktivem Eintrag: Anzeigename + (falls vorhanden) CPE-Vendor/Produkt als
        # Match-Token. Hybrid-Matching: gegen die strukturierte CVE-
        # Produktliste mit jeder Token-Länge, gegen den CVE-Freitext nur ab
        # _MIN_PROSE_TOKEN_LEN — beides mit Wortgrenzen (kein "act" in "Content").
        aktive_eintraege = [
            (e.name, _match_tokens(e.name, e.cpe))
            for e in techstack
            if e.aktiv and e.name
        ]

        def matcht_techstack(text: str, produkte_cve: list[str]) -> str:
            """Gibt den Anzeigenamen des ersten passenden Techstack-Eintrags zurück."""
            prose = text.lower()
            struct = " ".join(p.lower() for p in produkte_cve)
            for name, tokens in aktive_eintraege:
                for tok in tokens:
                    if struct and _token_im_text(tok, struct):
                        return name.lower()
                    if len(tok) >= _MIN_PROSE_TOKEN_LEN and _token_im_text(tok, prose):
                        return name.lower()
            return ""

        techstack_kandidaten: list[_Kandidat] = []
        allgemein_kandidaten: list[_Kandidat] = []

        # 1. CVEs — KEVs zuerst, dann weitere CVEs nach CVSS-Score
        kev_cves = [c for c in cves if c.cisa_kev]
        rest_cves = sorted(
            [c for c in cves if not c.cisa_kev],
            key=lambda c: c.cvss_score,
            reverse=True,
        )
        for cve in kev_cves + rest_cves:
            produkt_match = matcht_techstack(cve.beschreibung, cve.betroffene_produkte)
            rohtext = cve.beschreibung[:240]
            if produkt_match and len(techstack_kandidaten) < _MAX_PRO_SPALTE:
                techstack_kandidaten.append(
                    _Kandidat(
                        produkt=produkt_match.title(),
                        cve_id=cve.cve_id,
                        rohtext=rohtext,
                    )
                )
            elif not produkt_match and len(allgemein_kandidaten) < _MAX_PRO_SPALTE:
                produkt = (
                    cve.betroffene_produkte[0] if cve.betroffene_produkte else "CVE"
                )
                allgemein_kandidaten.append(
                    _Kandidat(produkt=produkt, cve_id=cve.cve_id, rohtext=rohtext)
                )

        # 2. RSS-Meldungen auffüllen wenn noch Platz ist
        for m in meldungen:
            if (
                len(techstack_kandidaten) >= _MAX_PRO_SPALTE
                and len(allgemein_kandidaten) >= _MAX_PRO_SPALTE
            ):
                break
            kombi = f"{m.titel} {m.beschreibung}"
            produkt_match = matcht_techstack(kombi, [])
            rohtext = f"{m.titel}. {m.beschreibung[:200]}".strip()
            if produkt_match and len(techstack_kandidaten) < _MAX_PRO_SPALTE:
                techstack_kandidaten.append(
                    _Kandidat(produkt=produkt_match.title(), cve_id="", rohtext=rohtext)
                )
            elif not produkt_match and len(allgemein_kandidaten) < _MAX_PRO_SPALTE:
                allgemein_kandidaten.append(
                    _Kandidat(produkt=m.quelle.value, cve_id="", rohtext=rohtext)
                )

        return techstack_kandidaten, allgemein_kandidaten

    # ------------------------------------------------------------------
    # Consumer-Feed-Kandidaten
    # ------------------------------------------------------------------

    def _lade_consumer_meldungen(self) -> list[ConsumerMeldung]:
        """Laedt Consumer-Feeds gemaess aktuellen Feed-Settings.

        Returns:
            Liste von ConsumerMeldungen (leer bei Netzwerkfehler).
        """
        settings = load_feed_settings()
        aktiv = {
            ConsumerQuelle.BSI: settings.consumer_feeds.get("bsi", True),
            ConsumerQuelle.MSRC: settings.consumer_feeds.get("msrc", True),
            ConsumerQuelle.CHROME: settings.consumer_feeds.get("chrome", True),
            ConsumerQuelle.MOZILLA: settings.consumer_feeds.get("mozilla", True),
        }
        try:
            return ConsumerFeedsService().lade_meldungen(aktiv=aktiv)
        except (OSError, RuntimeError, ConnectionError, ValueError) as exc:
            log.warning("Consumer-Feeds fehlgeschlagen: %s", type(exc).__name__)
            return []

    def _waehle_consumer_kandidaten(
        self,
        meldungen: list[ConsumerMeldung],
    ) -> list[_ConsumerKandidat]:
        """Waehlt die Top-Consumer-Eintraege aus den geladenen Feeds.

        Sortierung: zuerst nach Quell-Prioritaet (MSRC > Chrome > Mozilla >
        BSI), dann nach Datum absteigend. Begrenzt auf ``_MAX_CONSUMER``.

        Args:
            meldungen: Alle geladenen Consumer-Meldungen.

        Returns:
            Bis zu 5 Consumer-Kandidaten.
        """
        sortiert = sorted(
            meldungen,
            key=lambda m: (
                _CONSUMER_PRIO.get(m.quelle, 9),
                -m.veroeffentlicht.timestamp(),
            ),
        )
        kandidaten: list[_ConsumerKandidat] = []
        for m in sortiert[: _MAX_CONSUMER * 2]:
            rohtext = f"{m.titel}. {m.beschreibung[:200]}".strip()
            kandidaten.append(
                _ConsumerKandidat(
                    produkt=m.produkt or m.quelle.value,
                    quelle=m.quelle,
                    rohtext=rohtext,
                    veroeffentlicht=m.veroeffentlicht,
                )
            )
            if len(kandidaten) >= _MAX_CONSUMER:
                break
        return kandidaten

    # ------------------------------------------------------------------
    # Prompt-Aufbau und Antwort-Parsing
    # ------------------------------------------------------------------

    def _bauen_prompt(
        self,
        techstack: list[_Kandidat],
        allgemein: list[_Kandidat],
        consumer: list[_ConsumerKandidat],
    ) -> str:
        """Baut den User-Prompt aus den drei Kandidatenlisten.

        Args:
            techstack: Techstack-relevante Kandidaten.
            allgemein: Allgemeine Kandidaten.
            consumer: Consumer-Software-Kandidaten.

        Returns:
            Strukturierter Prompt-Text.
        """
        zeilen: list[str] = [f"Datum: {date.today()}", ""]
        zeilen.append("Eingabe techstack_eintraege:")
        if techstack:
            for i, k in enumerate(techstack, 1):
                zeilen.append(
                    f'  {i}. produkt="{k.produkt}" cve_id="{k.cve_id}"'
                    f' rohtext="{k.rohtext}"'
                )
        else:
            zeilen.append("  (leer)")
        zeilen.append("")
        zeilen.append("Eingabe allgemein_eintraege:")
        if allgemein:
            for i, k in enumerate(allgemein, 1):
                zeilen.append(
                    f'  {i}. produkt="{k.produkt}" cve_id="{k.cve_id}"'
                    f' rohtext="{k.rohtext}"'
                )
        else:
            zeilen.append("  (leer)")
        zeilen.append("")
        zeilen.append("Eingabe consumer_eintraege:")
        if consumer:
            for i, k in enumerate(consumer, 1):
                zeilen.append(
                    f'  {i}. produkt="{k.produkt}" quelle="{k.quelle.value}"'
                    f' rohtext="{k.rohtext}"'
                )
        else:
            zeilen.append("  (leer)")
        return "\n".join(zeilen)

    def _parse_antwort(
        self,
        antwort: str,
        techstack: list[_Kandidat],
        allgemein: list[_Kandidat],
        consumer: list[_ConsumerKandidat],
    ) -> dict:
        """Parst die JSON-Antwort des LLM.

        Fällt bei Parse-Fehlern auf die Roh-Kandidatentexte zurück — das
        Briefing zeigt dann unformulierte (aber vorhandene) Inhalte.

        Args:
            antwort: JSON-String aus Ollama.
            techstack: Eingabe-Kandidaten links (Fallback).
            allgemein: Eingabe-Kandidaten rechts (Fallback).
            consumer: Eingabe-Consumer-Kandidaten unten (Fallback).

        Returns:
            Dict mit ``techstack_eintraege``, ``allgemein_eintraege`` und
            ``consumer_eintraege``.
        """
        text = antwort.strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            log.warning("Briefing-JSON nicht parsebar — Fallback auf Rohtexte")
            return {
                "techstack_eintraege": [self._kandidat_zu_dict(k) for k in techstack],
                "allgemein_eintraege": [self._kandidat_zu_dict(k) for k in allgemein],
                "consumer_eintraege": [self._consumer_zu_dict(k) for k in consumer],
            }

        return {
            "techstack_eintraege": self._bereinige_eintraege(
                data.get("techstack_eintraege", []), techstack
            ),
            "allgemein_eintraege": self._bereinige_eintraege(
                data.get("allgemein_eintraege", []), allgemein
            ),
            "consumer_eintraege": self._bereinige_consumer(
                data.get("consumer_eintraege", []), consumer
            ),
        }

    def _bereinige_eintraege(
        self,
        roh: list,
        fallback: list[_Kandidat],
    ) -> list[dict]:
        """Normalisiert LLM-Einträge und entfernt wertende Begriffe.

        Args:
            roh: Roh-Liste aus der LLM-Antwort.
            fallback: Eingabe-Kandidaten für Zurückfallen bei Fehlen.

        Returns:
            Liste von Dicts mit Keys ``produkt``, ``cve_id``, ``beschreibung``.
        """
        ergebnis: list[dict] = []
        for item in roh[:_MAX_PRO_SPALTE]:
            if not isinstance(item, dict):
                continue
            produkt = str(item.get("produkt", "") or "").strip()
            cve_id = str(item.get("cve_id", "") or "").strip()
            beschreibung = str(item.get("beschreibung", "") or "").strip()
            if not beschreibung:
                continue
            ergebnis.append(
                {
                    "produkt": produkt,
                    "cve_id": cve_id,
                    "beschreibung": self._entwerte_text(beschreibung),
                }
            )

        if not ergebnis:
            # LLM hat leere Liste geschickt obwohl Kandidaten vorhanden —
            # Rohtexte als Fallback verwenden.
            ergebnis = [self._kandidat_zu_dict(k) for k in fallback]
        return ergebnis

    @staticmethod
    def _kandidat_zu_dict(k: _Kandidat) -> dict:
        """Konvertiert Roh-Kandidat zu Dict (Fallback ohne LLM-Reformulierung)."""
        return {"produkt": k.produkt, "cve_id": k.cve_id, "beschreibung": k.rohtext}

    @staticmethod
    def _consumer_zu_dict(k: _ConsumerKandidat) -> dict:
        """Konvertiert Consumer-Kandidaten zu Dict (Fallback)."""
        return {
            "produkt": k.produkt,
            "quelle": k.quelle.value,
            "beschreibung": k.rohtext,
            "datum": k.veroeffentlicht.strftime("%Y-%m-%d"),
        }

    def _bereinige_consumer(
        self,
        roh: list,
        fallback: list[_ConsumerKandidat],
    ) -> list[dict]:
        """Normalisiert LLM-Consumer-Eintraege inkl. Quell-Badge.

        Args:
            roh: Roh-Liste aus der LLM-Antwort.
            fallback: Kandidaten-Liste fuer Zurueckfallen bei Fehlen.

        Returns:
            Liste von Dicts mit Keys ``produkt``, ``quelle``, ``beschreibung``,
            ``datum``.
        """
        ergebnis: list[dict] = []
        fallback_iter = iter(fallback)
        gueltige_quellen = {q.value for q in ConsumerQuelle}
        for item in roh[:_MAX_CONSUMER]:
            if not isinstance(item, dict):
                continue
            produkt = str(item.get("produkt", "") or "").strip()
            quelle = str(item.get("quelle", "") or "").strip()
            beschreibung = str(item.get("beschreibung", "") or "").strip()
            if not beschreibung:
                continue
            if quelle not in gueltige_quellen:
                # LLM hat die Quelle verschluckt — aus dem Fallback ziehen.
                next_fb = next(fallback_iter, None)
                quelle = next_fb.quelle.value if next_fb else ""
            next_fb = next(
                (k for k in fallback if k.quelle.value == quelle),
                None,
            )
            datum = next_fb.veroeffentlicht.strftime("%Y-%m-%d") if next_fb else ""
            ergebnis.append(
                {
                    "produkt": produkt,
                    "quelle": quelle,
                    "beschreibung": self._entwerte_text(beschreibung),
                    "datum": datum,
                }
            )
        if not ergebnis:
            ergebnis = [self._consumer_zu_dict(k) for k in fallback]
        return ergebnis

    @staticmethod
    def _entwerte_text(text: str) -> str:
        """Entfernt wertende Begriffe und Ausrufezeichen aus dem LLM-Text.

        Sicherheitsnetz falls der LLM trotz System-Prompt dramatisiert.

        Args:
            text: LLM-Beschreibungstext.

        Returns:
            Entschärfter Text.
        """
        ersetzungen = {
            r"\bdringend\w*\b": "",
            r"\bsofort\b": "",
            r"\bkritisch\w*\b": "",
            r"\bgefährlich\w*\b": "",
            r"\bgefahr\w*\b": "",
            r"\balarm\w*\b": "",
            r"\bmassiv\w*\b": "",
            r"\bverheerend\w*\b": "",
        }
        out = text
        for pattern, repl in ersetzungen.items():
            out = re.sub(pattern, repl, out, flags=re.IGNORECASE)
        out = out.replace("!", ".")
        out = re.sub(r"\s{2,}", " ", out).strip(" ,.;")
        if out and not out.endswith("."):
            out += "."
        return out

    def _modell_verfuegbar(self, modell: str) -> bool:
        """Prüft ob das gewünschte Ollama-Modell installiert ist (mit Cache).

        Die ``/api/tags``-Antwort wird pro Modell für ``_MODELL_CACHE_TTL_S``
        Sekunden gecacht — verhindert einen zusätzlichen Ollama-Roundtrip
        vor jedem Streaming-Aufruf.

        Args:
            modell: Gewünschter Modellname.

        Returns:
            True wenn verfügbar oder Tags-API nicht erreichbar (best-effort).
        """
        now = time.monotonic()
        cached = self._modell_cache.get(modell)
        if cached is not None and now - cached[1] < _MODELL_CACHE_TTL_S:
            return cached[0]

        verfuegbar = self._fetch_modell_verfuegbar(modell)
        self._modell_cache[modell] = (verfuegbar, now)
        return verfuegbar

    def _fetch_modell_verfuegbar(self, modell: str) -> bool:
        """Tatsächlicher Tags-API-Call hinter dem Cache."""
        try:
            import requests as req  # noqa: PLC0415

            tags_resp = req.get(OLLAMA_TAGS_URL, timeout=5)
            if tags_resp.status_code != 200:
                return True
            installierte = [
                m.get("name", "") for m in tags_resp.json().get("models", [])
            ]
            if installierte and not any(modell in name for name in installierte):
                log.warning(
                    "Ollama-Modell '%s' nicht verfuegbar. Installierte: %s",
                    modell,
                    installierte[:5],
                )
                return False
        except (OSError, RuntimeError, ConnectionError):
            return True
        return True

    def _bauen_briefing(
        self,
        techstack_eintraege: list[dict],
        allgemein_eintraege: list[dict],
        techstack_leer: bool,
        modell: str,
        consumer_eintraege: list[dict] | None = None,
    ) -> dict:
        """Baut das finale Briefing-Dict mit Metadaten.

        Args:
            techstack_eintraege: Einträge linke Spalte.
            allgemein_eintraege: Einträge rechte Spalte.
            techstack_leer: True wenn kein Techstack konfiguriert ist.
            modell: Verwendetes Ollama-Modell.
            consumer_eintraege: Einträge untere Sektion (verbreitete Software).

        Returns:
            Vollständiges Briefing-Dict.
        """
        return {
            "datum": str(date.today()),
            "generiert_um": datetime.now().strftime("%H:%M"),
            "modell": modell,
            "techstack_leer": techstack_leer,
            "techstack_eintraege": techstack_eintraege,
            "allgemein_eintraege": allgemein_eintraege,
            "consumer_eintraege": consumer_eintraege or [],
        }

    def speichere_briefing(self, briefing: dict) -> None:
        """Persistiert ein (ggf. mit Phishing gemergtes) Briefing-Dict im Cache.

        Oeffentlicher Wrapper um:meth:`_speichere` (c1): Der briefing_tab-Worker
        mergt die parallele Phishing-Session in das CVE-Briefing und persistiert
        das Gesamtergebnis, damit ein Reload aus dem Cache (:meth:`lade_briefing`)
        auch die Phishing-Sektion enthaelt — sonst zeigte die gecachte Ansicht
        bis zur naechsten Generierung kein Phishing.
        """
        self._speichere(briefing)

    def _speichere(self, briefing: dict) -> None:
        """Speichert das Briefing als JSON-Datei.

        Args:
            briefing: Zu speicherndes Briefing-Dict.
        """
        BRIEFING_PATH.parent.mkdir(parents=True, exist_ok=True)
        BRIEFING_PATH.write_text(
            json.dumps(briefing, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

