"""
unified_assistant_service — Orchestrierung des vereinten FINLAI-Assistenten.

EINE Quelle der Wahrheit (Plan, B): legt die gehärtete Schutzpipeline um
EINEN Ollama-Aufruf und routet anhand des 3-wertigen Scope-Gates zwischen
Bedienung (handbook) und IT-Sicherheit (security). Verschmilzt damit die zuvor
getrennte Logik aus ``ChatService`` (Security-Chat) und ``RagRetriever``
(Handbuch) — gleiche Defense-in-Depth-Schichten, domänen-spezifisch geroutet:

    1. Injection-Heuristik auf der Roh-Eingabe (Layer 3, nur Logging/Audit).
    2. Unicode-Normalisierung (Layer 1) + Längen-Cap.
    3. Scope-Gate (Layer 2, 3-wertig): off-topic → Refusal OHNE Modellaufruf;
       sonst Domäne {handbook, security}.
    4. RAG-Grounding (Layer 6) über die domänen-passende Wissensquelle.
    5. Historien-Begrenzung (Layer 4, 13) + domänen-gerouteter System-Prompt
       (Layer 5): Security → ``SECURITY_SYSTEM_PROMPT``, Bedienung →
       ``build_handbuch_system_prompt``.
    6. Ollama-Aufruf (Streaming, Temp 0.3).
    7. Domänen-bewusster Output-Filter (Layer 7): Security behält IOCs/JWTs
       (``filter_security_output``), Handbuch redigiert streng
       (``filter_handbuch_output``); CVE-Disclaimer nur im Security-Pfad.
    8. Audit (nur Metadaten) für BEIDE Domänen.

Der Verlauf ist bewusst EPHEMER (nur In-Memory, gekappt) — kein persistenter
Session-Store (Plan: schlankes UI).

Schichtzugehörigkeit: core/ — kein PySide6. Läuft im QThread (blockierendes
I/O), NIEMALS im Main-Thread aufrufen.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from core.assistant.rag_service import RagService, RetrievedSource
from core.assistant.security_findings import APP_STATE_SOURCE_LABEL, FindingsProvider
from core.audit_log import AuditLogger
from core.guardrails.guardrails import (
    DOMAIN_HANDBOOK,
    DOMAIN_OFFTOPIC,
    DOMAIN_SECURITY,
    ScopeGate,
    detect_injection_signals,
    ensure_cve_disclaimer,
    filter_handbuch_output,
    filter_security_output,
)
from core.guardrails.prompts import (
    SECURITY_SYSTEM_PROMPT,
    UNIFIED_OFFTOPIC_REFUSAL,
    build_grounded_user_message,
    build_handbuch_system_prompt,
)
from core.guardrails.scope_classifier import make_ollama_domain_classifier
from core.llm.ollama_client import IOllamaClient
from core.logger import get_logger
from core.security.validators import MAX_USER_INPUT_CHARS, normalize_user_input

_log = get_logger(__name__)

#: Sichere Default-Temperatur (P0-4): reproduzierbar, KEIN Halluzinationsschutz.
_TEMPERATURE = 0.3

#: Maximale Verlaufs-Nachrichten an Ollama (P1-4, gegen Many-Shot/Token-DoS).
_MAX_HISTORY_MESSAGES = 13

#: Wortgrenze, ab der eine Nachricht als eigenständige Frage (statt kurzer
#: anaphorischer Folgefrage) gilt. Kurze Folgefragen werden fürs Scope-Gate mit
#: dem letzten Nutzer-Turn angereichert (Scope-Stabilität).
_FOLLOWUP_MAX_WORDS = 8

#: Marker für abgebrochene/unvollständige Antworten (P1-7).
_INCOMPLETE_NOTICE = (
    "\n\n_[Antwort unvollständig — die Verbindung wurde unterbrochen. "
    "Bitte werten Sie dies nicht als gesicherte Aussage.]_"
)

#: Audit-Tool-Tag je Domäne (Plan: beide Domänen werden auditiert).
_AUDIT_TOOL: dict[str, str] = {
    DOMAIN_HANDBOOK: "ollama_handbuch",
    DOMAIN_SECURITY: "ollama_security",
}
#: Audit-Tool-Tag für die geblockte Off-Topic-Anfrage (keine Domäne).
_AUDIT_TOOL_BLOCKED = "ollama_assistant"


@dataclass(frozen=True)
class AssistantResponse:
    """Ergebnis einer Assistenz-Anfrage (für UI + Tests).

    Attributes:
        answer: Die gefilterte, anzeigefertige Antwort.
        domain: Behandelte Domäne (``handbook``/``security``/``offtopic``).
        sources: Verwendete Quellen (domänen-getaggt, für das Quellen-Panel).
        blocked: True, wenn off-topic ohne Modellaufruf abgelehnt wurde.
        scope_method: Entscheidungsmethode des Scope-Gates (Audit).
        incomplete: True, wenn der Stream abbrach (Antwort unvollständig).
        filter_labels: Vom Output-Filter ausgelöste Labels (z. B. ``["api_token"]``).
    """

    answer: str
    domain: str
    sources: list[RetrievedSource] = field(default_factory=list)
    blocked: bool = False
    scope_method: str = ""
    incomplete: bool = False
    filter_labels: list[str] = field(default_factory=list)


class UnifiedAssistantService:
    """Vereinter Assistent (Bedienung + IT-Sicherheit) hinter EINER Pipeline.

    Args:
        client: Implementierung des ``IOllamaClient``-Ports.
        rag_service: Domänen-Dispatch für das Retrieval.
        scope_gate: Optionales Scope-Gate (Tests). ``None`` + aktiviertem Gate
            baut der Service pro Anfrage ein LLM-gestütztes 3-wertiges Gate.
        model: Ollama-Modellname (bereits aufgelöst).
        app_display_name: Anzeigename für den Handbuch-System-Prompt.
        enable_scope_gate: Wenn False, wird ohne Routing auf Handbuch behandelt
            (degradierter Modus). Default True.
        audit: Optionaler AuditLogger (Tests). Default: Prozess-Singleton.
        findings_provider: Optionaler App-State-Provider. Wenn gesetzt,
            wird bei Security-Fragen der aktuelle Ergebnis-Stand des eigenen
            Systems (Scores/Findings) als geprüfte Quelle mit-injiziert. ``None``
            (Default/Tests, oder bei nicht-lokalem Ollama) = ohne App-State.
    """

    def __init__(
        self,
        client: IOllamaClient,
        rag_service: RagService,
        *,
        scope_gate: ScopeGate | None = None,
        model: str = "",
        app_display_name: str = "NoRisk by FINLAI",
        enable_scope_gate: bool = True,
        audit: AuditLogger | None = None,
        findings_provider: FindingsProvider | None = None,
    ) -> None:
        self._client = client
        self._rag = rag_service
        self._scope_gate = scope_gate
        self._model = model
        self._app_display_name = app_display_name
        self._enable_scope_gate = enable_scope_gate
        self._audit = audit or AuditLogger()
        self._findings_provider = findings_provider
        #: Ephemerer In-Memory-Verlauf ({"role", "content"}), gekappt.
        self._history: list[dict[str, str]] = []

    # ------------------------------------------------------------------
    @property
    def model(self) -> str:
        """Aufgelöster Ollama-Modellname (leer, wenn nicht ermittelbar).

        Der Provider cacht eine Instanz nur, wenn ein Modell aufgelöst werden
        konnte (Selbstheilung bei zunächst nicht erreichbarem Ollama).
        """
        return self._model

    def reset(self) -> None:
        """Verwirft den ephemeren Gesprächsverlauf (neue Sitzung)."""
        self._history.clear()

    def ask(
        self, content: str, on_token: Callable[[str], None]
    ) -> AssistantResponse:
        """Beantwortet eine Anfrage durch die volle Schutzpipeline (streamend).

        Läuft im QThread — NIEMALS im Main-Thread aufrufen.

        Args:
            content: Roh-Eingabe des Nutzers.
            on_token: Callback je gestreamtem Token.

        Returns:
            ``AssistantResponse`` mit Antwort, Domäne, Quellen und Metadaten.
        """
        raw = content or ""
        signals = detect_injection_signals(raw)
        if signals:
            _log.info("Prompt-Injection-Signale erkannt: %s", ",".join(signals))

        normalized = normalize_user_input(raw)[:MAX_USER_INPUT_CHARS]
        domain, scope_method, blocked = self._classify(normalized)
        if blocked:
            return self._refuse(raw, len(signals), scope_method, on_token)

        sources = self._rag.retrieve(normalized, domain) if normalized.strip() else []
        if domain == DOMAIN_SECURITY:
            sources = self._with_app_state(sources)
        answer, incomplete, labels = self._generate(
            normalized, domain, sources, raw, on_token
        )

        self._remember(normalized, answer)
        self._audit.log_ki_aktion(
            tool=_AUDIT_TOOL.get(domain, _AUDIT_TOOL_BLOCKED),
            aktion="CHAT_ANTWORT",
            modell=self._model or "ollama",
            input_laenge=len(raw),
            output_laenge=len(answer),
            erfolgreich=not incomplete,
            scope_methode=scope_method,
            injection_signale=len(signals),
            output_gefiltert=bool(labels),
        )
        return AssistantResponse(
            answer=answer,
            domain=domain,
            sources=sources,
            blocked=False,
            scope_method=scope_method,
            incomplete=incomplete,
            filter_labels=labels,
        )

    # ------------------------------------------------------------------
    def _classify(self, normalized: str) -> tuple[str, str, bool]:
        """Bestimmt Domäne + Methode; meldet, ob off-topic geblockt wird.

        Returns:
            Tuple (domain, scope_method, blocked). Bei deaktiviertem Gate oder
            leerer Eingabe: Default-Domäne Handbuch, nicht geblockt.
        """
        if not self._enable_scope_gate or not normalized.strip():
            return DOMAIN_HANDBOOK, "disabled", False
        verdict = self._resolve_gate().check(self._contextualize_followup(normalized))
        return verdict.domain, verdict.method, not verdict.in_scope

    def _contextualize_followup(self, normalized: str) -> str:
        """Reichert kurze Folgefragen fürs Scope-Gate mit dem letzten Turn an.

        Ein anaphorischer Nachsatz wie „diese App hat ihn berechnet" trägt keine
        Themen-Marker und würde isoliert als off-topic klassifiziert (dann fälschlich
        abgelehnt). Wir hängen den letzten Nutzer-Turn als KONTEXT voran, damit das
        Gespräch im etablierten Scope bleibt. Nur bei kurzen Nachrichten
        (Folgefrage-Heuristik), um Themen-Drift bei eigenständigen neuen Fragen zu
        vermeiden. Betrifft ausschließlich die Klassifikation — die an das Modell
        gesendete Frage bleibt die ursprüngliche Eingabe.

        Args:
            normalized: Die normalisierte aktuelle Nutzer-Eingabe.

        Returns:
            Den (ggf. mit dem letzten Nutzer-Turn angereicherten) Klassifikationstext.
        """
        if len(normalized.split()) > _FOLLOWUP_MAX_WORDS:
            return normalized
        last_user = next(
            (m["content"] for m in reversed(self._history) if m["role"] == "user"),
            "",
        )
        if not last_user:
            return normalized
        return f"{last_user}\n{normalized}"

    def _with_app_state(self, sources: list[RetrievedSource]) -> list[RetrievedSource]:
        """Stellt den App-State (Scores/Findings) als geprüfte Quelle voran.

        Nur im Security-Pfad und nur wenn ein Provider injiziert ist (bei
        nicht-lokalem Ollama wird keiner verdrahtet). Fail-soft: liefert der
        Provider ``None`` oder wirft er, bleiben die Quellen unverändert.

        Args:
            sources: Die bisherigen RAG-Treffer.

        Returns:
            Die Quellen, ggf. mit dem App-State-Block als erster Quelle.
        """
        if self._findings_provider is None:
            return sources
        try:
            block = self._findings_provider.self_findings_block()
        except Exception as exc:  # noqa: BLE001 — App-State fail-soft, kein harter Stop
            _log.warning("App-State-Provider-Fehler: %s", type(exc).__name__)
            return sources
        if not block:
            return sources
        app_source = RetrievedSource(
            domain=DOMAIN_SECURITY,
            label=APP_STATE_SOURCE_LABEL,
            text=block,
            score=1.0,
            source_file="app_state",
        )
        return [app_source, *sources]

    def _resolve_gate(self) -> ScopeGate:
        """Liefert das injizierte Gate (Tests) oder baut ein 3-wertiges LLM-Gate."""
        if self._scope_gate is not None:
            return self._scope_gate
        return ScopeGate(
            domain_classify_fn=make_ollama_domain_classifier(self._client, self._model),
            default_domain=DOMAIN_HANDBOOK,
        )

    def _generate(
        self,
        normalized: str,
        domain: str,
        sources: list[RetrievedSource],
        raw: str,
        on_token: Callable[[str], None],
    ) -> tuple[str, bool, list[str]]:
        """Ruft Ollama domänen-geroutet auf und filtert die Ausgabe.

        Returns:
            Tuple (gefilterte Antwort, incomplete-Flag, Filter-Labels).
        """
        messages = self._build_messages(normalized, sources)
        system_prompt = (
            SECURITY_SYSTEM_PROMPT
            if domain == DOMAIN_SECURITY
            else build_handbuch_system_prompt(self._app_display_name)
        )
        collected: list[str] = []
        incomplete = False

        def _collect(token: str) -> None:
            collected.append(token)
            on_token(token)

        try:
            full = self._client.chat(
                model=self._model,
                messages=messages,
                on_token=_collect,
                system_prompt=system_prompt,
                temperature=_TEMPERATURE,
            )
        except (OSError, RuntimeError, ConnectionError, ValueError) as exc:
            _log.error("Assistenz-Anfrage fehlgeschlagen: %s", type(exc).__name__)
            full = "".join(collected)
            incomplete = True

        return self._finalize(full, domain, raw, incomplete)

    @staticmethod
    def _finalize(
        full: str, domain: str, raw: str, incomplete: bool
    ) -> tuple[str, bool, list[str]]:
        """Wendet den domänen-bewussten Output-Filter + CVE-Pflicht an (Layer 7)."""
        if domain == DOMAIN_SECURITY:
            filtered, labels = filter_security_output(full)
        else:
            filtered, labels = filter_handbuch_output(full)

        if incomplete:
            filtered = (filtered or "").rstrip() + _INCOMPLETE_NOTICE
        elif not filtered:
            filtered = "[Keine Antwort]"
        elif domain == DOMAIN_SECURITY:
            # Deterministische CVE-Disclaimer-Pflicht NUR im Security-Pfad.
            filtered = ensure_cve_disclaimer(raw, filtered)
        return filtered, incomplete, labels

    def _build_messages(
        self, normalized: str, sources: list[RetrievedSource]
    ) -> list[dict[str, str]]:
        """Baut die gekappte Nachrichtenliste: Verlauf + aktuelle (grounded) Frage."""
        # Platz für die aktuelle Nachricht lassen (gegen Many-Shot, P1-4).
        history = self._history[-(_MAX_HISTORY_MESSAGES - 1) :]
        out: list[dict[str, str]] = [
            {"role": m["role"], "content": m["content"]} for m in history
        ]
        current = self._grounded_message(normalized, sources)
        out.append({"role": "user", "content": current})
        return out

    @staticmethod
    def _grounded_message(normalized: str, sources: list[RetrievedSource]) -> str:
        """Bettet die Quellen als DATEN ein (Spotlighting); sonst reine Frage."""
        if not sources:
            return normalized
        context = "\n\n".join(
            f"[{i}] {s.label}\n{s.text}" for i, s in enumerate(sources, start=1)
        )
        return build_grounded_user_message(context, normalized)

    def _remember(self, normalized: str, answer: str) -> None:
        """Schreibt User-Frage (normalisiert) + Antwort in den ephemeren Verlauf."""
        self._history.append({"role": "user", "content": normalized})
        self._history.append({"role": "assistant", "content": answer})
        # Auf die letzten N Nachrichten kappen.
        self._history = self._history[-_MAX_HISTORY_MESSAGES:]

    def _refuse(
        self,
        raw: str,
        signal_count: int,
        scope_method: str,
        on_token: Callable[[str], None],
    ) -> AssistantResponse:
        """Lehnt eine Off-Topic-Anfrage ab, ohne das Chat-Modell aufzurufen."""
        on_token(UNIFIED_OFFTOPIC_REFUSAL)
        self._audit.log_ki_aktion(
            tool=_AUDIT_TOOL_BLOCKED,
            aktion="CHAT_BLOCKIERT",
            modell=self._model or "ollama",
            input_laenge=len(raw),
            output_laenge=len(UNIFIED_OFFTOPIC_REFUSAL),
            erfolgreich=True,
            geblockt=True,
            schutzschicht="scope_gate",
            scope_methode=scope_method,
            injection_signale=signal_count,
        )
        return AssistantResponse(
            answer=UNIFIED_OFFTOPIC_REFUSAL,
            domain=DOMAIN_OFFTOPIC,
            blocked=True,
            scope_method=scope_method,
        )
