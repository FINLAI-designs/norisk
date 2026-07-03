"""
handbuch_service — Singleton-Service für den RAG-Handbuch-Assistenten.

HandbuchService orchestriert DocumentLoader, ChunkIndexer und
RagRetriever zu einem vollständigen, thread-sicheren Dienst:

    1. initialize: Lädt Chunks → baut TF-IDF-Index → startet Watcher.
    2. ask: Delegiert an RagRetriever.answer.
    3. Watcher: watchdog-Observer überwacht docs/ auf Änderungen
                     und baut den Index bei neuen/geänderten.md-Dateien neu.
    4. shutdown: Stoppt Observer und gibt Ressourcen frei.

Thread-Sicherheit:
    _lock (threading.Lock) schützt _rebuild_index gegen parallele
    Aufrufe aus Watcher-Thread und Haupt-Thread.

Sicherheitsdesign (STRIDE):
    Tampering: Nur.md-Dateien im docs/-Pfad werden beobachtet.
    DoS: Watcher-Neuaufbau ist debounced (1 Sekunde Wartezeit).
    Repudiation: Initialisierung wird geloggt.

Schichtzugehörigkeit: application/ — kein GUI, kein direktes SQL.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import threading
from pathlib import Path

from core.logger import get_logger
from tools.handbuch_assistent.application.chunk_indexer import ChunkIndexer
from tools.handbuch_assistent.application.document_loader import DocumentLoader
from tools.handbuch_assistent.application.rag_retriever import RagRetriever
from tools.handbuch_assistent.domain.models import HandbuchAnswer

_log = get_logger(__name__)

_DEFAULT_MODEL: str | None = None  # wird lazy über get_default_model aufgelöst
_WATCHER_DEBOUNCE_S = 1.0

# Aliase für GUI-Rollen → interne Rollen
_ROLE_ALIASES: dict[str, str] = {
    "user": "anwender",
    "admin": "all",
}


class HandbuchService:
    """Singleton-Service für den Handbuch-Assistenten.

    Verwaltet den vollständigen RAG-Lebenszyklus: Initialisierung,
    Index-Verwaltung, LLM-Abfragen und Dateisystem-Überwachung.

    Attributes:
        _loader: DocumentLoader für Markdown-Dateien.
        _indexer: ChunkIndexer mit TF-IDF-Vektorraum.
        _retriever: RagRetriever mit OllamaClient.
        _observer: watchdog-Observer (oder None wenn nicht verfügbar).
        _lock: Lock für thread-sicheren Index-Neuaufbau.
        _initialized: True nach erfolgreichem initialize-Aufruf.
        _current_role: Zuletzt verwendete Rolle für den Index.
    """

    def __init__(
        self,
        docs_path: Path | None = None,
        model: str | None = None,
    ) -> None:
        """Initialisiert HandbuchService ohne sofortigen Index-Aufbau.

        Args:
            docs_path: Pfad zum Handbuch-Verzeichnis (Standard: docs/).
            model: Standard-LLM-Modell. None = erstes verfügbares Ollama-Modell.
        """
        from core.ollama_utils import get_default_model  # noqa: PLC0415

        self._docs_path = docs_path
        self._model = model or get_default_model() or ""
        self._loader = DocumentLoader(docs_path)
        self._indexer = ChunkIndexer()
        self._observer: object | None = None
        #: Referenz auf den im:func:`_start_watcher` erzeugten
        #: ``_MarkdownHandler``. Wird in:meth:`shutdown` benoetigt, um
        #: dessen Pending-Debounce-``threading.Timer`` zu canceln.
        self._md_handler: object | None = None
        self._lock = threading.Lock()
        self._initialized = False
        self._current_role = "anwender"
        self._current_app_name = ""

        # OllamaClient lazy, damit kein Netzwerkfehler beim Import
        self._retriever: RagRetriever | None = None

    # ------------------------------------------------------------------
    # Öffentliche Schnittstelle
    # ------------------------------------------------------------------

    def initialize(
        self,
        role: str = "anwender",
        model: str | None = None,
        app_name: str = "",
    ) -> None:
        """Lädt Chunks, baut Index und startet Dateisystem-Watcher.

        Idempotent — mehrfache Aufrufe bauen den Index neu auf.

        Args:
            role: Benutzerrolle für die Chunk-Filterung.
            model: LLM-Modell (überschreibt Standard).
            app_name: App-ID für app-spezifische Handbuch-Auswahl
                      (``"finlai"``, ``"norisk"``, ``"automate"``).
        """
        used_model = model or self._model
        self._current_role = role
        self._current_app_name = app_name

        _log.info(
            "HandbuchService: Initialisierung für Rolle='%s' App='%s' Modell='%s'",
            role,
            app_name or "(generisch)",
            used_model,
        )

        self._rebuild_index(role, app_name)
        self._setup_retriever(used_model)
        self._start_watcher()
        self._initialized = True
        _log.info("HandbuchService bereit (%d Chunks)", self._indexer.chunk_count)

    def rebuild(self) -> None:
        """Baut den Index mit der aktuellen Rolle und App neu auf.

        Convenience-Wrapper für die GUI (keine Argumente nötig).
        """
        self._rebuild_index(self._current_role, self._current_app_name)

    def ask(
        self,
        question: str,
        role: str = "anwender",
        model: str | None = None,
        app_name: str = "",
    ) -> HandbuchAnswer:
        """Stellt eine Frage an den Handbuch-Assistenten.

        Unterstützt GUI-Rollen-Aliase (``"user"`` → ``"anwender"``,
        ``"admin"`` → ``"all"``).
        Falls der Service noch nicht initialisiert ist, wird
        initialize automatisch aufgerufen.

        Args:
            question: Nutzerfrage.
            role: Benutzerrolle (``"anwender"``, ``"all"``,
                      ``"entwickler"`` oder Alias ``"user"``/``"admin"``).
            model: LLM-Modell (überschreibt Standard).
            app_name: App-ID für app-spezifische Handbuch-Auswahl
                      (``"finlai"``, ``"norisk"``, ``"automate"``).

        Returns:
            HandbuchAnswer mit Antwort und Metadaten.
        """
        # Alias auflösen
        mapped_role = _ROLE_ALIASES.get(role, role)
        role = mapped_role

        try:
            needs_reinit = (
                not getattr(self, "_initialized", False)
                or role != getattr(self, "_current_role", None)
                or app_name != getattr(self, "_current_app_name", None)
            )
            if needs_reinit:
                self.initialize(role=role, model=model, app_name=app_name)
        except AttributeError:
            # Objekt wurde ohne __init__ erstellt (z. B. via __new__ in Tests)
            pass

        retriever = getattr(self, "_retriever", None)
        if retriever is None:
            return HandbuchAnswer(
                question=question,
                answer="",
                sources=[],
                model=model or getattr(self, "_model", _DEFAULT_MODEL),
                success=False,
                error_message="RagRetriever nicht initialisiert.",
            )

        return retriever.answer(question, model=model, app_name=app_name)

    def shutdown(self) -> None:
        """Stoppt den watchdog-Observer und gibt Ressourcen frei.

        Reihenfolge: Pending-Debounce-Timer canceln, Observer stoppen,
        Lock kurz akquirieren um auf in-flight ``_rebuild_index``-Calls
        zu warten. Letzteres verhindert, dass ein Rebuild-Thread nach
        Test-Teardown weiter loggt (pytest schliesst den Log-Stream
        zwischen Tests → ``ValueError: I/O operation on closed file``).
        """
        # 1. Pending Debounce-Timer canceln, damit kein neuer
        # _rebuild_index nach dem shutdown startet.
        handler = self._md_handler
        if handler is not None:
            timer = handler._timer  # noqa: SLF001 — interne Synchronisation
            if timer is not None:
                try:
                    timer.cancel()
                    timer.join(timeout=2.0)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("HandbuchService-Timer-Cancel: %s", exc)
        self._md_handler = None

        # 2. Observer stoppen (Thread-Joining bis 2s pro stop+join).
        if self._observer is not None:
            try:
                self._observer.stop()  # type: ignore[union-attr]
                self._observer.join()  # type: ignore[union-attr]
            except Exception as exc:  # noqa: BLE001
                _log.warning("HandbuchService-Watcher-Shutdown: %s", exc)
            self._observer = None

        # 3. Auf in-flight _rebuild_index warten — Lock kurz akquirieren.
        # Wenn gerade ein Rebuild laeuft, blockiert das hier bis er
        # fertig ist. Wenn keiner laeuft, ist der Aufruf ein No-Op.
        with self._lock:
            pass

        self._initialized = False
        _log.info("HandbuchService gestoppt")

    @property
    def is_initialized(self) -> bool:
        """True wenn der Service bereit ist."""
        return self._initialized

    @property
    def chunk_count(self) -> int:
        """Anzahl der indizierten Chunks."""
        return self._indexer.chunk_count

    # ------------------------------------------------------------------
    # Interne Methoden
    # ------------------------------------------------------------------

    def _rebuild_index(self, role: str, app_name: str = "") -> None:
        """Lädt Chunks neu und baut den TF-IDF-Index auf.

        Thread-sicher via _lock.

        Args:
            role: Benutzerrolle für die Chunk-Filterung.
            app_name: App-ID für app-spezifische Handbuch-Auswahl.
        """
        with self._lock:
            chunks = self._loader.load_for_role(role, app_name=app_name)
            self._indexer.fit(chunks)
            _log.info(
                "HandbuchService: Index neu aufgebaut — %d Chunks (role=%s, app=%s)",
                len(chunks),
                role,
                app_name or "(generisch)",
            )

    def _setup_retriever(self, model: str) -> None:
        """Erstellt den RagRetriever mit OllamaClient.

        Wenn das konfigurierte Modell nicht lokal installiert ist, wird
        automatisch das erste verfügbare Modell verwendet.

        Args:
            model: Bevorzugter LLM-Modellname.
        """
        try:
            from core.llm.ollama_client import (
                OllamaClient,  # noqa: PLC0415
            )

            client = OllamaClient()

            # Prüfen ob das Modell verfügbar ist — sonst erstes vorhandenes nutzen
            available = [m.name for m in client.get_models()]
            if available and model not in available:
                fallback = available[0]
                _log.warning(
                    "Modell '%s' nicht installiert — verwende '%s' als Fallback.",
                    model,
                    fallback,
                )
                model = fallback

            self._retriever = RagRetriever(
                indexer=self._indexer,
                client=client,
                model=model,
            )
        except ImportError:
            _log.error("OllamaClient (core.llm) nicht importierbar — Handbuch-RAG deaktiviert")

    def _start_watcher(self) -> None:
        """Startet den watchdog-Observer auf dem docs/-Verzeichnis.

        Bei fehlender watchdog-Installation wird eine Warnung ausgegeben
        aber kein Fehler geworfen.
        """
        # Bestehenden Observer stoppen
        if self._observer is not None:
            try:
                self._observer.stop()  # type: ignore[union-attr]
                self._observer.join()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass
            self._observer = None

        if self._docs_path is None:
            base = Path(__file__).resolve().parents[3]
            watch_path = base / "docs"
        else:
            watch_path = self._docs_path

        if not watch_path.is_dir():
            _log.debug("Watcher: docs/-Verzeichnis nicht gefunden — kein Watcher")
            return

        try:
            from watchdog.events import FileSystemEventHandler  # noqa: PLC0415
            from watchdog.observers import Observer  # noqa: PLC0415

            service_ref = self

            class _MarkdownHandler(FileSystemEventHandler):
                """Reagiert auf Änderungen an.md-Dateien."""

                def __init__(self) -> None:
                    super().__init__()
                    self._timer: threading.Timer | None = None

                def on_any_event(self, event: object) -> None:  # type: ignore[override]
                    src = getattr(event, "src_path", "")
                    if not str(src).endswith(".md"):
                        return
                    # Debounce: Index erst nach kurzer Ruhezeit neu aufbauen
                    if self._timer is not None:
                        self._timer.cancel()
                    self._timer = threading.Timer(
                        _WATCHER_DEBOUNCE_S,
                        service_ref._rebuild_index,
                        args=[service_ref._current_role, service_ref._current_app_name],
                    )
                    self._timer.daemon = True
                    self._timer.start()

            observer = Observer()
            handler = _MarkdownHandler()
            observer.schedule(
                handler,
                str(watch_path),
                recursive=False,
            )
            observer.daemon = True
            observer.start()
            self._observer = observer
            self._md_handler = handler
            _log.info("HandbuchService: Watcher gestartet auf %s", watch_path)

        except ImportError:
            _log.warning(
                "watchdog nicht installiert — automatischer Index-Neuaufbau deaktiviert"
            )
        except Exception as exc:
            _log.error("Watcher-Start fehlgeschlagen: %s", exc)
