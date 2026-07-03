"""
assistant_tab — Schlanker Inline-Reiter des vereinten FINLAI-Assistenten, C).

Eine Eingabezeile, eine gestreamte Antwortfläche und ein nach Domäne gruppiertes
Quellen-Panel (📚 Handbuch / 🔒 Sicherheit). Das Widget bettet bewusst NICHT die
schwere Standalone-``OllamaPanel`` ein (Plan C: vermeidet die vom Review als P0
markierten Thread-/Session-Divergenz-Risiken), sondern spricht den am
Composition-Root verdrahteten ``UnifiedAssistantService`` über
``core.assistant.provider`` an.

Threading (analog ``tools/ki_integration/gui/chat/chat_view``):
    Der ``_AssistantWorker`` (QThread) ruft ``service.ask`` blockierend auf und
    emittiert je Token ein Qt-Signal. Widgets werden NIEMALS aus dem Worker
    heraus angefasst. Während des Streamings zeigt die Fläche die ROHEN Token
    (Live-Feedback); bei Abschluss wird der Antwortblock durch die GEFILTERTE
    ``AssistantResponse.answer`` ersetzt (Output-Filter, CVE-Disclaimer) — der
    angezeigte Endtext ist damit immer die geprüfte Fassung.

Lebenszyklus::meth:`cleanup` (vom ``HelpDialog.closeEvent`` aufgerufen) bricht
laufende Streams kontrolliert ab und meldet den Theme-Listener ab — gegen den
bekannten Qt-Teardown-Segfault (Exit 134) auf Linux.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import html
from collections.abc import Callable

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.assistant.rag_service import RagService, RetrievedSource
from core.assistant.unified_assistant_service import (
    AssistantResponse,
    UnifiedAssistantService,
)
from core.guardrails.guardrails import DOMAIN_HANDBOOK, DOMAIN_SECURITY
from core.icons import Icons, get_icon
from core.logger import get_logger
from core.widgets.ki_disclaimer import KiDisclaimer

_log = get_logger(__name__)

#: Nachricht ohne registrierte Factory (Dialog außerhalb des App-Kontexts).
_NO_SERVICE_MSG = (
    "Der Assistent ist hier nicht verfügbar. Bitte öffne ihn aus dem "
    "laufenden NoRisk-Hauptfenster."
)
#: Generische Fehlermeldung (unerwarteter Worker-Fehler).
_GENERIC_ERROR_MSG = "Es ist ein Fehler aufgetreten. Bitte versuche es erneut."
_INPUT_PLACEHOLDER = "Frage zu Bedienung oder IT-Sicherheit … (Enter zum Senden)"
#: Domänen-Überschriften des Quellen-Panels (Reihenfolge = Anzeigereihenfolge).
_DOMAIN_LABELS: dict[str, str] = {
    DOMAIN_HANDBOOK: "📚 Handbuch",
    DOMAIN_SECURITY: "🔒 Sicherheit",
}
#: Cleanup-Wartezeit (ms) auf einen laufenden Worker beim Dialog-Schließen.
_CLEANUP_WAIT_MS = 3000

#: Modul-weiter GC-Anker: hält Worker am Leben, die beim Teardown nach
#: ``wait`` noch laufen — ein per Python-GC eingesammelter laufender QThread
#: würde Qt zum Absturz bringen ("Destroyed while thread is running").
_SURVIVING_WORKERS: set[QThread] = set()


def _discard_surviving(worker: QThread) -> None:
    """Entfernt einen ausgelaufenen Survivor aus dem GC-Anker (kein Dauer-Leak)."""
    _SURVIVING_WORKERS.discard(worker)
    worker.deleteLater()


class _StreamAborted(Exception):
    """Stream via ``requestInterruption`` abgebrochen (analog ChatView).

    Bewusst KEINE Subklasse der vom Service gefangenen Typen — propagiert
    dadurch ungefangen bis in:meth:`_AssistantWorker.run`.
    """


class _AssistantWorker(QThread):
    """QThread für eine Assistenz-Anfrage durch die gehärtete Pipeline.

    Baut den Service lazy (über das injizierte Provider-Callable) IM Worker —
    so läuft auch die blockierende Modell-/Index-Auflösung off-thread.

    Signals:
        token: Roh-Token aus dem Streaming.
        done: Abgeschlossene ``AssistantResponse`` (gefilterte Endfassung).
        failed: Fehlermeldung (kein Service / unerwarteter Fehler).
    """

    token = Signal(str)
    done = Signal(object)  # AssistantResponse
    failed = Signal(str)

    def __init__(
        self,
        provider: Callable[[], UnifiedAssistantService | None] | None,
        content: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._provider = provider
        self._content = content

    def run(self) -> None:  # noqa: D102 — QThread-Override
        def _emit(tok: str) -> None:
            if self.isInterruptionRequested():
                raise _StreamAborted
            self.token.emit(tok)

        try:
            service = self._provider() if self._provider is not None else None
            if service is None:
                self.failed.emit(_NO_SERVICE_MSG)
                return
            response = service.ask(self._content, on_token=_emit)
            self.done.emit(response)
        except _StreamAborted:
            _log.debug("Assistenz-Stream abgebrochen (Interruption angefordert).")
        except Exception:  # noqa: BLE001 — UI darf nicht crashen, zeigt Hinweis
            _log.error("Assistenz-Worker-Fehler", exc_info=True)
            self.failed.emit(_GENERIC_ERROR_MSG)


class AssistantTab(QWidget):
    """Schlanker Inline-Assistenz-Reiter für den Handbuch-Dialog, C).

    Args:
        service_provider: Parameterloses Callable, das den (lazy gebauten)
            ``UnifiedAssistantService`` oder ``None`` liefert. Default ist der
            Provider aus ``core.assistant.provider`` — ``None`` außerhalb des
            App-Kontexts (z. B. Test), was das Widget höflich abfängt.
        parent: Optionales Eltern-Widget.
    """

    def __init__(
        self,
        service_provider: Callable[[], UnifiedAssistantService | None] | None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._provider = service_provider
        self._worker: _AssistantWorker | None = None
        #: Abgekoppelte Worker (Stop/Cleanup) bis zu ihrem ``finished``-Signal.
        self._stale: list[_AssistantWorker] = []
        #: Dokumentposition direkt nach dem "FINLAI:"-Label des aktuellen
        #: Antwortblocks — Ankerpunkt für die Filter-Ersetzung bei Abschluss.
        self._answer_anchor: int | None = None
        #: Verhindert doppelten Cleanup (closeEvent + aboutToQuit).
        self._cleaned_up = False
        self._build_ui()
        theme.register_listener(self._apply_theme)
        self._apply_theme()
        self._render_greeting()
        # Garantierter Teardown-Hook: closeEvent feuert NICHT, wenn der Dialog als
        # C++-Kind beim App-Shutdown zerstört wird (tool-gestartete Dialoge ohne
        # Python-Referenz). aboutToQuit bricht dann laufende QThreads ab, bevor Qt
        # einen noch laufenden Thread zerstört (Segfault-Schutz). cleanup ist
        # idempotent; bei normalem Schließen meldet es sich hier wieder ab.
        app = QApplication.instance()
        if app is not None:
            app.aboutToQuit.connect(self.cleanup)

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        intro = QLabel(
            "Stelle Fragen zur Bedienung von NoRisk und zu IT-Sicherheit. "
            "Der Assistent läuft lokal über Ollama — deine Eingaben verlassen das "
            "Gerät nicht."
        )
        intro.setObjectName("assistant_intro")
        intro.setWordWrap(True)
        root.addWidget(intro)

        self._transcript = QTextBrowser()
        self._transcript.setObjectName("assistant_transcript")
        self._transcript.setOpenExternalLinks(False)
        root.addWidget(self._transcript, stretch=1)

        self._sources_title = QLabel("Quellen")
        self._sources_title.setObjectName("assistant_sources_title")
        self._sources_title.setVisible(False)
        root.addWidget(self._sources_title)

        self._sources = QTextBrowser()
        self._sources.setObjectName("assistant_sources")
        self._sources.setMaximumHeight(140)
        self._sources.setVisible(False)
        root.addWidget(self._sources)

        # EU KI-VO Art. 4 — Human-in-the-Loop-Hinweis.
        root.addWidget(KiDisclaimer(text=KiDisclaimer.DEFAULT_TEXT_SECURITY))

        input_row = QHBoxLayout()
        input_row.setSpacing(8)

        self._input = QLineEdit()
        self._input.setObjectName("assistant_input")
        self._input.setPlaceholderText(_INPUT_PLACEHOLDER)
        self._input.returnPressed.connect(self._on_send)
        input_row.addWidget(self._input, stretch=1)

        self._send_btn = QPushButton("Senden")
        self._send_btn.setObjectName("assistant_send_btn")
        self._send_btn.setIcon(get_icon(Icons.ARROW_FORWARD))
        self._send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._send_btn.clicked.connect(self._on_send)
        input_row.addWidget(self._send_btn)

        self._stop_btn = QPushButton("Stopp")
        self._stop_btn.setObjectName("assistant_stop_btn")
        self._stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._stop_btn.clicked.connect(self._on_stop)
        self._stop_btn.setVisible(False)
        input_row.addWidget(self._stop_btn)

        root.addLayout(input_row)

    def focus_input(self) -> None:
        """Setzt den Tastaturfokus ins Eingabefeld (beim Direkt-Öffnen des Reiters)."""
        self._input.setFocus()

    # ------------------------------------------------------------------
    # Senden / Streaming
    # ------------------------------------------------------------------
    def _on_send(self) -> None:
        """Startet eine Anfrage im Worker-Thread (No-op während eines Streams)."""
        if self._worker is not None and self._worker.isRunning():
            return
        text = self._input.text().strip()
        if not text:
            return
        self._input.clear()
        self._append_user(text)
        self._begin_answer()
        self._hide_sources()
        self._set_busy(True)

        worker = _AssistantWorker(self._provider, text)
        worker.token.connect(self._on_token)
        worker.done.connect(self._on_done)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(self._on_finished)
        self._worker = worker
        worker.start()

    def _on_token(self, token: str) -> None:
        """Hängt einen Roh-Token an den aktuellen Antwortblock an."""
        try:
            self._cursor_to_end()
            self._transcript.insertPlainText(token)
        except RuntimeError:
            _log.warning("Transcript bereits zerstört — Token verworfen.")
            return
        self._scroll_bottom()

    def _on_done(self, response: object) -> None:
        """Ersetzt den Roh-Antwortblock durch die gefilterte Endfassung.

        Fail-safe: Bei einem unerwarteten Typ (heute nicht erreichbar — der
        Worker liefert stets eine ``AssistantResponse``) wird der gestreamte
        Roh-Block dennoch ersetzt, damit ungefilterte Modell-Ausgabe NIE als
        dauerhaft angezeigter Text bestehen bleibt-Invariante).
        """
        if isinstance(response, AssistantResponse):
            self._finalize_answer(response.answer)
            self._render_sources(response.sources)
        else:
            _log.error("Unerwarteter done-Typ: %s", type(response).__name__)
            self._finalize_answer(_GENERIC_ERROR_MSG)

    def _on_failed(self, message: str) -> None:
        """Zeigt eine Fehlermeldung anstelle der (leeren) Antwort an."""
        if self._answer_anchor is not None:
            self._finalize_answer(message)
        else:
            self._append_html(f"<br>{html.escape(message)}")

    def _on_finished(self) -> None:
        """Worker beendet: Eingabe wieder freigeben, Anker zurücksetzen."""
        self._answer_anchor = None
        self._worker = None
        self._set_busy(False)

    def _on_stop(self) -> None:
        """Bricht den laufenden Stream ab (Roh-Teilantwort bleibt sichtbar)."""
        self._detach_worker(self._worker)
        self._worker = None
        if self._answer_anchor is not None:
            try:
                self._cursor_to_end()
                self._transcript.insertHtml(" <i>[abgebrochen]</i>")
            except RuntimeError:
                pass
            self._answer_anchor = None
        self._set_busy(False)

    # ------------------------------------------------------------------
    # Transcript-Helfer
    # ------------------------------------------------------------------
    def _cursor_to_end(self) -> None:
        cursor = self._transcript.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self._transcript.setTextCursor(cursor)

    def _append_html(self, fragment: str) -> None:
        try:
            self._cursor_to_end()
            self._transcript.insertHtml(fragment)
        except RuntimeError:
            return
        self._scroll_bottom()

    def _render_greeting(self) -> None:
        c = theme.get()
        self._append_html(
            f'<span style="color:{c.ACCENT};font-weight:600;">FINLAI:</span> '
            "Hallo! Frage mich zur Bedienung von NoRisk oder zu "
            "IT-Sicherheits-Themen."
        )

    def _append_user(self, text: str) -> None:
        c = theme.get()
        sep = "" if self._transcript.document().isEmpty() else "<br><br>"
        self._append_html(
            f'{sep}<span style="color:{c.TEXT_DIM};font-weight:600;">Du:</span> '
            f"{html.escape(text)}<br>"
        )

    def _begin_answer(self) -> None:
        """Setzt das FINLAI-Label und merkt sich die Folgeposition als Anker."""
        c = theme.get()
        self._append_html(
            f'<span style="color:{c.ACCENT};font-weight:600;">FINLAI:</span> '
        )
        self._answer_anchor = self._transcript.textCursor().position()

    def _finalize_answer(self, final_text: str) -> None:
        """Ersetzt den gestreamten Roh-Text (Anker..Ende) durch ``final_text``."""
        if self._answer_anchor is None:
            return
        try:
            cursor = self._transcript.textCursor()
            cursor.setPosition(self._answer_anchor)
            cursor.movePosition(
                QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor
            )
            cursor.removeSelectedText()
            cursor.insertText(final_text)
            self._transcript.setTextCursor(cursor)
        except RuntimeError:
            return
        self._scroll_bottom()

    def _scroll_bottom(self) -> None:
        bar = self._transcript.verticalScrollBar()
        bar.setValue(bar.maximum())

    # ------------------------------------------------------------------
    # Quellen-Panel
    # ------------------------------------------------------------------
    def _render_sources(self, sources: list[RetrievedSource]) -> None:
        """Zeigt die Treffer nach Domäne gruppiert (📚 Handbuch / 🔒 Sicherheit)."""
        if not sources:
            self._hide_sources()
            return
        grouped = RagService.group_by_domain(sources)
        c = theme.get()
        parts: list[str] = []
        for domain, label in _DOMAIN_LABELS.items():
            items = grouped.get(domain)
            if not items:
                continue
            rows = "".join(
                "<li>"
                + html.escape(src.label or "—")
                + (
                    f' <span style="color:{c.TEXT_DIM};">'
                    f"({html.escape(src.source_file)})</span>"
                    if src.source_file
                    else ""
                )
                + "</li>"
                for src in items
            )
            parts.append(
                f'<div style="color:{c.ACCENT};font-weight:600;margin-top:4px;">'
                f"{label}</div><ul style=\"margin:2px 0 6px 0;\">{rows}</ul>"
            )
        if not parts:
            self._hide_sources()
            return
        self._sources.setHtml("".join(parts))
        self._sources_title.setVisible(True)
        self._sources.setVisible(True)

    def _hide_sources(self) -> None:
        self._sources_title.setVisible(False)
        self._sources.setVisible(False)
        self._sources.clear()

    # ------------------------------------------------------------------
    # Busy-Zustand + Worker-Lebenszyklus
    # ------------------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        self._input.setEnabled(not busy)
        self._send_btn.setVisible(not busy)
        self._stop_btn.setVisible(busy)
        if not busy:
            self._input.setFocus()

    def _detach_worker(self, worker: _AssistantWorker | None) -> None:
        """Koppelt einen Worker von der View ab (Stop): nicht-blockierend.

        Der Worker läuft signalfrei aus; die Referenz bleibt bis ``finished``
        erhalten (GC-Schutz), dann wird er verworfen.
        """
        if worker is None:
            return
        worker.requestInterruption()
        self._disconnect_worker(worker)
        if worker.isRunning():
            self._stale.append(worker)
            worker.finished.connect(lambda w=worker: self._discard_stale(w))
            if worker.isFinished():  # Mikro-Race: schon fertig vor connect
                self._discard_stale(worker)
        else:
            worker.deleteLater()

    def _discard_stale(self, worker: _AssistantWorker) -> None:
        if worker in self._stale:
            self._stale.remove(worker)
        worker.deleteLater()

    @staticmethod
    def _disconnect_worker(worker: _AssistantWorker) -> None:
        for signal in (worker.token, worker.done, worker.failed, worker.finished):
            try:
                signal.disconnect()
            except (RuntimeError, TypeError):
                pass

    # ------------------------------------------------------------------
    # Cleanup (vom HelpDialog.closeEvent aufgerufen) + Theme
    # ------------------------------------------------------------------
    def cleanup(self) -> None:
        """Bricht laufende Streams ab und meldet die Listener ab (idempotent).

        Gegen den bekannten Qt-Teardown-Segfault: trennt alle Worker-Signale,
        fordert Interruption an und wartet gebunden auf ein sauberes Ende. Ein
        beim Timeout noch laufender Worker wird im Modul-GC-Anker gehalten (nie
        per GC eingesammelt) und nach seinem ``finished`` wieder freigegeben.

        Setzt bewusst NICHT den (geteilten) Service-Verlauf zurück: der Verlauf
        ist ohnehin ephemer + gekappt, und ein Reset aus dem per-Widget-Cleanup
        würde (a) mit einem evtl. noch laufenden Worker-Thread um ``_history``
        konkurrieren und (b) den Verlauf eines zweiten, gleichzeitig offenen
        Assistenz-Reiters löschen (geteiltes Singleton).
        """
        if self._cleaned_up:
            return
        self._cleaned_up = True
        try:
            theme.unregister_listener(self._apply_theme)
        except (ValueError, RuntimeError):
            pass
        app = QApplication.instance()
        if app is not None:
            try:
                app.aboutToQuit.disconnect(self.cleanup)
            except (RuntimeError, TypeError):
                pass

        workers = [w for w in [self._worker, *self._stale] if w is not None]
        for worker in workers:
            self._disconnect_worker(worker)
            worker.requestInterruption()
        for worker in workers:
            if worker.isRunning() and not worker.wait(_CLEANUP_WAIT_MS):
                _log.warning(
                    "Assistenz-Worker bei Cleanup nicht beendet — wird gehalten."
                )
                _SURVIVING_WORKERS.add(worker)
                # Nach echtem Thread-Ende aus dem Anker entfernen (kein Dauer-Leak).
                worker.finished.connect(lambda w=worker: _discard_surviving(w))
                if worker.isFinished():  # Mikro-Race: schon fertig vor connect
                    _discard_surviving(worker)
            else:
                worker.deleteLater()
        self._worker = None
        self._stale.clear()

    def _apply_theme(self) -> None:
        c = theme.get()
        self.setStyleSheet(
            f"QLabel#assistant_intro {{"
            f" color: {c.TEXT_DIM}; font-size: 12px; background: transparent;"
            f" border: none;"
            f" }}"
            f"QLabel#assistant_sources_title {{"
            f" color: {c.TEXT_MAIN}; font-size: 12px; font-weight: 600;"
            f" background: transparent; border: none; margin-top: 4px;"
            f" }}"
            f"QTextBrowser#assistant_transcript {{"
            f" background: {c.BG_MAIN}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 10px;"
            f" font-size: 13px;"
            f" }}"
            f"QTextBrowser#assistant_sources {{"
            f" background: {c.CARD_BG}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px; padding: 8px;"
            f" font-size: 12px;"
            f" }}"
            f"QLineEdit#assistant_input {{"
            f" background: {c.BG_INPUT}; color: {c.TEXT_MAIN};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 8px 10px; font-size: 13px;"
            f" }}"
            f"QLineEdit#assistant_input:focus {{ border-color: {c.ACCENT}; }}"
            f"QLineEdit#assistant_input:disabled {{ color: {c.TEXT_DIM}; }}"
            f"QPushButton#assistant_send_btn {{"
            f" background: {c.ACCENT}; color: {c.BG_DARK}; border: none;"
            f" border-radius: 4px; padding: 8px 18px; font-size: 13px;"
            f" font-weight: 600;"
            f" }}"
            f"QPushButton#assistant_send_btn:hover {{"
            f" background: {c.ACCENT_DIM}; color: {c.BG_DARK};"
            f" }}"
            f"QPushButton#assistant_stop_btn {{"
            f" background: transparent; color: {c.TEXT_DIM};"
            f" border: 1px solid {c.BORDER}; border-radius: 4px;"
            f" padding: 8px 18px; font-size: 13px;"
            f" }}"
            f"QPushButton#assistant_stop_btn:hover {{"
            f" background: transparent; color: {c.TEXT_MAIN};"
            f" }}"
        )
