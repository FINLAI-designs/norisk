"""
advisory_service — Use Cases für den CSAF Advisory-Monitor.

Orchestriert Download, Speicherung, Matching und Abfrage von Advisories.
Alle Netzwerk- und DB-Operationen werden über Interfaces angesprochen.

Schichtzugehörigkeit: application/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime

from core.feed_settings import OFFLINE_HINT, external_fetches_allowed
from core.finlai_paths import finlai_dir
from core.logger import get_logger
from tools.csaf_advisor.application.csaf_downloader import (
    CsafDownloader,
    CsafDownloadError,
)
from tools.csaf_advisor.application.product_matcher import (
    ProductMatcher,
    SoftwareComponent,
)
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.advisory_match import AdvisoryMatch
from tools.csaf_advisor.domain.advisory_repository import IAdvisoryRepository
from tools.csaf_advisor.domain.csaf_provider import CsafProvider

log = get_logger(__name__)


class AdvisoryService:
    """Haupt-Use-Case-Service für den Advisory-Monitor.

    Attributes:
        _repo: Repository für Persistenz.
        _downloader: CSAF-Downloader für Netzwerkabrufe.
        _matcher: ProductMatcher für Advisory-Inventory-Abgleich.
    """

    def __init__(
        self,
        repository: IAdvisoryRepository,
        downloader: CsafDownloader | None = None,
        matcher: ProductMatcher | None = None,
        ki_todo_emitter: object | None = None,
    ) -> None:
        """Initialisiert den Service.

        Args:
            repository: Vollständig konfiguriertes Repository.
            downloader: Optional — wird erstellt wenn None.
            matcher: Optional — wird erstellt wenn None.
            ki_todo_emitter: Optionaler ``KiTodoEmitter``. Default
                wird lazy gebaut.
        """
        self._repo = repository
        self._downloader = downloader or CsafDownloader()
        self._matcher = matcher or ProductMatcher()
        if ki_todo_emitter is None:
            from core.storytelling.ki_todo_emitter import KiTodoEmitter  # noqa: PLC0415
            ki_todo_emitter = KiTodoEmitter()
        self._ki_todo_emitter = ki_todo_emitter

    # ------------------------------------------------------------------
    # Provider-Verwaltung
    # ------------------------------------------------------------------

    def list_providers(self) -> list[CsafProvider]:
        """Gibt alle gespeicherten Provider zurück.

        Returns:
            Liste aller Provider.
        """
        return self._repo.list_providers()

    def add_provider(self, provider: CsafProvider) -> None:
        """Fügt einen neuen (user-definierten) Provider hinzu.

        Args:
            provider: Der neue Provider.
        """
        self._repo.save_provider(provider)
        log.info("Provider hinzugefügt: %s", provider.name)

    def toggle_provider(self, provider_id: str, enabled: bool) -> None:
        """Aktiviert oder deaktiviert einen Provider.

        Args:
            provider_id: Eindeutige Provider-ID.
            enabled: True = aktiv, False = inaktiv.
        """
        provider = self._repo.get_provider(provider_id)
        if provider is None:
            log.warning("Provider nicht gefunden: %s", provider_id)
            return
        provider.enabled = enabled
        self._repo.save_provider(provider)

    def delete_provider(self, provider_id: str) -> None:
        """Löscht einen Provider (nur user-definierte).

        Args:
            provider_id: Eindeutige Provider-ID.
        """
        self._repo.delete_provider(provider_id)
        log.info("Provider gelöscht: %s", provider_id)

    # ------------------------------------------------------------------
    # Advisory-Abruf
    # ------------------------------------------------------------------

    def fetch_all_providers(
        self,
        progress_callback: Callable[[str, int, int, str], None] | None = None,
    ) -> tuple[int, list[str]]:
        """Ruft Advisories von allen aktiven Providern ab und speichert sie.

        Args:
            progress_callback: Optional — wird mit (provider_name, current, total, info)
                               aufgerufen.

        Returns:
            Tuple aus (Anzahl neu gespeicherter Advisories, Liste der Fehlermeldungen).
        """
        if not external_fetches_allowed():
            log.debug("CSAF-Abruf uebersprungen: %s", OFFLINE_HINT)
            return 0, [OFFLINE_HINT]
        providers = [p for p in self._repo.list_providers() if p.enabled]
        if not providers:
            log.info("Keine aktiven Provider konfiguriert.")
            return 0, ["Keine aktiven Provider konfiguriert."]

        total_new = 0
        errors: list[str] = []

        for provider in providers:

            def _cb(
                current: int, total: int, info: str, _p: CsafProvider = provider
            ) -> None:
                if progress_callback:
                    progress_callback(_p.name, current, total, info)

            try:
                advisories = self._downloader.fetch_advisories(
                    provider, progress_callback=_cb
                )
            except CsafDownloadError as exc:
                msg = f"{provider.name}: {exc}"
                log.warning("Fetch fehlgeschlagen — %s", msg)
                errors.append(msg)
                continue
            except Exception as exc:
                msg = f"{provider.name}: Unerwarteter Fehler — {type(exc).__name__}"
                log.error("Fetch fehlgeschlagen — %s: %s", msg, exc)
                errors.append(msg)
                continue

            # Speichern. ``CsafAdvisory`` ist ``frozen=True``, deshalb
            # ueber ``dataclasses.replace`` eine neue Instanz mit dem
            # aktuellen ``fetched_at``-Stempel erzeugen statt das Feld
            # in-place zu setzen (Bug follow-up 2026-05-14: hat
            # sonst ``FrozenInstanceError`` geworfen und den GUI-Sync
            # mit "FEHLER — cannot assign to field 'fetched_at'"
            # abgebrochen).
            now = datetime.now(tz=UTC).isoformat()
            saved = 0
            for advisory in advisories:
                stamped = replace(advisory, fetched_at=now)
                self._repo.save_advisory(stamped)
                saved += 1

            # Provider-Metadaten aktualisieren
            provider.last_fetch = now
            provider.advisory_count = self._repo.advisory_count()
            self._repo.save_provider(provider)

            total_new += saved
            log.info("Provider %s: %d Advisories gespeichert.", provider.name, saved)

        return total_new, errors

    # ------------------------------------------------------------------
    # Advisory-Abfragen
    # ------------------------------------------------------------------

    def list_advisories(
        self,
        severity: str | None = None,
        publisher: str | None = None,
        days: int | None = None,
    ) -> list[CsafAdvisory]:
        """Gibt gefilterte Advisories zurück.

        Args:
            severity: Filter auf Schweregrad (oder None = alle).
            publisher: Filter auf Herausgeber (oder None = alle).
            days: Nur Advisories der letzten N Tage (oder None = alle).

        Returns:
            Sortierte Liste der passenden Advisories (kritisch zuerst).
        """
        advisories = self._repo.list_advisories(
            severity=severity,
            publisher=publisher,
            days=days,
        )
        return sorted(
            advisories,
            key=lambda a: (a.severity_order(), a.current_release),
            reverse=False,
        )

    def get_advisory(self, advisory_id: str) -> CsafAdvisory | None:
        """Gibt ein einzelnes Advisory anhand seiner ID zurück.

        Args:
            advisory_id: Eindeutige Advisory-ID.

        Returns:
            CsafAdvisory oder None.
        """
        return self._repo.get_advisory(advisory_id)

    def advisory_count(self) -> int:
        """Gibt die Gesamtanzahl gespeicherter Advisories zurück.

        Returns:
            Anzahl der Advisories in der Datenbank.
        """
        return self._repo.advisory_count()

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def run_matching(
        self,
        inventory: list[SoftwareComponent],
    ) -> list[AdvisoryMatch]:
        """Gleicht alle gespeicherten Advisories gegen das Inventar ab.

        Löscht vorhandene Matches und berechnet neue.

        Args:
            inventory: Liste der Softwarekomponenten (aus Tech-Stack o. ä.).

        Returns:
            Liste der neuen Treffer.
        """
        self._repo.clear_matches()
        all_advisories = self._repo.list_advisories()

        if not all_advisories:
            log.info("Keine Advisories für Matching vorhanden.")
            return []

        matches = self._matcher.match(all_advisories, inventory)
        for match in matches:
            self._repo.save_match(match)

        log.info("%d Matches gespeichert.", len(matches))

        # (a)+(b): KiTodo-Hook nach Matching-Lauf.
        if matches:
            from tools.csaf_advisor.application.storytelling_adapter import (  # noqa: PLC0415
                emit_to_ki_emitter,
            )
            emit_to_ki_emitter(self._ki_todo_emitter, matches, all_advisories)

        return matches

    def list_matches(self) -> list[AdvisoryMatch]:
        """Gibt alle gespeicherten Treffer zurück.

        Returns:
            Liste aller AdvisoryMatch-Objekte.
        """
        return self._repo.list_matches()

    # ------------------------------------------------------------------
    # Tech-Stack als Inventar laden
    # ------------------------------------------------------------------

    def load_techstack_inventory(self) -> list[SoftwareComponent]:
        """Lädt den TechStack aus der FINLAI Cyber-Dashboard-Konfiguration.

        Falls keine TechStack-Datei vorhanden ist, wird eine leere Liste
        zurückgegeben (kein Fehler — Match-Feature wird dann deaktiviert).

        Returns:
            Liste der SoftwareComponent-Objekte aus dem Tech-Stack.
        """
        stack_path = finlai_dir() / "techstack.json"
        if not stack_path.exists():
            log.info(
                "Kein Tech-Stack unter %s gefunden — Match-Feature deaktiviert.",
                stack_path,
            )
            return []

        import json  # noqa: PLC0415

        try:
            data = json.loads(stack_path.read_text(encoding="utf-8"))
            components = [
                SoftwareComponent(
                    name=entry.get("name", ""),
                    version=entry.get("version", ""),
                    category=entry.get("kategorie", ""),
                )
                for entry in data
                if entry.get("aktiv", True) and entry.get("name", "")
            ]
            log.info("%d Komponenten aus Tech-Stack geladen.", len(components))
            return components
        except Exception as exc:
            log.warning("TechStack-Laden fehlgeschlagen: %s", exc)
            return []


def create_default_advisory_service() -> AdvisoryService:
    """Default-Factory mit dem production-tauglichen Repository.

    Erlaubt Cross-Tool-Konsumenten (z.B. ``cyber_dashboard``), den
    Service zu beziehen ohne ``tools.csaf_advisor.data`` direkt zu
    importieren — analog zu:func:`tools.cyber_dashboard.application.
    dashboard_service.create_default_dashboard_service`.

 follow-up.

    Returns:
        Voll konfigurierter ``AdvisoryService`` mit
        ``AdvisoryRepository``.
    """
    from tools.csaf_advisor.data.advisory_repository_impl import (  # noqa: PLC0415
        AdvisoryRepository,
    )

    return AdvisoryService(repository=AdvisoryRepository())


__all__ = ["AdvisoryService", "create_default_advisory_service"]
