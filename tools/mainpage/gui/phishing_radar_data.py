"""
phishing_radar_data — Reines View-Model fuer den Phishing-Radar.

Dieses Modul holt die Daten fuer den ``PhishingRadarBanner`` und das
``PhishingInboxDialog`` und stellt sie als reine Python-Werte
bereit — ohne Qt-Importe. Damit ist es separat testbar (pytest ohne
QApplication) und es bleibt klar, welche Felder das GUI brauchen.

Author: Patrick Riederich
Version: 1.0 (2026-05-28 Phishing-Radar-Refactor)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from core.logger import get_logger

log = get_logger(__name__)


# ----------------------------------------------------------------------
# Gemeinsame Render-Helfer (Qt-frei) — von Banner UND Inbox-Liste genutzt,
# damit Kuerzel/Tooltip/Relativzeit nur an EINER Stelle definiert sind.
# ----------------------------------------------------------------------

_SEVERITY_KUERZEL: dict[str, str] = {
    "kritisch": "KRIT",
    "hoch": "HOCH",
    "mittel": "MITT",
    "niedrig": "NIED",
    "info": "INFO",
}

_SEVERITY_TOOLTIP: dict[str, str] = {
    "kritisch": "KRITISCH — sofort handeln",
    "hoch": "HOCH — zeitnah pruefen",
    "mittel": "MITTEL — im Blick behalten",
    "niedrig": "NIEDRIG — zur Kenntnis nehmen",
    "info": "INFO — rein informativ",
}


def severity_kuerzel(value: str) -> str:
    """Liefert das 4-Zeichen-Kuerzel (KRIT/HOCH/...) zu einem Schweregrad-Value."""

    return _SEVERITY_KUERZEL.get(value, "INFO")


def severity_tooltip(value: str) -> str:
    """Liefert den Volltext-Tooltip zu einem Schweregrad (Barrierefreiheit, SC 1.4.1)."""

    return _SEVERITY_TOOLTIP.get(value, _SEVERITY_TOOLTIP["info"])


def relativ_zeit(zeitpunkt: datetime) -> str:
    """Menschlicher Kurztext fuer ``zeitpunkt`` ('vor 3 Std', 'gestern',...)."""

    jetzt = datetime.now(UTC)
    diff = jetzt - zeitpunkt
    stunden = diff.total_seconds() / 3600
    if stunden < 1:
        return "vor wenigen Minuten"
    if stunden < 24:
        return f"vor {int(stunden)} Std"
    tage = int(stunden / 24)
    if tage == 1:
        return "gestern"
    if tage < 14:
        return f"vor {tage} Tagen"
    return zeitpunkt.strftime("%d.%m.%Y")


@dataclass(frozen=True)
class BannerDaten:
    """Aggregierte Werte fuer den Mainpage-Banner.

    Attributes:
        items: Bis zu 2 frischeste High-Severity-Items
            (Konsumenten-Kategorie, nicht aufgeschoben, letzte 24h).
        neue_24h: Anzahl Items der letzten 24h (Pill-Text-Counter).
        ungelesen: Anzahl ungelesener Items in der Default-Kategorie.
        gesamt: Anzahl aller Items, die im Modal sichtbar sein wuerden
            (Phishing-Konsumenten + Awareness, letzte 7 Tage).
        bereit: True wenn der Service initialisiert werden konnte.
    """

    items: list
    neue_24h: int
    ungelesen: int
    gesamt: int
    bereit: bool


class PhishingRadarViewModel:
    """Holt Banner- und Inbox-Daten aus dem ``DashboardService``.

    Der Service wird optional injiziert — bei ``None`` liefert das
    View-Model leere Defaults (``bereit=False``), damit die GUI
    sauber einen Placeholder zeigt.

    Args:
        dashboard_service: Optionaler ``DashboardService``.
        modus: ``"easy"`` (Default — nur Konsumenten-Quellen) oder
            ``"expert"`` (Konsumenten + Awareness).
    """

    def __init__(
        self,
        dashboard_service: object | None = None,
        modus: str = "easy",
    ) -> None:
        self._service = dashboard_service
        self._modus = modus

    def set_modus(self, modus: str) -> None:
        """Setzt den Anzeige-Modus (``easy`` / ``expert``)."""

        self._modus = modus

    @property
    def modus(self) -> str:
        """Aktueller Anzeige-Modus (``easy`` / ``expert``)."""

        return self._modus

    def kategorien_fuer_modus(self) -> list:
        """Liefert die im aktuellen Modus sichtbaren Phishing-Kategorien.

        Single Source of Truth fuer Banner, Inbox und Quellen-Filter —
        ``easy`` zeigt nur Konsumenten-Quellen, ``expert`` zusaetzlich
        Awareness-Quellen.
        """

        from tools.cyber_dashboard.domain.models import (  # noqa: PLC0415
            Kategorie,
        )

        if self._modus == "expert":
            return [Kategorie.PHISHING_CONSUMER, Kategorie.PHISHING_AWARENESS]
        return [Kategorie.PHISHING_CONSUMER]

    def banner_daten(self) -> BannerDaten:
        """Liefert die Werte fuer den Mainpage-Banner."""

        if self._service is None:
            return BannerDaten(items=[], neue_24h=0, ungelesen=0, gesamt=0, bereit=False)
        try:
            from tools.cyber_dashboard.domain.models import (  # noqa: PLC0415
                Schweregrad,
            )

            kategorien = self.kategorien_fuer_modus()
            items = self._service.lade_phishing_alerts(  # type: ignore[attr-defined]
                kategorien=kategorien,
                min_schweregrad=Schweregrad.HOCH,
                seit_stunden=24,
                nur_ungelesen=False,
                nur_cache=True,
                # AP3: 6 Meldungen — der Banner ist jetzt eine
                # vertikale Spalten-Karte statt 120px-Vollbreiten-Band.
                limit=6,
            )
            neue_24h = self._service.zaehle_seit(kategorien, 24)  # type: ignore[attr-defined]
            ungelesen = self._service.zaehle_ungelesene(kategorien)  # type: ignore[attr-defined]
            gesamt = self._service.zaehle_seit(kategorien, 168)  # type: ignore[attr-defined]
            return BannerDaten(
                items=items,
                neue_24h=neue_24h,
                ungelesen=ungelesen,
                gesamt=gesamt,
                bereit=True,
            )
        except Exception as exc:  # noqa: BLE001 -- Banner darf nie crashen
            log.debug(
                "PhishingRadarViewModel.banner_daten fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return BannerDaten(items=[], neue_24h=0, ungelesen=0, gesamt=0, bereit=False)

    def inbox_items(
        self,
        quellen_filter: list | None = None,
        min_schweregrad_value: str = "mittel",
        seit_stunden: int = 168,
        nur_ungelesen: bool = False,
        limit: int = 100,
    ) -> list:
        """Liefert die Liste fuer das Inbox-Modal.

        ``quellen_filter`` ueberschreibt die Kategorie-Logik, wenn gesetzt.
        """

        if self._service is None:
            return []
        try:
            from tools.cyber_dashboard.domain.models import (  # noqa: PLC0415
                QUELLE_KATEGORIE,
                Schweregrad,
            )

            sg = Schweregrad(min_schweregrad_value)
            kategorien = self.kategorien_fuer_modus()
            if quellen_filter:
                # Reverse-Mapping Quelle->Kategorie: wir nehmen alle
                # Kategorien, die mindestens eine der Filter-Quellen
                # enthalten, um die ServiceAPI-Signatur stabil zu lassen.
                kategorien = list(
                    {QUELLE_KATEGORIE[q] for q in quellen_filter if q in QUELLE_KATEGORIE}
                )
                if not kategorien:
                    return []
            alle = self._service.lade_phishing_alerts(  # type: ignore[attr-defined]
                kategorien=kategorien,
                min_schweregrad=sg,
                seit_stunden=seit_stunden,
                nur_ungelesen=nur_ungelesen,
                nur_cache=True,
                limit=limit,
            )
            if quellen_filter:
                erlaubt = set(quellen_filter)
                alle = [m for m in alle if m.quelle in erlaubt]
            return alle
        except Exception as exc:  # noqa: BLE001 -- Modal darf nie crashen
            log.debug(
                "PhishingRadarViewModel.inbox_items fehlgeschlagen: %s",
                type(exc).__name__,
            )
            return []

    def markiere_gelesen(self, guids: list) -> None:
        """Delegiert an den Service. Defensive No-Op wenn Service None."""

        if self._service is None or not guids:
            return
        try:
            self._service.markiere_gelesen(guids)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "markiere_gelesen fehlgeschlagen: %s", type(exc).__name__
            )

    def markiere_ungelesen(self, guids: list) -> None:
        """Delegiert an den Service."""

        if self._service is None or not guids:
            return
        try:
            self._service.markiere_ungelesen(guids)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "markiere_ungelesen fehlgeschlagen: %s", type(exc).__name__
            )

    def gelesene_guids(self, guids: list) -> set:
        """Liefert die als gelesen markierten GUIDs (fuer Delegate-Render).

        Delegiert an die oeffentliche Service-API ``read_state_fuer`` —
        kein Durchgriff der GUI auf das Repository.
        """

        if self._service is None or not guids:
            return set()
        try:
            return self._service.read_state_fuer(guids)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log.debug("gelesene_guids fehlgeschlagen: %s", type(exc).__name__)
            return set()

    def schiebe_auf(self, guid: str, bis, quelle=None) -> None:  # noqa: ANN001
        """Delegiert an den Service. ``quelle`` spart den Cache-Scan."""

        if self._service is None or not guid:
            return
        try:
            self._service.schiebe_auf(guid, bis, quelle)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            log.debug("schiebe_auf fehlgeschlagen: %s", type(exc).__name__)
