"""
patch_result — Datenstruktur fuer ein vollstaendig aufgeloestes Patch-Item.

Verbesserung 3 (PM-1.1a Nachbesserung). Skelett fuer
:class:`PatchScanResult` — wird in PM-1.6 (Service-Layer) befuellt
und in PM-1.7 (UI-Tabelle) angezeigt.

Lebenszyklus eines Items::

    1. SoftwareItem (PM-1.1a, collector)
    2. + CPE-String (PM-1.2)
    3. + Policy/Channel (PM-1.3, policy_db)
    4. + UpdateRecommendation (PM-1.4, channel-resolver)
    5. + CVE-Liste + Risiko-Score (PM-1.5)
    6. = PatchScanResult (PM-1.6)
    7. → UI / Export (PM-1.7+)

Hinweis: Diese Datei haelt nur das Datenmodell. Konstruktion +
Befuellung erfolgt in PM-1.6 — bis dahin haben einige Felder
Sentinel-Werte (``None``, leeres Tupel, ``False``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from core.patch_collector import SoftwareSource
from core.patch_strategy import DEFAULT_PATCH_STRATEGY, PatchStrategy

if TYPE_CHECKING:
    from core.patch_channel_resolver import ChannelDecision
    from core.patch_cve_matcher import CveMatch

PolicySource = Literal["default", "user"]
"""Quelle der Policy-Entscheidung — kuratierter Default oder User-Override."""

Recommendation = Literal[
    "update_urgent",
    "update",
    "update_available",
    "pinned",
    "notify_only",
    "up_to_date",
    # erweiterte Klassen aus
    # ``core.patch_recommendation_engine``. Werden NICHT von
    # ``_recommend`` gesetzt — nur vom Enrichment-Pass nach CSAF +
    # EOL-Auswertung.
    "workaround_available",
    "eol_no_patch",
    "patch_available_with_csaf_context",
    # User hat fuer diese App ``PatchStrategy.NONE`` gewaehlt —
    # bewusster Opt-out vom Patchen. CVE-Daten bleiben sichtbar (Spalten),
    # nur die Handlungs-Empfehlung + der Upgrade-Button sind deaktiviert.
    "skipped_by_user",
]
"""Empfehlung an den User. Basisset wird vom Channel-Resolver (PM-1.4)
gesetzt; T-060 Rule-Engine ergaenzt drei Klassen mit Workaround-/EOL-/
CSAF-Kontext."""


@dataclass(frozen=True)
class PatchScanResult:
    """Vollstaendig aufgeloestes Patch-Item fuer UI + Export.

    Ein:class:`PatchScanResult` aggregiert alle Information, die
    der Patch-Monitor pro installierter Software gesammelt hat:
    Identifikation, Versionen, Policy, CVE-Daten, Empfehlung.

    Attributes:
        name: Original-Anzeigename aus
:class:`core.patch_collector.SoftwareItem`.
        normalized_name: Kanonischer Name aus
:func:`core.patch_normalizer.normalize_name` —
            Vergleichs-Schluessel fuer Policy/CVE-Lookup.
        vendor: Hersteller-Name (aus winget-Id-Praefix oder Registry
            ``Publisher``-Feld). ``None`` wenn nicht ermittelbar.
        winget_id: winget-Produkt-Id (z.B. ``"Mozilla.Firefox"``).
            ``None`` fuer Registry-only und MSIX-Eintraege.
        source: Quelle des Eintrags
            (:class:`core.patch_collector.SoftwareSource`).
        installed_version: Aktuell installierte Version
            (``"unbekannt"`` wenn nicht ermittelbar).
        available_version: Neueste verfuegbare Version laut
            winget/Vendor. ``None`` wenn nicht abgefragt oder
            unbekannt.
        channel: Update-Kanal aus
:class:`core.patch_policy.PatchPolicy.channel`
            (``"latest"`` / ``"stable"`` / ``"patch_only"`` /
            ``"pinned"`` / ``"notify_only"``).
        policy_source: ``"default"`` oder ``"user"`` — wird in
            PM-1.4 aus:class:`core.patch_policy.PatchPolicy.source`
            uebernommen.
        cve_ids: Liste der zutreffenden CVE-Ids (z.B.
            ``("CVE-2024-1234",)``). Leer bis PM-1.5.
        cvss_max: Hoechster CVSS-Score unter ``cve_ids``. ``None``
            bis PM-1.5 oder wenn keine CVEs gefunden.
        exploit_available: Gibt es einen oeffentlich bekannten
            Exploit fuer einen der ``cve_ids``? ``False`` bis PM-1.5.
        eol: Software ist End-of-Life — Vendor liefert keine
            Updates mehr. ``False`` bis PM-1.5.
        confidence_score: Vertrauensgrad des Policy-Matches:
            ``1.0`` = winget-Id Exact-Match,
            ``0.9`` = Name-Exact-Match,
            ``0.85`` = Hard-Override (:data:`core.patch_normalizer._HARD_OVERRIDES`),
            ``< 0.9`` = Substring-Match (laengster gewinnt).
        recommendation: Aktions-Empfehlung an den User
            (``"update_urgent"`` / ``"update"`` /
            ``"update_available"`` / ``"pinned"`` /
            ``"notify_only"`` / ``"up_to_date"``).
    """

    # App-Identifikation
    name: str
    normalized_name: str
    vendor: str | None
    winget_id: str | None
    source: SoftwareSource

    # Versionen
    installed_version: str
    available_version: str | None

    # Policy
    channel: str
    policy_source: PolicySource

    # CVE-Daten (PM-1.5)
    cve_ids: tuple[str, ...]
    cvss_max: float | None
    exploit_available: bool
    eol: bool

    # Meta
    confidence_score: float
    recommendation: Recommendation

    # Microsoft-Store-Identifier (z. B. "XP8K2L36VP0QMB").
    # Wird vom Patch-Console-Widget genutzt um Store-Apps zur Selektion zu
    # qualifizieren, plus an:class:`UpgradeRequest` durchgereicht damit
    # der Batch-Service den richtigen Executor-Modus waehlt.
    # Default ``None`` haelt aeltere Test-Faelle / persistierte DB-Rows
    # kompatibel — Catalog-Items haben keine store_id.
    store_id: str | None = None

    # Recommendation-Engine-Enrichment (Stop-Step B).
    # ``action_text`` ist der User-lesbare Vorschlag fuer das Detail-
    # Panel (z. B. "Workaround aus CSAF-Advisory BSI-2026-...
    # befolgen"). ``recommendation_source`` ist die Provenance fuer den
    # Audit-Trail (z. B. ``"csaf:CVE-2026-12345"`` oder
    # ``"eol:curated:office_2010"``). Beide bleiben ``None``/leer wenn
    # der Engine-Pass keine Erweiterung anwendet (Basis-Recommendation
    # genuegt).
    action_text: str | None = None
    recommendation_source: str = ""

    # user-eigene Patch-Strategie dieser App. Default STABLE; der
    # DB-Load-Pfad (``_build_result_from_db``) setzt den persistierten Wert,
    # damit die UI das Strategie-Dropdown korrekt vorbelegt.
    patch_strategy: PatchStrategy = DEFAULT_PATCH_STRATEGY

    # 2026-07-02: Rohes „Update verfuegbar"-Signal (Microsoft.WinGet.Client
    # ``IsUpdateAvailable`` bzw. Custom-Source-Check) — UNABHAENGIG von der
    # kanal-/strategie-basierten ``recommendation``. Der Quick-Check-Filter und
    # das Popup zeigen darauf ALLE gefundenen Updates (auch solche auf Kanal
    # ``notify_only``); die ``recommendation`` steuert nur, ob direkt patchbar
    # (Install-Checkbox) oder erst ein Kanalwechsel noetig ist. Default ``False``
    # haelt Alt-Rows/Tests kompatibel.
    is_update_available: bool = False

    @classmethod
    def from_decision_and_cves(
        cls,
        decision: ChannelDecision,
        cves: list[CveMatch],
        available_version: str | None = None,
        *,
        strategy: PatchStrategy = DEFAULT_PATCH_STRATEGY,
    ) -> PatchScanResult:
        """Konstruiert ein:class:`PatchScanResult` aus einer
:class:`core.patch_channel_resolver.ChannelDecision`, der
        zugehoerigen:class:`core.patch_cve_matcher.CveMatch`-Liste
        und der ``available_version`` aus dem PatchService-Lookup-Dict
        (gebaut aus ``SoftwareItem.latest_available``, gefuellt nur vom
        Microsoft.WinGet.Client-Modul-Pfad Cleanup).

        CVSS-Aggregat: ``cvss_max`` ist das Maximum ueber alle CVEs
        (``None`` wenn keine vorhanden). ``exploit_available`` ist
        wahr, sobald **eine** der CVEs einen oeffentlich bekannten
        Exploit hat (CISA KEV o.ae.).

        Recommendation-Logik (in absteigender Prioritaet):

        * ``"pinned"`` wenn ``channel == "pinned"`` — User-Wunsch
          ueberschreibt alles.
        * ``"notify_only"`` wenn ``channel == "notify_only"`` —
          unbekannte Software, manuell pruefen.
        * ``"update_urgent"`` wenn ``cvss_max >= 9.0`` ODER
          ``exploit_available is True`` — egal welche
          ``available_version``.
        * ``"update"`` wenn ``cvss_max >= 4.0`` (Mittelschwere CVEs).
        * ``"update_available"`` wenn ``available_version`` gesetzt
          und ``!= installed_version`` und keine CVE-Funde — Patch
          existiert, aber kein Security-Druck.
        * ``"up_to_date"`` sonst.

        ``strategy == PatchStrategy.NONE`` ueberschreibt das gesamte
        Mapping mit ``"skipped_by_user"`` — der User hat diese App vom
        Patchen ausgenommen. CVE-Daten (``cve_ids``/``cvss_max``/
        ``exploit_available``) werden trotzdem befuellt und bleiben in der
        UI sichtbar; nur die Handlungs-Empfehlung entfaellt.

        Args:
            decision: Aus dem ChannelResolver.
            cves: Aus dem CveMatcher (kann leer sein, wenn ``cpe``
                der Decision ``None`` ist oder kein CVE matcht).
            available_version: Aus dem PatchService-Lookup-Dict
                ``{item.winget_id: item.latest_available}``. ``None``
                wenn das Programm kein winget-Id hat oder kein
                Update verfuegbar ist (Tabular-/Registry-/MSIX-Items
                haben ``latest_available = None``).
            strategy: User-Patch-Strategie dieser App. Default
:data:`core.patch_strategy.DEFAULT_PATCH_STRATEGY`.

        Returns:
            Vollstaendig befuelltes ``PatchScanResult``. ``eol`` ist
            in PM-1.8 noch ``False`` — der EoL-Check folgt in PM-1.9.
        """
        cvss_max = max((c.cvss_score for c in cves), default=None)
        exploit = any(c.exploit_available for c in cves)
        recommendation = _recommend(
            decision, cvss_max, exploit, available_version, strategy=strategy
        )
        vendor = _extract_vendor(decision.cpe)

        return cls(
            name=decision.item.name,
            normalized_name=decision.normalized_name,
            vendor=vendor,
            winget_id=decision.item.winget_id,
            source=decision.item.source,
            installed_version=decision.item.version,
            available_version=available_version,
            channel=decision.channel,
            policy_source=decision.policy_source,
            cve_ids=tuple(c.cve_id for c in cves),
            cvss_max=cvss_max,
            exploit_available=exploit,
            eol=False,  # PM-1.9
            confidence_score=decision.confidence,
            recommendation=recommendation,
            store_id=decision.item.store_id,
            patch_strategy=strategy,
            is_update_available=decision.item.is_update_available,
        )


def _recommend(
    decision: ChannelDecision,
    cvss_max: float | None,
    exploit: bool,
    available_version: str | None = None,
    *,
    strategy: PatchStrategy = DEFAULT_PATCH_STRATEGY,
) -> Recommendation:
    """Empfehlungs-Mapping (:meth:`PatchScanResult.from_decision_and_cves`).

    Bug-Fix 2026-05-12 (Patrick-Smoke): ``IsUpdateAvailable`` ist
    autoritativ statt String-Vergleich. Zwei false-Klassen wurden so behoben:

    * **False-positive `update_available`**: Bei Apps wie Nextcloud oder
      manchen VC++-Redists ist die installierte Version *neuer* als der
      neueste Eintrag im winget-Manifest. ``InstalledVersion`` enthaelt
      dann z. B. ``"> 33.0.3"`` und ``AvailableVersions[0]`` ist ``"33.0.3"``.
      Der frueher genutzte String-Vergleich (`"> 33.0.3" != "33.0.3"`)
      schlug an, obwohl ``IsUpdateAvailable=False`` autoritativ meldet:
      kein Update noetig.
    * **False-negative `up_to_date`**: msstore-Apps haben ``winget_id=None``
      (Store-Produkt-IDs wie ``"XP8K2L36VP0QMB"`` taugen nicht als
      winget-Catalog-ID, siehe ``patch_winget_module.collect_winget_module``).
      Damit war ``available_version`` aus dem PatchService-Lookup
      stets ``None`` und die Branch fiel auf ``up_to_date`` — selbst wenn
      ``IsUpdateAvailable=True`` war (z. B. KeePassXC Store-Version).
    ``strategy == PatchStrategy.NONE`` hat oberste Prioritaet und
    liefert ``"skipped_by_user"`` — der explizite User-Opt-out gewinnt
    gegen jede automatische Klasse (auch ``update_urgent``). Die
    CVE-Risikodaten bleiben am ``PatchScanResult`` erhalten und in der UI
    sichtbar; nur die Handlungs-Empfehlung + der Upgrade-Button entfallen.
    """
    if strategy is PatchStrategy.NONE:
        return "skipped_by_user"
    if decision.channel == "pinned":
        return "pinned"
    if decision.channel == "notify_only":
        return "notify_only"
    if exploit or (cvss_max is not None and cvss_max >= 9.0):
        return "update_urgent"
    if cvss_max is not None and cvss_max >= 4.0:
        return "update"
    # IsUpdateAvailable ist die autoritative Quelle aus dem
    # Microsoft.WinGet.Client-Modul. ``available_version`` bleibt als
    # Display-Information erhalten (Tabellen-Spalte), wird aber NICHT
    # mehr fuer die Recommendation-Entscheidung herangezogen.
    #
    # KEIN ``and cvss_max is None``: die schwerebasierten Klassen (update_urgent
    # ab 9.0, update ab 4.0) sind oben bereits abgehandelt. Ein verfuegbares
    # Update mit NIEDRIG-schwerer CVE (0 < cvss < 4) bleibt trotzdem
    # installierbar → ``update_available``. Der fruehere Guard klemmte genau
    # diese Zeilen faelschlich auf ``up_to_date`` (Live-Test 2026-07-02: 8
    # gefundene Updates, aber 0 im „Updates verfuegbar"-Filter → Popup ging nicht auf).
    if decision.item.is_update_available:
        return "update_available"
    return "up_to_date"


def _extract_vendor(cpe: str | None) -> str | None:
    """Extrahiert das Vendor-Feld aus einem CPE-2.3-String.

    Format: ``cpe:2.3:a:<vendor>:<product>:...``

    Returns:
        Vendor-String, oder ``None`` wenn ``cpe`` ``None`` /
        kein gueltiger CPE / Wildcard-Vendor (``"*"``).
    """
    if not cpe:
        return None
    parts = cpe.split(":")
    if len(parts) < 4:
        return None
    vendor = parts[3]
    if not vendor or vendor == "*":
        return None
    return vendor
