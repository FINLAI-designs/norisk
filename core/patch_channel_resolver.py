"""
patch_channel_resolver — Aggregiert Inventar + Normalizer + PolicyDB
+ CPE-Builder zu einer pro-Item-Entscheidung.

PM-1.4.:class:`ChannelResolver.resolve` ist die Schnitt-
stelle zwischen Sammlern (PM-1.1a) und CVE-Matcher (PM-1.5) sowie
Service-Layer (PM-1.6). Eingang: ein:class:`SoftwareItem`.
Ausgang: ein:class:`ChannelDecision` mit Channel, Confidence,
CPE, Reason — alles, was UI + Audit-Log brauchen.

Aufloesungs-Hierarchie (:meth:`ChannelResolver.resolve`):

1. **User-Override** — vom User gesetzte Policy hat absolute
   Prioritaet, Confidence = 1.0.
2. **Runtime-Force** —:func:`core.patch_normalizer.is_runtime_noise`
   erkennt Redistributables /.NET Runtime / DirectX und erzwingt
   ``patch_only`` mit Confidence 0.90.
3. **Default-Policy-Match** —:class:`core.patch_policy.PolicyDB`
   bzw.:func:`core.patch_normalizer.find_policy_key` liefert einen
   Channel; Confidence skaliert mit der Match-Qualitaet, +0.10 wenn
   ein winget-Id den Match stuetzt (gedeckelt bei 0.95).
4. **Default-Fallback** — kein Match: ``notify_only``, Confidence
   0.0 (UI zeigt das als "manuelle Pruefung noetig").
"""

from __future__ import annotations

from dataclasses import dataclass

from core.logger import get_logger
from core.patch_collector import SoftwareItem
from core.patch_cpe import build_cpe
from core.patch_normalizer import (
    find_policy_key,
    is_runtime_noise,
    normalize_for_matching,
    normalize_name,
)
from core.patch_policy import PatchPolicy, PolicyDB

log = get_logger(__name__)


@dataclass(frozen=True)
class ChannelDecision:
    """Pro-Item-Entscheidung: Channel + Begruendung + CPE.

    Attributes:
        item: Quelle aus:func:`core.patch_collector.collect_all`.
        channel: ``"latest"``/``"stable"``/``"patch_only"``/
            ``"pinned"``/``"notify_only"``.
        policy_source: ``"user"`` (User-Override),
            ``"runtime_force"`` (Runtime/Redistributable erkannt),
            ``"policy"`` (Default-Policy-Match), ``"default"``
            (kein Match → notify_only).
        confidence: ``[0.0, 1.0]`` — wie sicher die Entscheidung
            ist. UI sollte unter 0.5 als "manuell pruefen" anzeigen.
        normalized_name: Anzeige-Form aus
:func:`core.patch_normalizer.normalize_name` (fuer
            Debug + UI).
        cpe: CPE-2.3-String aus:func:`core.patch_cpe.build_cpe`,
            oder ``None`` wenn nicht ableitbar.
        reason: Menschenlesbarer Einzeiler — wird im Detail-Panel
            angezeigt ("Wieso ist diese App auf 'patch_only'?").
    """

    item: SoftwareItem
    channel: str
    policy_source: str
    confidence: float
    normalized_name: str
    cpe: str | None
    reason: str


class ChannelResolver:
    """Faltet PolicyDB + Normalizer + CPE-Builder zu einer Entscheidung.

    Wird typischerweise einmal pro Inventar-Sammeldurchlauf
    instanziiert und ueber:meth:`resolve_batch` auf die komplette
    Liste aus:func:`core.patch_collector.collect_all` angewendet.
    """

    def __init__(self, policy: PolicyDB | None = None) -> None:
        """Initialisiert den Resolver.

        Args:
            policy: Optional vorbereitete:class:`PolicyDB`-Instanz.
                Tests injizieren hier eine Fake-Variante; im
                Produktivpfad bleibt das Default — ein neu
                konstruiertes:class:`PolicyDB`.
        """
        self._policy = policy if policy is not None else PolicyDB()

    @property
    def policy(self) -> PolicyDB:
        """Die zugrunde liegende:class:`PolicyDB`.

        Erlaubt der Application-Schicht (Patch-Inventory-Service), den
        User-Channel-Override + globalen Default zu setzen, ohne eine zweite
        PolicyDB-Instanz (= zweite DB-Verbindung) zu oeffnen.
        """
        return self._policy

    def resolve(self, item: SoftwareItem) -> ChannelDecision:
        """Liefert die:class:`ChannelDecision` fuer ein Item.

        Aufloesungs-Reihenfolge wie im Modul-Docstring beschrieben:
        User-Override > Runtime-Force > Policy-Match > Default.
        Wirft NIE eine Exception nach aussen — selbst wenn die
        DB stirbt, gibt es notfalls eine ``"default"``-Decision
        mit Confidence 0.0 (defensives Fail-Open, UI bleibt
        nutzbar).
        """
        try:
            return self._resolve_impl(item)
        except Exception as e:  # noqa: BLE001 — fail-open by design
            log.exception(
                "ChannelResolver.resolve fehlgeschlagen fuer %r — "
                "fallback auf default. ", item.name
            )
            return ChannelDecision(
                item=item,
                channel="notify_only",
                policy_source="default",
                confidence=0.0,
                normalized_name=normalize_name(item.name),
                cpe=None,
                reason=f"Resolver-Fehler: {e!s}",
            )

    def resolve_batch(
        self, items: list[SoftwareItem]
    ) -> list[ChannelDecision]:
        """Wendet:meth:`resolve` auf eine Liste an, in Reihenfolge."""
        return [self.resolve(item) for item in items]

    # ------------------------------------------------------------------
    # interne Hilfsfunktionen — explizit ausgelagert fuer Testbarkeit
    # ------------------------------------------------------------------

    def _resolve_impl(self, item: SoftwareItem) -> ChannelDecision:
        norm = normalize_name(item.name)
        norm_match = normalize_for_matching(item.name)
        cpe = build_cpe(item)
        policy = self._policy.get(item.name)

        resolved_source, matched_key, match_conf = self._classify(
            item, policy, norm_match
        )
        confidence = _calc_confidence(item, resolved_source, match_conf)
        reason = _build_reason(
            item=item,
            policy=policy,
            resolved_source=resolved_source,
            matched_key=matched_key,
            confidence=confidence,
            norm_match=norm_match,
        )

        return ChannelDecision(
            item=item,
            channel=policy.channel,
            policy_source=resolved_source,
            confidence=confidence,
            normalized_name=norm,
            cpe=cpe,
            reason=reason,
        )

    def _classify(
        self,
        item: SoftwareItem,
        policy: PatchPolicy,
        norm_match: str,
    ) -> tuple[str, str | None, float | None]:
        """Bestimmt resolved_source + (optional) Match-Info.

        ``policy.source`` aus:class:`PolicyDB.get` ist nur
        ``"user"`` oder ``"default"``. Hier rekonstruieren wir die
        feinere ``"runtime_force"``/``"policy"``/``"default"``-
        Aufteilung und holen die match_confidence per zweitem
:func:`find_policy_key`-Aufruf (PolicyDB.get verliert sie).
        """
        if policy.source == "user":
            return ("user", None, None)
        if is_runtime_noise(item.name):
            return ("runtime_force", None, None)
        if policy.channel == "notify_only":
            return ("default", None, None)

        # Reguläres Policy-Match — Confidence rekonstruieren.
        match = find_policy_key(norm_match, self._policy.policy_keys)
        if match is None:
            # Defensiv: PolicyDB hat einen Channel != notify_only
            # zurueckgegeben, aber find_policy_key liefert None.
            # Sollte nicht passieren — zur Sicherheit als
            # "policy" mit niedriger Confidence markieren.
            return ("policy", None, 0.5)
        matched_key, match_conf = match
        return ("policy", matched_key, match_conf)


def _calc_confidence(
    item: SoftwareItem,
    resolved_source: str,
    match_conf: float | None,
) -> float:
    """Confidence-Heuristik aus PM-1.4-Spec.

    * ``"user"`` → 1.0
    * ``"runtime_force"`` → 0.90
    * ``"policy"`` mit winget-Id → ``min(0.95, match_conf + 0.10)``
    * ``"policy"`` ohne winget-Id → ``min(1.0, match_conf)``
    * ``"default"`` → 0.0
    """
    if resolved_source == "user":
        return 1.0
    if resolved_source == "runtime_force":
        return 0.90
    if resolved_source == "default":
        return 0.0
    # "policy" case
    base = match_conf if match_conf is not None else 0.5
    if item.winget_id:
        return round(min(0.95, base + 0.10), 2)
    return round(min(1.0, base), 2)


def _build_reason(
    *,
    item: SoftwareItem,
    policy: PatchPolicy,
    resolved_source: str,
    matched_key: str | None,
    confidence: float,
    norm_match: str,
) -> str:
    """Baut die menschenlesbare Begruendung — wird in der UI gezeigt.

    Beispiele aus PM-1.4-Spec::

        "User-Override: channel=pinned"
        "Runtime-Komponente erkannt → patch_only"
        "Policy-Match 'firefox' via 'mozilla.firefox':
            latest (confidence=0.95)"
        "Substring-Match 'chrome' in 'google chrome':
            latest (confidence=0.78)"
        "Kein Policy-Match → notify_only"
    """
    if resolved_source == "user":
        return f"User-Override: channel={policy.channel}"
    if resolved_source == "runtime_force":
        return f"Runtime-Komponente erkannt → {policy.channel}"
    if resolved_source == "default":
        return f"Kein Policy-Match → {policy.channel}"

    # policy case
    key_label = matched_key or "?"
    if item.winget_id:
        return (
            f"Policy-Match '{key_label}' via '{item.winget_id}': "
            f"{policy.channel} (confidence={confidence:.2f})"
        )
    return (
        f"Substring-Match '{key_label}' in '{norm_match}': "
        f"{policy.channel} (confidence={confidence:.2f})"
    )
