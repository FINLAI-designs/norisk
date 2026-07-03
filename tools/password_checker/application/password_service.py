"""password_service — Orchestriert Passwort-Analyse und HIBP-Prüfung.

Kombiniert die pure Domain-Analyse (password_analyzer) mit dem
optionalen HIBP-Netzwerk-Check.

Security:
    - Das Passwort wird nur im RAM gehalten und nicht weitergespeichert.
    - HIBP-Check ist optional (Netzwerk-Fehler blockieren nicht).

Schichtzugehörigkeit: application/ — kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.feed_settings import external_fetches_allowed
from core.logger import get_logger
from tools.password_checker.domain.models import (
    PasswordCheckResult,
    PasswordPolicy,
)
from tools.password_checker.domain.password_analyzer import (
    analysiere_passwort,
    staerke_bei_breach,
)
from tools.password_checker.domain.policy_templates import (
    ALLE_VORLAGEN,
    POLICY_BSI,
)

_log = get_logger(__name__)


class PasswordService:
    """Orchestriert Passwort-Stärke-Analyse + optionalen HIBP-Breach-Check.

    Attributes:
        _hibp: Optionaler HIBPClient (None = kein Breach-Check).
    """

    def __init__(self, hibp_client=None, last_check_repo=None) -> None:
        """Initialisiert den PasswordService.

        Args:
            hibp_client: HIBPClient-Instanz oder None (dann kein Breach-Check).
            last_check_repo: Optionales LastCheckRepository (Cockpit-Kachel-
                Persistenz des Prüf-Zeitpunkts); Default lazy beim ersten
                ``pruefen``.
        """
        self._hibp = hibp_client
        self._last_check_repo = last_check_repo

    def pruefen(
        self,
        passwort: str,
        policy: PasswordPolicy | None = None,
        mit_breach_check: bool = True,
    ) -> PasswordCheckResult:
        """Führt die vollständige Passwort-Prüfung durch.

        Args:
            passwort: Das zu prüfende Passwort.
            policy: Policy (None = BSI Standard).
            mit_breach_check: HIBP-Breach-Check aktivieren (benötigt Netzwerk).

        Returns:
            PasswordCheckResult mit allen Analyse-Ergebnissen.
        """
        verwendete_policy = policy or POLICY_BSI
        result = analysiere_passwort(passwort, verwendete_policy)

        # HIBP-Leak-Abgleich nur, wenn externe Abrufe erlaubt sind
        # (Offline-Modus -> kein SHA-1-Praefix an api.pwnedpasswords.com).
        if mit_breach_check and self._hibp is not None and external_fetches_allowed():
            kompromittiert, vorkommnisse = self._hibp.ist_kompromittiert(passwort)
            result.breach_vorkommnisse = vorkommnisse if kompromittiert else 0
            # F2: Ein HIBP-Treffer kappt das Stärke-Verdikt hart — sonst
            # zeigt ein in Datenpannen gefundenes, aber entropie-„starkes"
            # Passwort fälschlich „STARK" (Score und Breach waren entkoppelt).
            result.staerke, result.score = staerke_bei_breach(
                result.staerke, result.score, result.breach_vorkommnisse
            )

        self._markiere_geprueft()
        return result

    def _markiere_geprueft(self) -> None:
        """Best-effort: Zeitpunkt der Prüfung persistieren (Cockpit-Kachel).

        Speichert NUR den Zeitpunkt (kein Passwort). Fehler nie nach aussen —
        die Prüfung darf an der Persistenz nie scheitern.
        """
        try:
            repo = self._last_check_repo
            if repo is None:
                from tools.password_checker.data.last_check_repository import (  # noqa: PLC0415
                    LastCheckRepository,
                )

                repo = LastCheckRepository()
            repo.markiere_geprueft()
        except Exception as exc:  # noqa: BLE001 -- Persistenz nie blockierend
            _log.debug(
                "Passwort-Last-Check-Persistenz uebersprungen (%s)",
                type(exc).__name__,
            )

    def lade_policy(self, vorlage_name: str) -> PasswordPolicy:
        """Lädt eine Policy-Vorlage anhand ihres Anzeigenamens.

        Args:
            vorlage_name: Anzeigename der Vorlage (z.B. "BSI Grundschutz").

        Returns:
            Entsprechende PasswordPolicy oder BSI als Fallback.
        """
        for policy in ALLE_VORLAGEN.values():
            if policy.name == vorlage_name:
                return policy
        return POLICY_BSI
