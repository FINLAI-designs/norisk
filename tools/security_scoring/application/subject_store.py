"""subject_store — SubjectStore-Adapter über die SystemProfile-Verwaltung.

Implementiert den core-Port:class:`core.security_subject.ports.SubjectStore`,
indem er die bestehende:class:`ManageProfilesUseCase` (SystemProfile-CRUD über
``system_profiles``) wiederverwendet und ``SystemProfile`` ↔:class:`Subject`
mappt. Kein paralleler Datenpfad — die ``system_profiles``-Tabelle bleibt der
einzige Owner;eflexions-Regel 2: bestehende Struktur nutzen
statt zweite anzulegen).

``Subject.branche``/``groesse`` werden über die additiven ``system_profiles``-
Spalten persistiert, Migrations-Schritt) und via ``update_stammdaten``
gepflegt (z. B. beim Übernehmen der Firma aus einem Kunden-Audit).

Schichtzugehörigkeit: application/ — Use-Case-Orchestrierung, kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from dataclasses import replace

from core.logger import get_logger
from core.security_subject.models import NutzungsSignale, Subject, SubjectKind
from core.security_subject.resolver import (
    create_avv_reference_check,
    create_subject_cleanup_hooks,
    create_usage_signal_provider,
)
from core.security_subject.scoping_constants import anhang_fuer
from core.security_subject.w1_profil import W1_UNCHANGED, Segment
from tools.security_scoring.application.tech_stack.manage_profiles_use_case import (
    ManageProfilesUseCase,
    create_default_manage_profiles_use_case,
)
from tools.security_scoring.domain.org_security import (
    NaVorbelegung,
    OrgAssessment,
    konkret_beantwortete_keys,
    nutzungs_na_keys,
    profil_na_keys,
)
from tools.security_scoring.domain.tech_stack.entities import SystemProfile

log = get_logger(__name__)

#: Gueltige persistierte Segment-Werte: alle Enum-Values plus ``""`` (= nicht
#: erfasst). ``None`` ist KEIN Wert, sondern der „unveraendert"-Marker in
#::meth:`ScoringSubjectStore.update_profile_w1`.
_VALID_SEGMENTS = frozenset({s.value for s in Segment} | {""})


def create_default_subject_store() -> ScoringSubjectStore | None:
    """Default-Factory mit production-tauglichem Use Case.

    Erlaubt Cross-Tool-Konsumenten (customer_audit, Dashboard), den Store
    über den core-Port zu beziehen, ohne ``security_scoring``-Interna zu
    importieren.

    Returns:
        Einsatzbereiter Store oder ``None``, wenn das zugrunde liegende
        Repository nicht initialisierbar ist (z. B. fehlender SQLCipher-
        Schlüssel) — Fehlerbehandlung bleibt fail-soft beim Aufrufer.
    """
    use_case = create_default_manage_profiles_use_case()
    if use_case is None:
        return None
    return ScoringSubjectStore(use_case)


def _eigenes_subjekt() -> Subject | None:
    """Löst das eigene Subjekt auf (fail-soft).

    Returns:
        Das eigene Subjekt oder ``None``, wenn kein Store/Subjekt verfügbar ist
        oder ein Fehler auftritt — die Aufrufer behandeln das als „keine
        Vorbelegung".
    """
    try:
        store = create_default_subject_store()
        return store.get_self() if store is not None else None
    except Exception:  # noqa: BLE001 — fail-soft: ohne Profil keine Vorbelegung
        log.debug("_eigenes_subjekt: SubjectStore nicht verfügbar")
        return None


def _eigene_nutzungssignale(subject_id: str) -> NutzungsSignale:
    """Liest die Cross-Tool-Nutzungssignale des eigenen Subjekts (fail-soft).

    Bezieht den:class:`UsageSignalProvider` über den core-Resolver (lazy →
    customer_audit, kein tool→tool). Bei fehlendem Provider oder Fehler leere
    Signale (alle ``None``) → kein Auto-N/A No-op-Garantie).

    Args:
        subject_id: UUID des eigenen Subjekts.

    Returns:
        Tri-state:class:`NutzungsSignale`.
    """
    try:
        provider = create_usage_signal_provider()
        if provider is None:
            return NutzungsSignale()
        return provider.signale_fuer(subject_id)
    except Exception:  # noqa: BLE001 — fail-soft: ohne Signal kein Auto-N/A
        log.debug("_eigene_nutzungssignale: UsageSignalProvider nicht verfügbar")
        return NutzungsSignale()


def eigenes_na_vorbelegung(
    letztes_assessment: OrgAssessment | None = None,
) -> NaVorbelegung:
    """Vollständige N/A-Vorbelegung für das eigene Subjekt Ebene 3).

    Faltet drei Quellen zusammen (alle fail-soft):
      1. **FTE-Profil** (Ebene 2) via:func:`profil_na_keys`.
      2. **Nutzungssignale** (Ebene 3) aus dem jüngsten SELF-Sovereignty-Audit
         (Cross-Tool über den core-Resolver).
      3. **Konflikt-Regel:** bereits konkret (JA/NEIN) beantwortete Fragen des
         jüngsten Assessments werden nie erneut auto-N/A-vorbelegt — so bremst
         eine veraltete Nicht-Nutzung den Nutzer nicht aus (z. B. späterer
         M365-Zukauf; siehe §Temporale Reversibilität).

    Args:
        letztes_assessment: Das jüngste gespeicherte Org-Assessment (für die
            Konflikt-Regel) oder ``None`` (keine konkrete Vorhistorie).

    Returns:
:class:`NaVorbelegung` mit finaler N/A-Menge, Nutzungs-Teilmenge (Tooltip)
        und Audit-Datum. Ohne eigenes Subjekt eine leere Vorbelegung.
    """
    subjekt = _eigenes_subjekt()
    if subjekt is None:
        return NaVorbelegung()
    fte_na = profil_na_keys(subjekt.fte)
    signale = _eigene_nutzungssignale(subjekt.subject_id)
    konkret = (
        konkret_beantwortete_keys(letztes_assessment)
        if letztes_assessment is not None
        else frozenset()
    )
    return nutzungs_na_keys(fte_na, signale, konkret)


class ScoringSubjectStore:
    """SubjectStore-Adapter über:class:`ManageProfilesUseCase`."""

    def __init__(self, use_case: ManageProfilesUseCase) -> None:
        """Initialisiert den Adapter.

        Args:
            use_case: Use Case für die SystemProfile-Verwaltung.
        """
        self._uc = use_case

    # ------------------------------------------------------------------
    # Lesen
    # ------------------------------------------------------------------

    def get(self, subject_id: str) -> Subject | None:
        """Lädt ein Subjekt per ID (oder ``None``)."""
        profile = self._uc.get_profile_by_id(subject_id)
        return _to_subject(profile) if profile else None

    def get_self(self) -> Subject | None:
        """Gibt das eigene Subjekt zurück (ohne es anzulegen)."""
        profile = self._uc.get_own_system()
        return _to_subject(profile) if profile else None

    def list_all(self) -> list[Subject]:
        """Listet alle Subjekte (eigenes zuerst, dann alphabetisch)."""
        return [_to_subject(p) for p in self._uc.get_all_profiles()]

    # ------------------------------------------------------------------
    # Schreiben (idempotent)
    # ------------------------------------------------------------------

    def ensure_self_subject(self, name: str) -> Subject:
        """Stellt sicher, dass genau ein eigenes Subjekt existiert."""
        return _to_subject(self._uc.ensure_own_system(name))

    def find_or_create_client(self, name: str) -> Subject:
        """Findet ein Kunden-Subjekt per Name oder legt es neu an."""
        return _to_subject(self._uc.find_or_create_customer(name))

    def update_stammdaten(
        self,
        subject_id: str,
        *,
        branche: str | None = None,
        groesse: str | None = None,
        contact: str | None = None,
    ) -> None:
        """Aktualisiert gesetzte Stammdaten-Felder eines Subjekts.

        Liest das Profil, ersetzt nur die übergebenen Felder und schreibt
        über den bestehenden Update-Pfad zurück (kein Voll-Zeilen-Clobbering
        unbeteiligter Felder).
        """
        profile = self._uc.get_profile_by_id(subject_id)
        if profile is None:
            log.warning("update_stammdaten: Subjekt %s unbekannt", subject_id)
            return
        updated = replace(
            profile,
            branche=profile.branche if branche is None else branche,
            groesse=profile.groesse if groesse is None else groesse,
            contact=profile.contact if contact is None else contact,
        )
        self._uc.update_profile(updated)

    def update_scoping_profile(
        self,
        subject_id: str,
        *,
        fte: int | None = None,
        umsatz_eur: int | None = None,
        bilanzsumme_eur: int | None = None,
        sektor_key: str | None = None,
        rolle: str | None = None,
    ) -> None:
        """Aktualisiert die Einstiegs-Scoping-Felder; nur gesetzte Felder).

        Liest das Profil, ersetzt nur die übergebenen Felder und schreibt über
        den bestehenden Update-Pfad zurück (kein Voll-Zeilen-Clobbering).

        ``nis2_anhang`` wird hier deterministisch aus ``sektor_key`` abgeleitet
        (Single Write Path) — nie unabhängig gesetzt, damit der denormalisierte
        Anhang nicht zum Sektor desynchronisieren kann.
        """
        profile = self._uc.get_profile_by_id(subject_id)
        if profile is None:
            log.warning("update_scoping_profile: Subjekt %s unbekannt", subject_id)
            return
        updated = replace(
            profile,
            fte=profile.fte if fte is None else fte,
            umsatz_eur=profile.umsatz_eur if umsatz_eur is None else umsatz_eur,
            bilanzsumme_eur=(
                profile.bilanzsumme_eur if bilanzsumme_eur is None else bilanzsumme_eur
            ),
            sektor_key=profile.sektor_key if sektor_key is None else sektor_key,
            nis2_anhang=(
                profile.nis2_anhang if sektor_key is None else anhang_fuer(sektor_key)
            ),
            rolle=profile.rolle if rolle is None else rolle,
        )
        self._uc.update_profile(updated)

    def update_profile_w1(
        self,
        subject_id: str,
        *,
        segment: str | None = None,
        hat_eigene_website: int | None = W1_UNCHANGED,
        hat_eigene_api: int | None = W1_UNCHANGED,
        ist_entwickler: int | None = W1_UNCHANGED,
        hat_server_infrastruktur: int | None = W1_UNCHANGED,
    ) -> None:
        """Aktualisiert die W1-Interview-Profilfelder; nur gesetzte Felder).

        Liest das Profil, ersetzt nur die übergebenen Felder und schreibt über
        den bestehenden Update-Pfad zurück (kein Voll-Zeilen-Clobbering
        unbeteiligter Felder).

        ``segment`` nutzt ``None`` als „unverändert"-Marker (Segment ist nie
        ``None``, sondern ``""`` wenn nicht erfasst). Die tri-state Booleans
        nutzen den Sentinel:data:`W1_UNCHANGED` (``-1``) als „unverändert":
        ``None`` ist dort ein gültiger Wert (= zurücksetzen auf „nicht erfasst")
        und kann deshalb nicht „unverändert" bedeuten.

        Args:
            subject_id: UUID des (eigenen) Subjekts.
            segment: Segment-Schlüssel oder ``None`` (unverändert).
            hat_eigene_website: 0/1/``None`` oder Sentinel (unverändert).
            hat_eigene_api: 0/1/``None`` oder Sentinel (unverändert).
            ist_entwickler: 0/1/``None`` oder Sentinel (unverändert).
            hat_server_infrastruktur: 0/1/``None`` oder Sentinel (unverändert).

        Raises:
            ValueError: Wenn ``segment`` gesetzt (≠ ``None``), aber kein gültiger
:class:`Segment`-Wert bzw. ``""`` ist, fail-closed).
        """
        # Segment-Wert fail-closed gegen das Enum validieren, bevor er
        # persistiert wird (heute kommen nur Dropdown-Werte an; der Guard schuetzt
        # gegen kuenftige Aufrufer mit Freitext/Nicht-String). ``None`` = unveraendert.
        if segment is not None and (
            not isinstance(segment, str) or segment not in _VALID_SEGMENTS
        ):
            raise ValueError(
                f"Ungueltiges Segment fuer update_profile_w1: {segment!r}. "
                f"Erlaubt: {sorted(_VALID_SEGMENTS)} (oder None = unveraendert)."
            )
        profile = self._uc.get_profile_by_id(subject_id)
        if profile is None:
            log.warning("update_profile_w1: Subjekt %s unbekannt", subject_id)
            return
        updated = replace(
            profile,
            segment=profile.segment if segment is None else segment,
            hat_eigene_website=(
                profile.hat_eigene_website
                if hat_eigene_website == W1_UNCHANGED
                else hat_eigene_website
            ),
            hat_eigene_api=(
                profile.hat_eigene_api
                if hat_eigene_api == W1_UNCHANGED
                else hat_eigene_api
            ),
            ist_entwickler=(
                profile.ist_entwickler
                if ist_entwickler == W1_UNCHANGED
                else ist_entwickler
            ),
            hat_server_infrastruktur=(
                profile.hat_server_infrastruktur
                if hat_server_infrastruktur == W1_UNCHANGED
                else hat_server_infrastruktur
            ),
        )
        self._uc.update_profile(updated)

    # ------------------------------------------------------------------
    # Löschen (DSGVO Art. 17 Orphan-Cleanup)
    # ------------------------------------------------------------------

    def delete_subject_if_unreferenced(self, subject_id: str) -> bool:
        """Löscht ein verwaistes Kunden-Subjekt (DSGVO Art. 17).

        Prüft die scoring-eigenen Referenzen (Scores/Hardening/Org — per
        ``subject_id`` bzw. defensiv per Name) und löscht das
        ``system_profiles``-Profil nur, wenn keine bestehen. Das eigene System
        wird nie gelöscht. Der audit-seitige Referenz-Check liegt beim Aufrufer.
        """
        if not subject_id:
            return False
        profile = self._uc.get_profile_by_id(subject_id)
        if profile is None:
            return False
        self_subject = self.get_self()
        if self_subject is not None and self_subject.subject_id == subject_id:
            return False  # eigenes System nie löschen

        # DSGVO-Loesch-Block E4): ein Kunde mit aufbewahrungspflichtigen
        # Kunden-AVVs darf NICHT verworfen werden. Cross-Tool ueber den core-
        # Resolver (kein security_scoring -> supply_chain_monitor-Import).
        # FAIL-CLOSED: Ist der Checker nicht verfuegbar (DEK/DB-Fehler), kann die
        # Aufbewahrungspflicht nicht geprueft werden -> Loeschung verweigern, statt
        # eine moeglicherweise belegte Identitaet unwiederbringlich zu loeschen
        # (FINLAI-Invariante fail-closed; das Risiko ist nur eine aufgeschobene
        # Bereinigung, nicht ein verwaister Vertragsbeleg).
        avv_check = create_avv_reference_check()
        if avv_check is None:
            log.warning(
                "Kunden-AVV-Referenz-Check nicht verfuegbar -> Subjekt-Loeschung "
                "fail-closed verweigert (ADR-042 E4): %s",
                subject_id[:8],
            )
            return False
        if avv_check.has_references(subject_id):
            log.info(
                "Kunden-Subjekt behaelt aufbewahrungspflichtige AVVs -> nicht "
                "geloescht (ADR-042 E4): %s",
                subject_id[:8],
            )
            return False

        # Repos lazy bauen (Composition in der application-Schicht, analog
        # subject_backfill — kein paralleler Datenpfad).
        from tools.security_scoring.data.hardening_score_repository import (  # noqa: PLC0415
            HardeningScoreRepository,
        )
        from tools.security_scoring.data.org_assessment_repository import (  # noqa: PLC0415
            OrgAssessmentRepository,
        )
        from tools.security_scoring.data.score_repository import (  # noqa: PLC0415
            ScoreRepository,
        )

        name = profile.name
        refs = (
            ScoreRepository().count_for_subject(subject_id, name)
            + HardeningScoreRepository().count_for_subject(subject_id, name)
            + OrgAssessmentRepository().count_for_subject(subject_id)
        )
        if refs:
            return False  # noch scoring-seitig referenziert -> nicht verwaist
        self._uc.delete_customer_profile(subject_id)
        # nicht-blockierendes Cascade-Cleanup NACH erfolgreicher
        # Loeschung — Betriebs-/UX-Daten ohne Aufbewahrungspflicht (aktuell der
        # Workflow-Fortschritt inkl. Notizen) des Kunden abraeumen. Best-effort:
        # ein Fehlschlag darf die bereits erfolgte Loeschung nie rueckgaengig
        # machen (die Kunden-PII in system_profiles ist bereits weg).
        for hook in create_subject_cleanup_hooks():
            try:
                hook.cleanup(subject_id)
            except Exception as exc:  # noqa: BLE001 — Cleanup crasht den Loeschpfad nie
                log.warning(
                    "Subject-Cleanup-Hook fehlgeschlagen (%s): %s",
                    type(exc).__name__,
                    subject_id[:8],
                )
        log.info(
            "Verwaistes Kunden-Subjekt entfernt (DSGVO Art. 17, T-402): %s",
            subject_id,
        )
        return True


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


def _to_subject(profile: SystemProfile) -> Subject:
    """Mappt ein ``SystemProfile`` auf das kanonische:class:`Subject`.

    Die String-Werte von ``SystemType`` und:class:`SubjectKind` sind
    identisch — daher ist ``SubjectKind(profile.system_type.value)``
    verlustfrei.

    Args:
        profile: Das zu mappende SystemProfile.

    Returns:
        Das entsprechende Subject.
    """
    return Subject(
        subject_id=profile.id,
        kind=SubjectKind(profile.system_type.value),
        name=profile.name,
        branche=profile.branche,
        groesse=profile.groesse,
        contact=profile.contact,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
        fte=profile.fte,
        umsatz_eur=profile.umsatz_eur,
        bilanzsumme_eur=profile.bilanzsumme_eur,
        sektor_key=profile.sektor_key,
        nis2_anhang=profile.nis2_anhang,
        rolle=profile.rolle,
        segment=profile.segment,
        hat_eigene_website=profile.hat_eigene_website,
        hat_eigene_api=profile.hat_eigene_api,
        ist_entwickler=profile.ist_entwickler,
        hat_server_infrastruktur=profile.hat_server_infrastruktur,
    )
