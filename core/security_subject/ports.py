"""core.security_subject.ports — Port für den Zugriff auf Subjekte.

Definiert den:class:`SubjectStore`-Vertrag, den ``security_scoring``
(Tabelle ``system_profiles``) implementiert. Konsumenten (``customer_audit``,
Dashboard) typisieren gegen diesen Port und erhalten die konkrete
Implementierung per Dependency Injection / lazy Resolver — kein tool→tool-Import.

Schichtzugehörigkeit: core/ — reiner Protocol-Vertrag, keine I/O.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.security_subject.models import NutzungsSignale, Subject
from core.security_subject.w1_profil import W1_UNCHANGED


@runtime_checkable
class SubjectStore(Protocol):
    """Vertrag für Lesen/Anlegen kanonischer Subjekte.

    Die konkrete Implementierung besitzt die ``system_profiles``-Tabelle in
    der ``security_scoring``-DB. Alle Methoden sind fail-loud bei
    echten DB-Fehlern; der lazy Resolver der Konsumenten kapselt fail-soft.
    """

    def ensure_self_subject(self, name: str) -> Subject:
        """Stellt sicher, dass genau ein ``EIGENES``-Subjekt existiert.

        Args:
            name: Anzeigename, falls neu angelegt werden muss.

        Returns:
            Das bestehende oder neu angelegte eigene Subjekt.
        """
        ...

    def find_or_create_client(self, name: str) -> Subject:
        """Findet ein Kunden-Subjekt per Name (case-insensitive) oder legt es an.

        Args:
            name: Firmenname des Kunden/Mandanten.

        Returns:
            Das gefundene oder neu angelegte ``KUNDE``-Subjekt.
        """
        ...

    def get(self, subject_id: str) -> Subject | None:
        """Lädt ein Subjekt per ID.

        Args:
            subject_id: UUID des Subjekts.

        Returns:
            Das Subjekt oder ``None``, wenn unbekannt.
        """
        ...

    def get_self(self) -> Subject | None:
        """Gibt das eigene Subjekt zurück (oder ``None``, falls noch keines)."""
        ...

    def list_all(self) -> list[Subject]:
        """Listet alle Subjekte (eigenes zuerst, dann alphabetisch)."""
        ...

    def update_stammdaten(
        self,
        subject_id: str,
        *,
        branche: str | None = None,
        groesse: str | None = None,
        contact: str | None = None,
    ) -> None:
        """Aktualisiert Subjekt-Stammdaten (nur gesetzte Felder).

        Args:
            subject_id: UUID des Subjekts.
            branche: Neue Branche oder ``None`` (unverändert).
            groesse: Neue Unternehmensgröße oder ``None`` (unverändert).
            contact: Neuer Ansprechpartner oder ``None`` (unverändert).
        """
        ...

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

        Anders als:meth:`update_stammdaten` werden hier die NIS2-tauglichen
        Profil-Felder des eigenen Systems gepflegt. Jeder ``None``-Parameter
        bleibt unverändert.

        ``nis2_anhang`` ist KEIN Parameter — die Implementierung leitet ihn
        deterministisch aus ``sektor_key`` ab (Single Write Path), sobald ein
        Sektor gesetzt wird. So kann der denormalisierte Anhang nie zum Sektor
        desynchronisieren (Review-Invariante).

        Args:
            subject_id: UUID des Subjekts.
            fte: Vollzeitäquivalente oder ``None`` (unverändert).
            umsatz_eur: Jahresumsatz in EUR oder ``None`` (unverändert).
            bilanzsumme_eur: Bilanzsumme in EUR oder ``None`` (unverändert).
            sektor_key: NIS2-Sektor-Schlüssel oder ``None`` (unverändert). Setzt
                implizit auch ``nis2_anhang`` (abgeleitet).
            rolle: Rolle der erfassenden Person oder ``None`` (unverändert).
        """
        ...

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
        """Aktualisiert die W1-Interview-Profilfelder des eigenen Systems.

        Pflegt das im W1-Interview erfasste Profil (Segment + Infrastruktur-
        Eigenschaften), aus dem die Sidebar das Modul-Gating ableitet. Nur
        gesetzte Felder werden geschrieben (kein Voll-Zeilen-Clobbering).

        ``segment`` nutzt ``None`` als „unverändert"-Marker (Segment ist nie
        ``None``, nur ``""`` wenn nicht erfasst). Die tri-state Booleans nutzen
        den Sentinel:data:`core.security_subject.w1_profil.W1_UNCHANGED` (``-1``)
        — ``None`` ist dort ein gültiger Wert (= „nicht erfasst") und kann daher
        nicht „unverändert" bedeuten.

        Args:
            subject_id: UUID des (eigenen) Subjekts.
            segment: Segment-Schlüssel oder ``None`` (unverändert).
            hat_eigene_website: 0/1/``None`` oder Sentinel (unverändert).
            hat_eigene_api: 0/1/``None`` oder Sentinel (unverändert).
            ist_entwickler: 0/1/``None`` oder Sentinel (unverändert).
            hat_server_infrastruktur: 0/1/``None`` oder Sentinel (unverändert).
        """
        ...

    def delete_subject_if_unreferenced(self, subject_id: str) -> bool:
        """Löscht ein KUNDEN-Subjekt, wenn es scoring-seitig nicht mehr
        referenziert wird (DSGVO Art. 17 Orphan-Cleanup).

        Entfernt die Subjekt-Stammdaten (PII: Firmenname/Ansprechpartner/Branche)
        aus ``system_profiles``, sobald KEIN Score/Hardening/Org-Assessment das
        Subjekt mehr hält. Der audit-seitige Referenz-Check (gibt es noch Audits
        für dieses Subjekt?) liegt beim Aufrufer (``customer_audit``). Das eigene
        Subjekt wird NIE gelöscht.

        Args:
            subject_id: UUID des zu prüfenden Subjekts.

        Returns:
            True, wenn das Subjekt gelöscht wurde; False, wenn es noch
            (scoring-seitig) referenziert wird, das eigene System ist oder nicht
            existiert.
        """
        ...


@runtime_checkable
class UsageSignalProvider(Protocol):
    """Vertrag für tri-state Nutzungssignale eines Subjekts.

    Implementiert von ``customer_audit`` (liest das jüngste SELF-Sovereignty-
    Audit und übersetzt es in kategorisierte:class:`NutzungsSignale`).
    Konsumenten (``security_scoring`` Org-Assessment) beziehen die Implementierung
    über den lazy core-Resolver
:func:`core.security_subject.resolver.create_usage_signal_provider` — kein
    tool→tool-Import §3.2).
    """

    def signale_fuer(self, subject_id: str) -> NutzungsSignale:
        """Liefert die Nutzungssignale für ein Subjekt.

        Args:
            subject_id: UUID des Subjekts (i. d. R. das eigene System).

        Returns:
:class:`NutzungsSignale`; alle Felder ``None``, wenn kein belastbares
            SELF-Audit vorliegt (fail-soft, kein Auto-N/A).
        """
        ...


@runtime_checkable
class AvvReferenceCheck(Protocol):
    """Vertrag für den Kunden-AVV-Referenz-Check beim Subjekt-Löschen E4).

    Implementiert von ``supply_chain_monitor`` (``CustomerAvvRepository``).
    Konsumenten (der Subjekt-Lösch-Pfad in ``security_scoring``) beziehen die
    Implementierung über den lazy core-Resolver
:func:`core.security_subject.resolver.create_avv_reference_check` — kein
    tool→tool-Import. Existieren noch aufbewahrungspflichtige Kunden-AVVs, wird
    die Subjekt-Löschung blockiert.
    """

    def has_references(self, subject_id: str) -> bool:
        """True, wenn das Subjekt noch Kunden-AVVs hält (blockiert Löschung).

        Args:
            subject_id: UUID des zu prüfenden Subjekts.

        Returns:
            True bei mindestens einem referenzierenden Kunden-AVV, sonst False.
        """
        ...


@runtime_checkable
class SubjectCleanupHook(Protocol):
    """Vertrag für nicht-blockierendes Cascade-Cleanup beim Subjekt-Löschen.

    Anders als:class:`AvvReferenceCheck` (blockiert die Löschung bei
    aufbewahrungspflichtigen Bezügen) räumt ein Cleanup-Hook Betriebs-/UX-Daten
    ohne Aufbewahrungspflicht *nach* der erfolgreichen Löschung best-effort ab —
    z. B. den Workflow-Fortschritt (Status + Notizen) eines gelöschten Kunden
    (``norisk_dashboard``). Konsumenten beziehen die Implementierungen über den
    lazy core-Resolver
:func:`core.security_subject.resolver.create_subject_cleanup_hooks` — kein
    tool→tool-Import. Ein Fehlschlag darf die Löschung nie rückgängig machen.
    """

    def cleanup(self, subject_id: str) -> None:
        """Entfernt verwaiste Daten des gelöschten Subjekts (best-effort).

        Args:
            subject_id: UUID des soeben gelöschten Subjekts.
        """
        ...
