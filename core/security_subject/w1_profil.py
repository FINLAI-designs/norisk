"""core.security_subject.w1_profil — W1-Interview-Profil des eigenen Systems.

Reine, I/O-freie Domänen-Konstanten für den W1-Interview-Schritt (Refactoring-
Plan §4/§6.2): das **Segment** des eigenen Systems sowie die Schlüssel der
Profil-Gating-Flags, mit denen die Sidebar profil-irrelevante Module ausblendet/
ausgraut (z. B. „API-Security" nur mit eigener API).

Liegt — wie:mod:`core.security_subject.scoping_constants` — in ``core/``, damit
sowohl der First-Run-Wizard (``core/``) als auch die Sidebar (``core/``) die
Werte ohne ``tools/``-Import nutzen können: kein core→tools).

Die Persistenz der zugehörigen Felder erfolgt additiv in ``system_profiles``
/-Muster) am eigenen Subjekt; ``M365`` ist bewusst **kein**
Feld hier — es lebt tri-state in:class:`core.security_subject.models.NutzungsSignale`
(aus SELF-Audits abgeleitet) und treibt das Scoring, nicht das Gating.

Schichtzugehörigkeit: core/ — keine I/O, keine Imports aus tools/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from enum import StrEnum


class Segment(StrEnum):
    """Segment des eigenen Systems (W1-Interview, Refactoring-Plan §1).

    Bestimmt den Sichtbarkeits-*Default* je Nutzergruppe (z. B. ein privater
    Heimanwender braucht standardmäßig keine Audit-/Supply-Chain-Module). Der
    persistierte Wert ist der String (``Segment.EPU.value == "epu"``); ``""`` =
    nicht erfasst.

    PRIVAT: Privat- / Heimanwender (kein Unternehmen).
    GAMER: Gaming- / Power-User (privat, hohe Systemnutzung).
    EPU: Einzelunternehmen / Ein-Personen-Unternehmen.
    KMU_KLEIN: Kleinunternehmen (bis ~49 Mitarbeitende).
    KMU_MITTEL: Mittleres Unternehmen (~50–249 Mitarbeitende).
    """

    PRIVAT = "privat"
    GAMER = "gamer"
    EPU = "epu"
    KMU_KLEIN = "kmu_klein"
    KMU_MITTEL = "kmu_mittel"


# Anzeige-Reihenfolge + Labels für das W1-Dropdown (Sie-Form, R-Sie).
# Tupel aus (Segment-Schlüssel, Anzeigetext).
SEGMENTE: tuple[tuple[str, str], ...] = (
    (Segment.PRIVAT, "Privat / Heimanwender"),
    (Segment.GAMER, "Gaming / Power-User"),
    (Segment.EPU, "EPU / Einzelunternehmen"),
    (Segment.KMU_KLEIN, "Kleinunternehmen (bis 49 Mitarbeitende)"),
    (Segment.KMU_MITTEL, "Mittleres Unternehmen (50–249 Mitarbeitende)"),
)


# ---------------------------------------------------------------------------
# Profil-Gating-Schlüssel
# ---------------------------------------------------------------------------
# Jeder Schlüssel ist EXAKT der Attributname des tri-state Flags auf
#:class:`core.security_subject.models.Subject` (und ``SystemProfile``). Die
# Sidebar-Items tragen den passenden Schlüssel in ``profile_gating_key`` und der
# Builder liest das Flag per ``getattr(subject, key)`` — KEINE zentrale
# Dispatch-Map (Regel 12), die Quelle der Wahrheit ist das Subjekt-Feld.
#
# Tri-state-Semantik des gelesenen Flags (0/1/None):
# 1 → Eigenschaft vorhanden → Modul relevant → normal sichtbar.
# None → nicht erfasst → keine Aussage → normal sichtbar (kein Gating).
# 0 → Eigenschaft fehlt → Modul irrelevant → ausgegraut (Gating greift).
GATING_KEY_WEBSITE = "hat_eigene_website"  # → Zertifikats-Monitor (cert_monitor)
GATING_KEY_API = "hat_eigene_api"  # → API-Security (api_security)
GATING_KEY_ENTWICKLER = "ist_entwickler"  # → Dependency-Auditor (dependency_auditor)

# Vollständige Menge der gültigen Gating-Schlüssel (Guard gegen Tippfehler in
# der Sidebar-Config; ``hat_server_infrastruktur`` ist bewusst NICHT dabei — es
# dient dem Segment-/Zukunfts-Gating, gated heute kein einzelnes Modul).
GATING_KEYS: frozenset[str] = frozenset(
    {GATING_KEY_WEBSITE, GATING_KEY_API, GATING_KEY_ENTWICKLER}
)


# Sentinel für „Feld nicht ändern" bei den tri-state W1-Booleans (
# ``SubjectStore.update_profile_w1``): ``None`` ist dort ein ECHTER Wert (=
# zurücksetzen auf „nicht erfasst") und kann deshalb nicht „unverändert"
# bedeuten. ``-1`` ist kein gültiger Boolean-Wert (gültig: 0/1/None) und dient
# als eindeutiger Unverändert-Marker (eflexions-Regel 2: keine
# bedeutungstragende None überladen).
W1_UNCHANGED = -1
