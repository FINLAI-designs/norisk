"""
models — Domain-Modelle fuer den Supply-Chain-Monitor.

Schichtzugehoerigkeit: domain/ — keine Importe aus application/data/gui.

Iteration 2a: Vendor + VendorCategory + Kritikalitaets-
Validierung.

Iteration 2b: Catalog + Detection-Pipeline. Drei
Detection-Quellen mit gewichtetem Confidence-Score (Cert=3, MX=2,
Installed=1). Persistente Tabelle ``vendor_detections`` mit Status
(pending/accepted/rejected/deferred). Outlook-Profil-Scan EXPLIZIT NICHT
in 2b (Patrick-Direktive 2026-05-15, vgl. ``sovereignty_scanner.py:16-18``).

Iteration 2c: AVV-Tracker. AvvDocument (PDF im
Filesystem, Metadaten in DB), Art28Check-Enum + flexible Custom-Checks,
Subprocessor + n:m-Beziehung zu Vendoren (Konzentrationsrisiko).
Renewal-Status (OK / EXPIRING / OVERDUE) anhand ``valid_until``.

Iteration 2d-i: Off-Boarding-Checkliste pro Vendor
mit 10 fixen Default-Checks (Datenexport / AVV-Beendigung / Account-
Loeschung / etc.) plus ergaenzbare Custom-Punkte. Status-Lifecycle
IN_PROGRESS / COMPLETED / CANCELLED.

Iteration 2d-ii: Compliance-Modell fuer Reports.
ComplianceFramework (NIST CSF 2.0 GV.SC, BSI Grundschutz OPS.2.3 + ORP.5),
ComplianceRequirement + ComplianceCoverage (COVERED / PARTIAL / GAP /
MANUAL_REVIEW) + ComplianceAssessment-Aggregat. Daten-getrieben aus den
bestehenden Vendor/AVV/Subprocessor-Repos.

Author: Patrick Riederich
Version: 0.5-ii, 2026-05-15)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

MIN_CRITICALITY: int = 1
MAX_CRITICALITY: int = 5
MAX_NAME_LENGTH: int = 200
MAX_NOTES_LENGTH: int = 2000

# Iter 2c — AVV-Tracker.
RENEWAL_WARNING_DAYS_DEFAULT: int = 90
MAX_CUSTOM_CHECK_LABEL_LENGTH: int = 200
MAX_AVV_FILE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB - typische AVV-PDFs
MAX_SUBPROCESSOR_NAME_LENGTH: int = 200

# Iter 2d-i — Off-Boarding.
MAX_OFFBOARDING_REASON_LENGTH: int = 500

# Iter 2b — Detection-Konfiguration. Aenderungen hier wirken sich auf
# bestehende Suggestion-Berechnungen aus; bitte gleichzeitig die Tests in
# ``tests/test_supply_chain_aggregator.py`` anpassen.
SOURCE_WEIGHT_INSTALLED_APP: int = 1
SOURCE_WEIGHT_MX_LOOKUP: int = 2
SOURCE_WEIGHT_CERT_ISSUER: int = 3
CONFIDENCE_THRESHOLD_MEDIUM: int = 3  # >= 3 Punkte
CONFIDENCE_THRESHOLD_HIGH: int = 5  # >= 5 Punkte
MAX_CANONICAL_NAME_LENGTH: int = 200
MAX_PATTERN_LENGTH: int = 200
MAX_PATTERNS_PER_FIELD: int = 50


class VendorCategory(Enum):
    """Vendor-Kategorien fuer Kanzleien und KMUs.

    Diese Kategorien sind in `NoRisk_AUDIT_ERWEITERUNG_KONZEPT.md` §5.1
    festgelegt und decken den typischen Lieferanten-Mix einer Kanzlei ab.
    """

    KANZLEISOFTWARE = "kanzleisoftware"  # DATEV, RA-MICRO, AnNoText,...
    CLOUD = "cloud"  # M365, Google Workspace, AWS,...
    MSP = "msp"  # IT-Dienstleister, Managed Service Provider
    KOMMUNIKATION = "kommunikation"  # Telefonie, E-Mail, Fax, beA-Anbieter
    SPEZIAL = "spezial"  # Branchen-Spezial: Notariats-Software, Steuer-API,...

    @classmethod
    def from_value(cls, value: str) -> VendorCategory:
        """Robuste Konvertierung aus DB-String mit Default-Fallback.

        Args:
            value: Roh-String aus der DB.

        Returns:
            Passende VendorCategory; bei unbekanntem Wert ``SPEZIAL``.
        """
        try:
            return cls(value)
        except ValueError:
            return cls.SPEZIAL


@dataclass(frozen=True)
class Vendor:
    """Ein Eintrag im Vendor-/Dienstleister-Inventar.

    Attributes:
        id: Datenbank-ID (``None`` vor dem INSERT).
        name: Vendor-Name (1..200 Zeichen, getrimmt).
        category::class:`VendorCategory`.
        criticality_score: Kritikalitaet 1-5 (5 = hoechstkritisch). Definition
                            in `NoRisk_AUDIT_ERWEITERUNG_KONZEPT.md` §5.1.
        notes: Freitext (max. 2000 Zeichen). Default leer.
        created_at: Erst-Anlage (UTC).
        updated_at: Letzte Aenderung (UTC).

    Raises:
        ValueError: Bei ungueltigem Namen oder Score ausserhalb 1-5.
    """

    id: int | None
    name: str
    category: VendorCategory
    criticality_score: int
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        normalized_name = self.name.strip()
        if not normalized_name:
            raise ValueError("Vendor.name darf nicht leer sein.")
        if len(normalized_name) > MAX_NAME_LENGTH:
            raise ValueError(
                f"Vendor.name darf max. {MAX_NAME_LENGTH} Zeichen haben "
                f"(aktuell {len(normalized_name)})."
            )
        if not MIN_CRITICALITY <= self.criticality_score <= MAX_CRITICALITY:
            raise ValueError(
                f"Vendor.criticality_score muss zwischen {MIN_CRITICALITY} "
                f"und {MAX_CRITICALITY} liegen (aktuell {self.criticality_score})."
            )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"Vendor.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben "
                f"(aktuell {len(self.notes)})."
            )
        # frozen → object.__setattr__ als einzige Moeglichkeit zur Normalisierung.
        if normalized_name != self.name:
            object.__setattr__(self, "name", normalized_name)

    def is_critical(self) -> bool:
        """``True`` wenn der Vendor als kritisch eingestuft ist (Score >= 4)."""
        return self.criticality_score >= 4


# ---------------------------------------------------------------------------
# Iter 2b — Detection-Pipeline
# ---------------------------------------------------------------------------


class DetectionSource(Enum):
    """Quelle eines Detection-Treffers.

    Die Gewichtung (Cert > MX > Installed) spiegelt die technische Verlaesslichkeit
    der jeweiligen Quelle: Cert-Issuer ist kryptografisch verifiziert, MX-Records
    sind DNS-belegt, Installed-Apps sind nur lokal sichtbar. Die Punkte stehen in
    ``DETECTION_SOURCE_WEIGHTS``.
    """

    INSTALLED_APP = "installed_app"
    MX_LOOKUP = "mx_lookup"
    CERT_ISSUER = "cert_issuer"


DETECTION_SOURCE_WEIGHTS: dict[DetectionSource, int] = {
    DetectionSource.INSTALLED_APP: SOURCE_WEIGHT_INSTALLED_APP,
    DetectionSource.MX_LOOKUP: SOURCE_WEIGHT_MX_LOOKUP,
    DetectionSource.CERT_ISSUER: SOURCE_WEIGHT_CERT_ISSUER,
}


class DetectionConfidence(Enum):
    """Aggregierte Konfidenz-Stufe einer:class:`VendorSuggestion`."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_points(cls, points: int) -> DetectionConfidence:
        """Stufenkonversion fuer Aggregations-Punkte.

        Args:
            points: Summe ueber alle eindeutigen:class:`DetectionSource`,
                die fuer einen Catalog-Eintrag mindestens einen Treffer
                geliefert haben.

        Returns:
            Eine der drei:class:`DetectionConfidence`-Stufen.
        """
        if points >= CONFIDENCE_THRESHOLD_HIGH:
            return cls.HIGH
        if points >= CONFIDENCE_THRESHOLD_MEDIUM:
            return cls.MEDIUM
        return cls.LOW


class DetectionStatus(Enum):
    """Lebenszyklus eines Detection-Treffers in der DB."""

    PENDING = "pending"  # neu, der User hat noch nicht entschieden
    ACCEPTED = "accepted"  # User hat den Vorschlag in einen Vendor uebernommen
    REJECTED = "rejected"  # User will diesen Vorschlag NICHT — kommt nicht wieder
    DEFERRED = "deferred"  # User vertagt die Entscheidung


def _normalize_pattern_tuple(value: tuple[str, ...]) -> tuple[str, ...]:
    """Trim + Lowercase + Dedup + Boundary-Check fuer Pattern-Listen."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in value:
        cleaned = raw.strip().lower()
        if not cleaned or cleaned in seen:
            continue
        if len(cleaned) > MAX_PATTERN_LENGTH:
            raise ValueError(
                f"Pattern darf max. {MAX_PATTERN_LENGTH} Zeichen haben "
                f"(aktuell {len(cleaned)})."
            )
        seen.add(cleaned)
        result.append(cleaned)
        if len(result) > MAX_PATTERNS_PER_FIELD:
            raise ValueError(
                f"Maximal {MAX_PATTERNS_PER_FIELD} Patterns pro Feld erlaubt."
            )
    return tuple(result)


@dataclass(frozen=True)
class VendorCatalogEntry:
    """Bekannter Vendor mit Match-Patterns fuer die Auto-Detection.

    Ein Catalog-Eintrag ist die "Schablone", die wir auf Installed-Apps,
    MX-Hostnames und Cert-Issuer-CNs anwenden. Erkennt einer der Patterns
    einen Treffer, entsteht eine:class:`VendorDetection` mit Verweis auf
    diesen Eintrag.

    Patterns sind **case-insensitive Substring-Checks** (keine RegEx), damit
    der Catalog von Nicht-Entwicklern editierbar bleibt. Die Normalisierung
    (Trim + Lowercase + Dedup) passiert in:meth:`__post_init__`.

    Attributes:
        id: Datenbank-ID (``None`` vor INSERT).
        canonical_name: Anzeige-Name des Vendors (z. B. ``"Microsoft"``).
        default_category::class:`VendorCategory` fuer abgeleitete Vendoren.
        aliases: Alternative Schreibweisen (Info, optional). Werden
                               NICHT fuer Detection benutzt — dafuer sind die
                               drei Pattern-Felder da.
        app_name_patterns: Substring-Patterns fuer Installed-App-Namen.
        mx_hostname_patterns: Substring-Patterns fuer MX-Record-Hostnames.
        cert_issuer_patterns: Substring-Patterns fuer Cert-Issuer-CN/O.
        notes: Freitext (max. 2000 Zeichen).
        created_at / updated_at: UTC-Stamps.

    Raises:
        ValueError: Bei leerem ``canonical_name`` oder zu langen Patterns.
    """

    id: int | None
    canonical_name: str
    default_category: VendorCategory
    aliases: tuple[str, ...] = ()
    app_name_patterns: tuple[str, ...] = ()
    mx_hostname_patterns: tuple[str, ...] = ()
    cert_issuer_patterns: tuple[str, ...] = ()
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        name = self.canonical_name.strip()
        if not name:
            raise ValueError("VendorCatalogEntry.canonical_name darf nicht leer sein.")
        if len(name) > MAX_CANONICAL_NAME_LENGTH:
            raise ValueError(
                f"VendorCatalogEntry.canonical_name darf max. "
                f"{MAX_CANONICAL_NAME_LENGTH} Zeichen haben (aktuell {len(name)})."
            )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"VendorCatalogEntry.notes darf max. {MAX_NOTES_LENGTH} "
                f"Zeichen haben (aktuell {len(self.notes)})."
            )
        if name != self.canonical_name:
            object.__setattr__(self, "canonical_name", name)
        # Patterns + Aliases normalisieren (in-place auf frozen-Dataclass via
        # ``object.__setattr__``, weil Pattern-Listen aus DB-Strings kommen
        # und nicht immer schon clean sind).
        object.__setattr__(self, "aliases", _normalize_pattern_tuple(self.aliases))
        object.__setattr__(
            self, "app_name_patterns", _normalize_pattern_tuple(self.app_name_patterns)
        )
        object.__setattr__(
            self,
            "mx_hostname_patterns",
            _normalize_pattern_tuple(self.mx_hostname_patterns),
        )
        object.__setattr__(
            self,
            "cert_issuer_patterns",
            _normalize_pattern_tuple(self.cert_issuer_patterns),
        )

    def patterns_for(self, source: DetectionSource) -> tuple[str, ...]:
        """Liefert die Patterns fuer eine konkrete Detection-Quelle."""
        if source is DetectionSource.INSTALLED_APP:
            return self.app_name_patterns
        if source is DetectionSource.MX_LOOKUP:
            return self.mx_hostname_patterns
        return self.cert_issuer_patterns


@dataclass(frozen=True)
class VendorDetection:
    """Ein konkreter Treffer einer Auto-Detection-Quelle.

    Pro Treffer wird **eine** Zeile in der ``vendor_detections``-Tabelle
    persistiert. Die Aggregation zu:class:`VendorSuggestion` ist transient
    (bei jedem Aufruf neu berechnet).

    Attributes:
        id: Datenbank-ID (``None`` vor INSERT).
        catalog_entry_id: FK zur:class:`VendorCatalogEntry`-ID.
        source: Welche Quelle den Treffer geliefert hat.
        raw_match: Roh-String aus der Quelle (z. B. ``"Microsoft Office 365"``
                           oder ``"outlook-com.olc.protection.outlook.com"``).
        detected_at: Zeitpunkt des Scans (UTC).
        status: Lebenszyklus-Status (Default: ``PENDING``).
        status_changed_at: Zeitpunkt der letzten Status-Aenderung.
        vendor_id: Wenn ``status == ACCEPTED``: ID des angelegten Vendors.

    Raises:
        ValueError: Bei leerem ``raw_match``.
    """

    id: int | None
    catalog_entry_id: int
    source: DetectionSource
    raw_match: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: DetectionStatus = DetectionStatus.PENDING
    status_changed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    vendor_id: int | None = None

    def __post_init__(self) -> None:
        cleaned = self.raw_match.strip()
        if not cleaned:
            raise ValueError("VendorDetection.raw_match darf nicht leer sein.")
        if len(cleaned) > MAX_NAME_LENGTH:
            # Wir kuerzen lange Treffer auf MAX_NAME_LENGTH statt zu werfen:
            # Zertifikat-Issuer-Strings koennen >200 Zeichen lang sein, und das
            # darf den Scan nicht crashen. Kuerzung bewahrt den Anfang (das
            # interessante Stueck).
            cleaned = cleaned[:MAX_NAME_LENGTH]
        if cleaned != self.raw_match:
            object.__setattr__(self, "raw_match", cleaned)

    def is_actionable(self) -> bool:
        """``True`` wenn der Treffer noch eine User-Entscheidung braucht."""
        return self.status in {DetectionStatus.PENDING, DetectionStatus.DEFERRED}


@dataclass(frozen=True)
class VendorSuggestion:
    """Aggregierter Vorschlag aus mehreren:class:`VendorDetection`-Treffern.

    Wird zur Laufzeit aus dem:class:`VendorDetectionRepository` berechnet
    und nicht persistiert. Die Punkte ergeben sich aus den **unique** Quellen,
    die mindestens einen Treffer geliefert haben:

    >>> # Microsoft per Cert + MX + Installed-App
    >>> sources = {DetectionSource.CERT_ISSUER, DetectionSource.MX_LOOKUP,
... DetectionSource.INSTALLED_APP}
    >>> sum(DETECTION_SOURCE_WEIGHTS[s] for s in sources)
    6

    Attributes:
        catalog_entry::class:`VendorCatalogEntry` (Anchor).
        detections: Alle persistierten Treffer fuer diesen Eintrag.
        source_points: Summe der Gewichte ueber unique Quellen.
        confidence: Stufung anhand der Punkte.
        last_detected_at: Maximum aller ``detected_at``-Stamps.
    """

    catalog_entry: VendorCatalogEntry
    detections: tuple[VendorDetection, ...]
    source_points: int
    confidence: DetectionConfidence
    last_detected_at: datetime

    @classmethod
    def from_detections(
        cls,
        catalog_entry: VendorCatalogEntry,
        detections: tuple[VendorDetection, ...],
    ) -> VendorSuggestion:
        """Bildet eine Suggestion aus einer Menge von Detections.

        Nur Detections mit Status ``PENDING`` oder ``DEFERRED`` flossen in
        die Punkte ein. ``ACCEPTED``/``REJECTED``-Detections werden NICHT
        gezaehlt, weil sie eine User-Entscheidung haben.

        Args:
            catalog_entry: Der zugehoerige Catalog-Eintrag.
            detections: Detections, die diesem Catalog-Eintrag zugeordnet
                           wurden.

        Returns:
            Aggregierte:class:`VendorSuggestion`.

        Raises:
            ValueError: Wenn ``detections`` leer ist oder einer der Eintraege
                eine andere ``catalog_entry_id`` traegt.
        """
        if not detections:
            raise ValueError("VendorSuggestion braucht mindestens eine Detection.")
        for det in detections:
            if det.catalog_entry_id != catalog_entry.id:
                raise ValueError(
                    "Detection.catalog_entry_id stimmt nicht mit "
                    "VendorCatalogEntry.id ueberein."
                )
        actionable = tuple(d for d in detections if d.is_actionable())
        unique_sources = {d.source for d in actionable}
        points = sum(DETECTION_SOURCE_WEIGHTS[s] for s in unique_sources)
        confidence = DetectionConfidence.from_points(points)
        last_seen = max(d.detected_at for d in detections)
        return cls(
            catalog_entry=catalog_entry,
            detections=detections,
            source_points=points,
            confidence=confidence,
            last_detected_at=last_seen,
        )


# ---------------------------------------------------------------------------
# Iter 2c — AVV-Tracker (Auftragsverarbeitungsvertraege)
# ---------------------------------------------------------------------------


class Art28Check(Enum):
    """Die 10 fixen Pflichtinhalts-Checks nach DSGVO Art. 28 Abs. 3.

    Buchstaben a-h aus dem Gesetzestext, plus zwei Praxis-Punkte
    (``DPIA_HILFE`` und ``EU_STANDARDVERTRAGSKLAUSELN``), die bei der
    Vorlagen-Pruefung von Kanzlei-Mandanten besonders haeufig fehlen.

    User koennen ueber:class:`AvvChecklistEntry` mit ``is_custom=True``
    eigene Punkte ergaenzen — dieses Enum bleibt der feste Default-Satz.
    """

    WEISUNGSBINDUNG = "weisungsbindung"  # Art. 28(3)(a)
    VERSCHWIEGENHEIT = "verschwiegenheit"  # Art. 28(3)(b)
    TOMS = "toms"  # Art. 28(3)(c) — Technisch/Organisatorische Massnahmen
    SUB_AUFTRAGNEHMER = "sub_auftragnehmer"  # Art. 28(3)(d) — Genehmigungsvorbehalt
    BETROFFENENRECHTE = "betroffenenrechte"  # Art. 28(3)(e)
    UNTERSTUETZUNG = "unterstuetzung"  # Art. 28(3)(f) — DSFA/Meldepflichten
    LOESCHUNG = "loeschung"  # Art. 28(3)(g) — Rueckgabe/Loeschung
    AUDIT_RECHTE = "audit_rechte"  # Art. 28(3)(h) — Pruefrechte
    DPIA_HILFE = "dpia_hilfe"  # Praxis: explizite DPIA-Mitwirkung
    EU_STANDARDVERTRAGSKLAUSELN = "eu_scc"  # Praxis: Drittland-Klauseln

    @classmethod
    def from_value(cls, value: str) -> Art28Check | None:
        """Wandelt einen DB-String in das Enum, oder ``None`` (z. B. fuer
        Custom-Checks, die keinen Art28-Bezug haben).
        """
        try:
            return cls(value)
        except ValueError:
            return None


class AvvDocumentStatus(Enum):
    """Status eines AVV-Dokuments."""

    DRAFT = "draft"  # Hochgeladen, aber noch nicht aktiv (z. B. Pruefung laeuft)
    ACTIVE = "active"  # Gueltig + aktuell
    EXPIRED = "expired"  # ``valid_until`` ueberschritten


class RenewalStatus(Enum):
    """Aggregierte Renewal-Status-Stufe — berechnet aus ``valid_until``."""

    OK = "ok"  # >= RENEWAL_WARNING_DAYS_DEFAULT Tage uebrig
    EXPIRING_SOON = "expiring_soon"  # 0..RENEWAL_WARNING_DAYS_DEFAULT Tage uebrig
    OVERDUE = "overdue"  # valid_until in der Vergangenheit


def renewal_status_for(
    valid_until: datetime,
    now: datetime | None = None,
    warning_days: int = RENEWAL_WARNING_DAYS_DEFAULT,
) -> RenewalStatus:
    """Berechnet den Renewal-Status eines AVV anhand ``valid_until``.

    Geteilte Logik fuer Lieferanten- (:class:`AvvDocument`) und Kunden-AVVs
    (:class:`CustomerAvvDocument`) — beide Perspektiven nutzen dieselbe
    Ablauf-Schwelle (DRY).

    Args:
        valid_until: Vertragsende (UTC).
        now: Referenz-Zeitpunkt. Default: ``datetime.now(UTC)``.
                      In Tests injizierbar.
        warning_days: Schwelle fuer ``EXPIRING_SOON``. Default: 90 Tage.

    Returns:
        Eine der:class:`RenewalStatus`-Stufen.
    """
    reference = now or datetime.now(UTC)
    if valid_until < reference:
        return RenewalStatus.OVERDUE
    days_left = (valid_until - reference).days
    if days_left <= warning_days:
        return RenewalStatus.EXPIRING_SOON
    return RenewalStatus.OK


@dataclass(frozen=True)
class AvvDocument:
    """Ein Auftragsverarbeitungsvertrag mit Vendor + PDF.

    Die PDF-Datei liegt im Filesystem unter
    ``~/.finlai/avv/<vendor_id>/<uuid>.pdf`` (Patrick-Direktive 2026-05-15)
    — die DB speichert nur Pfad + SHA256 + Metadaten, damit das Sizing
    bei 50+ Mandanten und 100+ Vendoren skaliert.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        vendor_id: FK zu:class:`Vendor`.
        file_path: Absoluter Pfad zur PDF-Datei.
        sha256: SHA-256 der PDF-Datei (Tamper-Erkennung).
        size_bytes: Originalgroesse der PDF.
        original_filename: Anzeigename ueber den der User die Datei kennt.
        uploaded_at: Zeitpunkt des Uploads (UTC).
        valid_from: Vertragsbeginn (Datum).
        valid_until: Vertragsende (Datum) — Basis fuer Renewal-Status.
        status::class:`AvvDocumentStatus` (Default ACTIVE).
        notes: Freitext (max. 2000 Zeichen).

    Raises:
        ValueError: Bei ungueltigen Eingaben (negative Groesse, falscher
            Hash-Length, valid_until < valid_from).
    """

    id: int | None
    vendor_id: int
    file_path: str
    sha256: str
    size_bytes: int
    original_filename: str
    valid_from: datetime
    valid_until: datetime
    status: AvvDocumentStatus = AvvDocumentStatus.ACTIVE
    notes: str = ""
    uploaded_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("AvvDocument.size_bytes darf nicht negativ sein.")
        if self.size_bytes > MAX_AVV_FILE_SIZE_BYTES:
            raise ValueError(
                f"AvvDocument.size_bytes ueberschreitet das Limit "
                f"({self.size_bytes} > {MAX_AVV_FILE_SIZE_BYTES})."
            )
        if len(self.sha256) != 64:  # SHA-256 hex = 64 Zeichen
            raise ValueError("AvvDocument.sha256 muss 64-Zeichen-Hex sein.")
        if not self.original_filename.strip():
            raise ValueError("AvvDocument.original_filename darf nicht leer sein.")
        if self.valid_until < self.valid_from:
            raise ValueError(
                "AvvDocument.valid_until darf nicht vor valid_from liegen."
            )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"AvvDocument.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben."
            )

    def renewal_status(
        self,
        now: datetime | None = None,
        warning_days: int = RENEWAL_WARNING_DAYS_DEFAULT,
    ) -> RenewalStatus:
        """Berechnet den Renewal-Status anhand ``valid_until``.

        Args:
            now: Referenz-Zeitpunkt. Default: ``datetime.now(UTC)``.
                          In Tests injizierbar.
            warning_days: Schwelle fuer ``EXPIRING_SOON``. Default: 90 Tage.

        Returns:
            Eine der:class:`RenewalStatus`-Stufen.
        """
        return renewal_status_for(self.valid_until, now, warning_days)


@dataclass(frozen=True)
class AvvChecklistEntry:
    """Ein einzelner Check in der Art-28-Pflichtinhalts-Checkliste.

    Pro AVV werden 10 Default-Eintraege (einer pro:class:`Art28Check`-Wert)
    plus beliebig viele Custom-Eintraege gefuehrt. Custom-Eintraege haben
    ``is_custom = True`` und ``art28_check = None``; ``custom_label`` ist
    dann Pflicht.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        avv_id: FK zu:class:`AvvDocument`.
        art28_check: Eines der Art-28-Enum-Werte (``None`` bei Custom).
        custom_label: Freitext-Label fuer Custom-Checks (max. 200 Zeichen).
        is_present: Hat der AVV den Pflichtinhalt? (True/False/None).
                      ``None`` = noch nicht geprueft.
        is_custom: True wenn vom User definierter Custom-Check.
        notes: Optionale Notiz zum Check.
    """

    id: int | None
    avv_id: int
    is_present: bool | None
    art28_check: Art28Check | None = None
    custom_label: str = ""
    is_custom: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if self.is_custom:
            if self.art28_check is not None:
                raise ValueError(
                    "AvvChecklistEntry: is_custom=True schliesst art28_check aus."
                )
            label = self.custom_label.strip()
            if not label:
                raise ValueError(
                    "AvvChecklistEntry: custom_label ist Pflicht bei is_custom=True."
                )
            if len(label) > MAX_CUSTOM_CHECK_LABEL_LENGTH:
                raise ValueError(
                    f"AvvChecklistEntry.custom_label darf max. "
                    f"{MAX_CUSTOM_CHECK_LABEL_LENGTH} Zeichen haben."
                )
            if label != self.custom_label:
                object.__setattr__(self, "custom_label", label)
        else:
            if self.art28_check is None:
                raise ValueError(
                    "AvvChecklistEntry: art28_check ist Pflicht bei is_custom=False."
                )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"AvvChecklistEntry.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben."
            )

    @property
    def display_label(self) -> str:
        """Anzeige-Label — fuer Default-Checks aus dem Art28-Enum-Wert
        abgeleitet, fuer Custom-Checks der ``custom_label``-String.
        """
        if self.is_custom:
            return self.custom_label
        # ``__post_init__`` garantiert dass art28_check gesetzt ist wenn
        # is_custom False ist — explizite Pruefung haelt mypy/bandit ruhig.
        check = self.art28_check
        if check is None:
            return ""
        return check.value.replace("_", " ").title()


@dataclass(frozen=True)
class CustomerAvvDocument:
    """Ein Kunden-AVV — WIR als Auftragsverarbeiter, der Kunde als Verantwortlicher.

    Gegenstueck zu:class:`AvvDocument` (Lieferanten-Sicht): statt eines
    ``vendor_id`` haengt der Datensatz an einer ``subject_id`` — der kanonischen
    Kunden-Identitaet (``Subject``/``kind=KUNDE``, ``core/security_subject``).
    Die PDF liegt verschluesselt unter
    ``~/.finlai/avv/customers/<subject_id>/<uuid>.pdf.enc``, gleicher
    DEK ``supply_chain:avv_pdf``); die DB speichert nur Pfad + SHA256 + Metadaten.

    Die ``subject_id`` ist ein Cross-DB-Soft-FK — das ``Subject`` lebt in der
    ``security_scoring``-DB, daher gibt es keinen DB-Fremdschluessel und keinen
    JOIN. Die Existenz wird im Service ueber den ``SubjectStore``-Port geprueft.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        subject_id: UUID des Kunden-``Subject`` (Soft-FK).
        file_path: Absoluter Pfad zur verschluesselten PDF.
        sha256: SHA-256 des Klartexts (Tamper-Erkennung).
        size_bytes: Originalgroesse der PDF.
        original_filename: Anzeigename, ueber den der User die Datei kennt.
        valid_from: Vertragsbeginn (UTC).
        valid_until: Vertragsende (UTC) — Basis fuer Renewal-Status.
        status::class:`AvvDocumentStatus` (Default ACTIVE).
        notes: Freitext (max. 2000 Zeichen).
        uploaded_at: Zeitpunkt des Uploads (UTC).

    Raises:
        ValueError: Bei ungueltigen Eingaben (leerer subject_id/Dateiname,
            negative Groesse, falsche Hash-Length, valid_until < valid_from).
    """

    id: int | None
    subject_id: str
    file_path: str
    sha256: str
    size_bytes: int
    original_filename: str
    valid_from: datetime
    valid_until: datetime
    status: AvvDocumentStatus = AvvDocumentStatus.ACTIVE
    notes: str = ""
    uploaded_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not self.subject_id.strip():
            raise ValueError("CustomerAvvDocument.subject_id darf nicht leer sein.")
        if self.size_bytes < 0:
            raise ValueError("CustomerAvvDocument.size_bytes darf nicht negativ sein.")
        if self.size_bytes > MAX_AVV_FILE_SIZE_BYTES:
            raise ValueError(
                f"CustomerAvvDocument.size_bytes ueberschreitet das Limit "
                f"({self.size_bytes} > {MAX_AVV_FILE_SIZE_BYTES})."
            )
        if len(self.sha256) != 64:  # SHA-256 hex = 64 Zeichen
            raise ValueError("CustomerAvvDocument.sha256 muss 64-Zeichen-Hex sein.")
        if not self.original_filename.strip():
            raise ValueError(
                "CustomerAvvDocument.original_filename darf nicht leer sein."
            )
        if self.valid_until < self.valid_from:
            raise ValueError(
                "CustomerAvvDocument.valid_until darf nicht vor valid_from liegen."
            )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"CustomerAvvDocument.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben."
            )

    def renewal_status(
        self,
        now: datetime | None = None,
        warning_days: int = RENEWAL_WARNING_DAYS_DEFAULT,
    ) -> RenewalStatus:
        """Berechnet den Renewal-Status anhand ``valid_until``.

        Delegiert an:func:`renewal_status_for` (geteilt mit
:class:`AvvDocument`).

        Args:
            now: Referenz-Zeitpunkt. Default: ``datetime.now(UTC)``.
            warning_days: Schwelle fuer ``EXPIRING_SOON``. Default: 90 Tage.

        Returns:
            Eine der:class:`RenewalStatus`-Stufen.
        """
        return renewal_status_for(self.valid_until, now, warning_days)


@dataclass(frozen=True)
class Subprocessor:
    """Ein Sub-Auftragsverarbeiter (z. B. AWS unter Microsoft, T-Systems
    unter Google).

    Subprocessors sind ihre eigene Entitaet — sie koennen mehreren Vendoren
    zugeordnet werden (n:m via:class:`VendorSubprocessorLink`). Damit
    laesst sich Konzentrationsrisiko messen ("X% unserer Vendoren nutzen
    AWS als Sub-Auftragnehmer").

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        name: Anzeige-Name (max. 200 Zeichen).
        country: ISO-2-Country-Code (z. B. ``"US"``, ``"DE"``).
        category::class:`VendorCategory` (gleicher Enum wie Vendor).
        notes: Optionale Notiz (max. 2000 Zeichen).
    """

    id: int | None
    name: str
    country: str
    category: VendorCategory
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("Subprocessor.name darf nicht leer sein.")
        if len(name) > MAX_SUBPROCESSOR_NAME_LENGTH:
            raise ValueError(
                f"Subprocessor.name darf max. {MAX_SUBPROCESSOR_NAME_LENGTH} "
                f"Zeichen haben."
            )
        country = self.country.strip().upper()
        if len(country) != 2 or not country.isalpha():
            raise ValueError(
                f"Subprocessor.country muss ein ISO-2-Code sein (z. B. 'DE'), "
                f"aktuell {self.country!r}."
            )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"Subprocessor.notes darf max. {MAX_NOTES_LENGTH} Zeichen haben."
            )
        if name != self.name:
            object.__setattr__(self, "name", name)
        if country != self.country:
            object.__setattr__(self, "country", country)


@dataclass(frozen=True)
class VendorSubprocessorLink:
    """n:m-Beziehung zwischen:class:`Vendor` und:class:`Subprocessor`.

    Pro Link wird das *Rolle*-Feld gefuehrt, damit der User dokumentieren
    kann WOFUER ein Subprocessor genutzt wird (z. B. "Storage", "Email-
    Versand", "CDN"). Mehrere Rollen pro Pair = mehrere Links.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        vendor_id: FK zu:class:`Vendor`.
        subprocessor_id: FK zu:class:`Subprocessor`.
        role: Freitext-Beschreibung (z. B. "Storage").
        linked_at: Zeitpunkt der Verknuepfung.
    """

    id: int | None
    vendor_id: int
    subprocessor_id: int
    role: str = ""
    linked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if len(self.role) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"VendorSubprocessorLink.role darf max. {MAX_NOTES_LENGTH} "
                f"Zeichen haben."
            )


@dataclass(frozen=True)
class CustomerSubprocessorLink:
    """n:m-Beziehung zwischen einem KUNDEN (``Subject``/kind=KUNDE) und einem
:class:`Subprocessor`.

    Analog zu:class:`VendorSubprocessorLink`, aber fuer die Kunden-Perspektive
    (wir sind Auftragsverarbeiter): welche Sub-Auftragnehmer setzen WIR fuer
    einen bestimmten Kunden ein. Die Kunden-Identitaet ist ein Cross-DB-Soft-FK
    (``subject_id`` aus ``core.security_subject``) — kein FK/JOIN, Namensauf-
    loesung nur ueber den ``SubjectStore``-Port (H, Live-Test 2026-07-01).

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        subject_id: Soft-FK auf das Kunden-Subject (kind=KUNDE).
        subprocessor_id: FK zu:class:`Subprocessor`.
        role: Freitext-Beschreibung (z. B. "Storage").
        linked_at: Zeitpunkt der Verknuepfung.
    """

    id: int | None
    subject_id: str
    subprocessor_id: int
    role: str = ""
    linked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if len(self.role) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"CustomerSubprocessorLink.role darf max. {MAX_NOTES_LENGTH} "
                f"Zeichen haben."
            )


# ---------------------------------------------------------------------------
# Iter 2d-i — Off-Boarding (Vendor-Abwicklung)
# ---------------------------------------------------------------------------


class OffBoardingCheck(Enum):
    """Die 10 fixen Default-Checks fuer Vendor-Off-Boarding.

    Aus Konzept-Kapitel §5.1 ("Off-Boarding-Checkliste"). User koennen
    via:class:`OffBoardingChecklistEntry` mit ``is_custom=True`` eigene
    Punkte ergaenzen.
    """

    DATA_EXPORT = "data_export"  # Mandanten-Daten beim Vendor exportiert
    DATA_DELETION_CONFIRMED = "data_deletion_confirmed"  # Loeschnachweis erhalten
    AVV_TERMINATED = "avv_terminated"  # AVV gekuendigt + schriftlich bestaetigt
    ACCOUNTS_DEACTIVATED = "accounts_deactivated"  # User-Accounts deaktiviert
    CREDENTIALS_ROTATED = "credentials_rotated"  # Geteilte Credentials rotiert
    INTEGRATIONS_REMOVED = "integrations_removed"  # Webhooks / API-Keys entfernt
    PAYMENT_STOPPED = "payment_stopped"  # Lastschrift / Zahlung beendet
    SUBPROCESSORS_NOTIFIED = "subprocessors_notified"  # Sub-Auftragnehmer informiert
    BACKUP_RETAINED = "backup_retained"  # Eigene Backup-Kopie fuer Rechtsfrist
    DOCUMENTATION_UPDATED = "documentation_updated"  # Inventar aktualisiert

    @classmethod
    def from_value(cls, value: str) -> OffBoardingCheck | None:
        try:
            return cls(value)
        except ValueError:
            return None


class OffBoardingStatus(Enum):
    """Lebenszyklus einer Off-Boarding-Instanz."""

    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class OffBoarding:
    """Ein Off-Boarding-Vorgang fuer einen Vendor.

    Pro Vendor maximal eine aktive Instanz (UNIQUE-Constraint im
    Repository). Ein abgeschlossenes oder abgebrochenes Off-Boarding
    kann durch Loeschen + Neu-Start erneuert werden.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        vendor_id: FK zu:class:`Vendor`.
        status::class:`OffBoardingStatus`.
        reason: Optionaler Grund-/Notiz-Text (max. 500 Zeichen).
        started_at: Start-Zeitpunkt (UTC).
        completed_at: Abschluss-Zeitpunkt (``None`` solange IN_PROGRESS).
    """

    id: int | None
    vendor_id: int
    status: OffBoardingStatus = OffBoardingStatus.IN_PROGRESS
    reason: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        if len(self.reason) > MAX_OFFBOARDING_REASON_LENGTH:
            raise ValueError(
                f"OffBoarding.reason darf max. {MAX_OFFBOARDING_REASON_LENGTH} "
                f"Zeichen haben."
            )
        if (
            self.status is OffBoardingStatus.COMPLETED
            and self.completed_at is None
        ):
            raise ValueError(
                "OffBoarding mit Status COMPLETED braucht completed_at."
            )

    def is_open(self) -> bool:
        """``True`` wenn das Off-Boarding noch User-Aufmerksamkeit braucht."""
        return self.status is OffBoardingStatus.IN_PROGRESS


@dataclass(frozen=True)
class OffBoardingChecklistEntry:
    """Ein einzelner Check innerhalb eines Off-Boardings.

    Analog:class:`AvvChecklistEntry`: 10 Default-Eintraege (einer pro
:class:`OffBoardingCheck`-Wert) + beliebig viele Custom-Eintraege
    mit ``is_custom=True`` und ``custom_label`` als Pflichtfeld.

    Attributes:
        id: DB-ID (``None`` vor INSERT).
        offboarding_id: FK zu:class:`OffBoarding`.
        check_key: Eines der Default-Enum-Werte (``None`` bei Custom).
        custom_label: Freitext-Label fuer Custom-Checks.
        is_done: Hat der User diesen Schritt erledigt?
        is_custom: True wenn User-definiert.
        notes: Optionale Notiz.
    """

    id: int | None
    offboarding_id: int
    is_done: bool
    check_key: OffBoardingCheck | None = None
    custom_label: str = ""
    is_custom: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if self.is_custom:
            if self.check_key is not None:
                raise ValueError(
                    "OffBoardingChecklistEntry: is_custom=True schliesst "
                    "check_key aus."
                )
            label = self.custom_label.strip()
            if not label:
                raise ValueError(
                    "OffBoardingChecklistEntry: custom_label ist Pflicht "
                    "bei is_custom=True."
                )
            if len(label) > MAX_CUSTOM_CHECK_LABEL_LENGTH:
                raise ValueError(
                    f"OffBoardingChecklistEntry.custom_label darf max. "
                    f"{MAX_CUSTOM_CHECK_LABEL_LENGTH} Zeichen haben."
                )
            if label != self.custom_label:
                object.__setattr__(self, "custom_label", label)
        else:
            if self.check_key is None:
                raise ValueError(
                    "OffBoardingChecklistEntry: check_key ist Pflicht bei "
                    "is_custom=False."
                )
        if len(self.notes) > MAX_NOTES_LENGTH:
            raise ValueError(
                f"OffBoardingChecklistEntry.notes darf max. "
                f"{MAX_NOTES_LENGTH} Zeichen haben."
            )

    @property
    def display_label(self) -> str:
        if self.is_custom:
            return self.custom_label
        key = self.check_key
        if key is None:
            return ""
        return key.value.replace("_", " ").title()


# ---------------------------------------------------------------------------
# Iter 2d-ii — Compliance-Mapping fuer Reports
# ---------------------------------------------------------------------------


class ComplianceFramework(Enum):
    """Frameworks fuer GV.SC-Compliance-Mapping."""

    NIST_CSF_GVSC = "nist_csf_gvsc"  # NIST CSF 2.0, Function GV.SC-01..10
    BSI_OPS_2_3 = "bsi_ops_2_3"  # BSI Grundschutz OPS.2.3 (Cloud-Nutzung)
    BSI_ORP_5 = "bsi_orp_5"  # BSI Grundschutz ORP.5 (Compliance-Management)


class ComplianceCoverage(Enum):
    """Bewertung der Compliance-Abdeckung pro Anforderung."""

    COVERED = "covered"  # Daten-getriebener Beleg vorhanden
    PARTIAL = "partial"  # Teilweise erfuellt (z. B. einzelne AVVs fehlen)
    GAP = "gap"  # Keine oder unzureichende Daten
    MANUAL_REVIEW = "manual_review"  # Procedural-Anforderung — vom Tool nicht
    # automatisch pruefbar (z. B. Organisations-Strategie). User muss selbst
    # bewerten und ggf. extern dokumentieren.


@dataclass(frozen=True)
class ComplianceRequirement:
    """Eine einzelne Compliance-Anforderung aus einem Framework.

    Statisch im Code definiert (kein DB-Persist). Der Catalog der bekannten
    Anforderungen lebt in
:data:`tools.supply_chain_monitor.application.compliance_assessor.
    COMPLIANCE_REQUIREMENTS`.

    Attributes:
        framework::class:`ComplianceFramework`.
        identifier: Eindeutiger Schluessel innerhalb des Frameworks
                     (z. B. ``"GV.SC-04"`` oder ``"OPS.2.3.A4"``).
        title: Kurztitel.
        description: 1-2 Saetze fuer den PDF-Report.
    """

    framework: ComplianceFramework
    identifier: str
    title: str
    description: str

    def __post_init__(self) -> None:
        if not self.identifier.strip():
            raise ValueError("ComplianceRequirement.identifier darf nicht leer sein.")
        if not self.title.strip():
            raise ValueError("ComplianceRequirement.title darf nicht leer sein.")


@dataclass(frozen=True)
class ComplianceAssessment:
    """Bewertung einer einzelnen Anforderung aus aktuellen Daten.

    Wird vom ``ComplianceAssessor`` transient erzeugt — nicht persistiert,
    weil sich die Heuristik mit jedem Daten-Stand aendert.

    Attributes:
        requirement: Die bewertete:class:`ComplianceRequirement`.
        coverage: Aggregations-Ergebnis.
        evidence: Kurze Begruendung fuer den Status (z. B.
                     ``"3/5 Vendoren mit aktivem AVV"`` oder
                     ``"keine Detection-Daten — Auto-Detection noch nicht gelaufen"``).
        details: Optionale strukturierte Zusatzdaten fuer Renderer
                     (z. B. ``{"avv_count": 3, "vendor_count": 5}``).
    """

    requirement: ComplianceRequirement
    coverage: ComplianceCoverage
    evidence: str
    details: dict[str, object] = field(default_factory=dict)
