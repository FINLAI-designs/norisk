"""
test_sovereignty_domain.

Tests fuer DetectedProvider + SovereigntyAuditResult + Score-Logik
+ Provider-Catalog. Reine Domain/Application-Schicht, kein DNS,
kein Windows-Registry.
"""

from __future__ import annotations

from tools.customer_audit.application.provider_catalog import (
    all_providers,
    by_category,
    find_by_keyword,
)
from tools.customer_audit.domain.entities import (
    DetectedProvider,
    SovereigntyAuditResult,
    compute_sovereignty_score,
)


def test_catalog_hat_alle_kategorien() -> None:
    """Provider-Catalog deckt die Kanzlei-typischen Kategorien ab."""
    cats = {p.category for p in all_providers()}
    assert "email" in cats
    assert "file_sync" in cats
    assert "office_suite" in cats
    assert "kanzlei_software" in cats
    assert "vpn" in cats


def test_catalog_findet_microsoft_via_mx() -> None:
    """MX-Host ``protection.outlook.com`` matched Microsoft 365."""
    p = find_by_keyword("kanzlei-mx.protection.outlook.com")
    assert p is not None
    assert p.name == "Microsoft 365"
    assert p.status == "eu_boundary"  # CLOUD-Act + EU-Boundary


def test_catalog_findet_eu_sovereign_provider() -> None:
    p = find_by_keyword("hetzner")
    assert p is not None
    assert p.cloud_act_exposed is False
    assert p.status == "eu_sovereign"


def test_catalog_kanzlei_software_status() -> None:
    p = find_by_keyword("DATEV Mittelstand Pro")
    assert p is not None
    assert p.name == "DATEV"
    assert p.status == "eu_sovereign"


def test_catalog_unbekannt_liefert_none() -> None:
    assert find_by_keyword("xyznix-unknown.example") is None


def test_by_category_liefert_eu_email() -> None:
    emails = by_category("email")
    namen = {p.name for p in emails}
    assert "mailbox.org" in namen
    assert "Posteo" in namen


def test_compute_score_alles_eu_sovereign() -> None:
    audit = SovereigntyAuditResult(
        detection_enabled=True,
        domain="kanzlei.at",
        detected=[
            DetectedProvider(
                name="Hetzner", status="eu_sovereign", category="saas_other",
                via="dns_mx", evidence="mx.hetzner.com",
            ),
            DetectedProvider(
                name="mailbox.org", status="eu_sovereign", category="email",
                via="dns_mx", evidence="mxext1.mailbox.org",
            ),
        ],
    )
    assert compute_sovereignty_score(audit) == 0


def test_compute_score_cloud_act_zwei_dienste() -> None:
    """Zwei CLOUD-Act-Provider → -20 (gelber/roter Bereich)."""
    audit = SovereigntyAuditResult(
        detection_enabled=True,
        domain="kanzlei.de",
        detected=[
            DetectedProvider(
                name="Microsoft 365", status="cloud_act", category="office_suite",
                via="dns_mx", evidence="kanzlei.mail.protection.outlook.com",
            ),
            DetectedProvider(
                name="Dropbox", status="cloud_act", category="file_sync",
                via="software", evidence="Dropbox 175.4",
            ),
        ],
    )
    # Microsoft 365 hat status="eu_boundary" im Catalog, aber wir testen
    # hier mit forciertem "cloud_act"-Status.
    assert compute_sovereignty_score(audit) == -20


def test_compute_score_eu_boundary_milder() -> None:
    audit = SovereigntyAuditResult(
        detection_enabled=True,
        domain="kanzlei.de",
        detected=[
            DetectedProvider(
                name="Microsoft 365", status="eu_boundary", category="office_suite",
                via="dns_mx", evidence="kanzlei.mail.protection.outlook.com",
            ),
        ],
    )
    assert compute_sovereignty_score(audit) == -5


def test_compute_score_detection_off_cap_nur_auf_boni() -> None:
    """-Review-Followup: der 50%-Cap bei Detection-OFF
    darf nur positive Boni halbieren — Penalties (negative Scores)
    bleiben voll. Sonst belohnt das System User, die Detection
    abschalten und einen schlechten Provider selbst-deklarieren.
    """
    audit = SovereigntyAuditResult(
        detection_enabled=False,
        detected=[],
        declared=[
            DetectedProvider(
                name="Microsoft 365", status="cloud_act", category="office_suite",
                via="self_declared", evidence="",
            ),
            DetectedProvider(
                name="Dropbox", status="cloud_act", category="file_sync",
                via="self_declared", evidence="",
            ),
        ],
    )
    # Roh -20, Cap greift NICHT bei negativem Raw-Score.
    assert compute_sovereignty_score(audit) == -20


def test_compute_score_detection_off_cap_auf_positive_boni() -> None:
    """Positive Boni werden bei Detection-OFF halbiert (Selbst-Auskunft
    schwaecher als Detection)."""
    audit = SovereigntyAuditResult(
        detection_enabled=False,
        detected=[],
        declared=[
            DetectedProvider(
                name="Nextcloud", status="self_hosted", category="file_sync",
                via="self_declared", evidence="",
            ),
        ],
    )
    # Roh +5, mit Cap auf 50% = 2 (int-Truncation).
    assert compute_sovereignty_score(audit) == 2


def test_compute_score_dedup_detected_ueberschreibt_declared() -> None:
    audit = SovereigntyAuditResult(
        detection_enabled=True,
        detected=[
            DetectedProvider(
                name="Microsoft 365", status="cloud_act", category="office_suite",
                via="dns_mx", evidence="mx.outlook.com",
            ),
        ],
        declared=[
            DetectedProvider(
                name="Microsoft 365", status="cloud_act", category="office_suite",
                via="self_declared", evidence="",
            ),
        ],
    )
    # Dedup: nur einmal gezaehlt → -10
    assert compute_sovereignty_score(audit) == -10


def test_score_capped_lower_bound() -> None:
    """5x CLOUD-Act = -50 (Cap)."""
    audit = SovereigntyAuditResult(
        detection_enabled=True,
        detected=[
            DetectedProvider(
                name=f"P{i}", status="cloud_act", category="saas_other",
                via="software", evidence="",
            )
            for i in range(10)
        ],
    )
    assert compute_sovereignty_score(audit) == -50


def test_audit_result_roundtrip() -> None:
    src = SovereigntyAuditResult(
        detection_enabled=True,
        domain="kanzlei.at",
        detected=[
            DetectedProvider(
                name="Hetzner", status="eu_sovereign", category="saas_other",
                via="dns_mx", evidence="mx.hetzner.com",
                legal_entity_country="DE", parent_country="DE",
            ),
        ],
        declared=[
            DetectedProvider(
                name="Mullvad VPN", status="eu_sovereign", category="vpn",
                via="self_declared", evidence="",
            ),
        ],
        scan_errors=["test-error"],
        rechtshinweise=["test-hint"],
        score=5,
        info_block_shown=True,
    )
    again = SovereigntyAuditResult.from_dict(src.to_dict())
    assert again == src


def test_detected_provider_original_label_roundtrip() -> None:
    """: ``original_label`` ueberlebt to_dict/from_dict; Alt-Audits ohne
    das Feld defaulten abwaertskompatibel auf ``""``."""
    p = DetectedProvider(
        name="Microsoft 365", status="cloud_act", category="saas_other",
        via="self_declared", evidence="", original_label="Microsoft Teams",
    )
    again = DetectedProvider.from_dict(p.to_dict())
    assert again.original_label == "Microsoft Teams"
    assert again.name == "Microsoft 365"

    legacy = DetectedProvider.from_dict(
        {"name": "Microsoft 365", "status": "cloud_act",
         "category": "saas_other", "via": "self_declared", "evidence": ""}
    )
    assert legacy.original_label == ""


def test_original_label_aendert_score_nicht() -> None:
    """: 'Microsoft Teams' und 'Microsoft 365' kollabieren im Catalog
    beide auf ``name='Microsoft 365'``. Der Score dedupt ueber ``name`` und
    zaehlt sie nur einmal — das ``original_label`` ist reine Anzeige und
    aendert das Ergebnis nicht."""
    m365 = DetectedProvider(
        name="Microsoft 365", status="cloud_act", category="saas_other",
        via="self_declared", evidence="", original_label="Microsoft 365",
    )
    teams = DetectedProvider(
        name="Microsoft 365", status="cloud_act", category="saas_other",
        via="self_declared", evidence="", original_label="Microsoft Teams",
    )
    audit = SovereigntyAuditResult(detection_enabled=True, declared=[m365, teams])
    assert compute_sovereignty_score(audit) == -10  # einmal cloud_act
