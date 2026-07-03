"""
test_csaf_advisor — Tests für den CSAF Advisory-Monitor.

Testet:
  - CsafParser: CSAF 2.0 JSON → CsafAdvisory
  - ProductMatcher: Advisory ↔ Software-Inventar
  - AdvisoryRepository: CRUD-Operationen (in-memory via Temp-DB)
  - AdvisoryService: Orchestrierung

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.csaf_advisor.application.csaf_parser import CsafParser
from tools.csaf_advisor.application.product_matcher import (
    ProductMatcher,
    SoftwareComponent,
)
from tools.csaf_advisor.domain.advisory import CsafAdvisory
from tools.csaf_advisor.domain.csaf_provider import CsafProvider

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CSAF_JSON = {
    "document": {
        "title": "Fortinet FortiClient EMS — Remote Code Execution",
        "publisher": {"name": "Fortinet PSIRT"},
        "tracking": {
            "id": "FG-IR-2026-0042",
            "version": "1.0",
            "initial_release_date": "2026-01-15T10:00:00Z",
            "current_release_date": "2026-01-20T14:00:00Z",
        },
        "aggregate_severity": {"text": "Critical"},
        "notes": [
            {
                "category": "summary",
                "text": "A critical RCE vulnerability in FortiClient EMS allows remote attackers.",
            }
        ],
    },
    "vulnerabilities": [
        {
            "cve": "CVE-2026-00420",
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ],
            "notes": [],
        }
    ],
    "product_tree": {
        "branches": [
            {
                "category": "product_name",
                "name": "FortiClient",
                "branches": [
                    {
                        "category": "product_version",
                        "name": "7.2.1",
                        "product": {"name": "FortiClient EMS 7.2.1"},
                    }
                ],
            }
        ]
    },
}

MINIMAL_CSAF_JSON = {
    "document": {
        "title": "Test Advisory",
        "publisher": {"name": "Test Publisher"},
        "tracking": {
            "id": "TEST-001",
            "version": "1",
        },
    }
}


# ---------------------------------------------------------------------------
# CsafParser Tests
# ---------------------------------------------------------------------------


class TestCsafParser:
    """Tests für CsafParser."""

    def setup_method(self) -> None:
        """Erstellt eine frische Parser-Instanz."""
        self.parser = CsafParser()

    def test_parse_vollstaendiges_csaf(self) -> None:
        """Parser extrahiert alle Felder aus einem vollständigen CSAF JSON."""
        advisory = self.parser.parse(
            SAMPLE_CSAF_JSON, source_url="https://example.com/test.json"
        )

        assert advisory.title == "Fortinet FortiClient EMS — Remote Code Execution"
        assert advisory.publisher == "Fortinet PSIRT"
        assert advisory.tracking_id == "FG-IR-2026-0042"
        assert advisory.tracking_version == "1.0"
        assert advisory.severity == "critical"
        assert advisory.cvss_score == 9.8
        assert "CVE-2026-00420" in advisory.cve_ids
        assert advisory.source_url == "https://example.com/test.json"

    def test_parse_initial_release_datum(self) -> None:
        """Parser kürzt ISO-Datetime auf Datumsanteil."""
        advisory = self.parser.parse(SAMPLE_CSAF_JSON)
        assert advisory.initial_release == "2026-01-15"
        assert advisory.current_release == "2026-01-20"

    def test_parse_produkte_aus_product_tree(self) -> None:
        """Parser extrahiert Produktnamen aus branches und full_product_names."""
        advisory = self.parser.parse(SAMPLE_CSAF_JSON)
        assert (
            "FortiClient" in advisory.affected_products
            or "FortiClient EMS 7.2.1" in advisory.affected_products
        )

    def test_parse_summary_aus_notes(self) -> None:
        """Parser extrahiert Zusammenfassung aus document.notes."""
        advisory = self.parser.parse(SAMPLE_CSAF_JSON)
        assert "RCE" in advisory.summary or "vulnerability" in advisory.summary

    def test_parse_minimal_csaf_kein_fehler(self) -> None:
        """Parser wirft keine Exception bei minimalem CSAF JSON."""
        advisory = self.parser.parse(MINIMAL_CSAF_JSON)
        assert advisory.title == "Test Advisory"
        assert advisory.publisher == "Test Publisher"
        assert advisory.severity in ("critical", "high", "medium", "low")

    def test_parse_leeres_json_kein_crash(self) -> None:
        """Parser behandelt leeres JSON ohne Exception."""
        advisory = self.parser.parse({})
        assert isinstance(advisory, CsafAdvisory)
        assert advisory.severity == "medium"  # Fallback

    def test_schweregrad_normierung_hoch(self) -> None:
        """Parser normiert 'High' auf 'high'."""
        data = dict(MINIMAL_CSAF_JSON)
        data["document"] = dict(data["document"])
        data["document"]["aggregate_severity"] = {"text": "High"}
        advisory = self.parser.parse(data)
        assert advisory.severity == "high"

    def test_schweregrad_aus_cvss_score(self) -> None:
        """Parser leitet Schweregrad aus CVSS-Score ab wenn kein Text vorhanden."""
        data = {
            "document": {
                "title": "Test",
                "publisher": {"name": "Test"},
                "tracking": {"id": "X-001", "version": "1"},
            },
            "vulnerabilities": [
                {"cve": "CVE-2026-001", "scores": [{"cvss_v3": {"baseScore": 8.5}}]}
            ],
        }
        advisory = self.parser.parse(data)
        assert advisory.severity == "high"

    def test_cvss_max_score(self) -> None:
        """Parser gibt den höchsten CVSS-Score zurück wenn mehrere vorhanden."""
        data = dict(SAMPLE_CSAF_JSON)
        data["vulnerabilities"] = [
            {"cve": "CVE-001", "scores": [{"cvss_v3": {"baseScore": 5.0}}]},
            {"cve": "CVE-002", "scores": [{"cvss_v3": {"baseScore": 9.8}}]},
        ]
        advisory = self.parser.parse(data)
        assert advisory.cvss_score == 9.8


# ---------------------------------------------------------------------------
# ProductMatcher Tests
# ---------------------------------------------------------------------------


class TestProductMatcher:
    """Tests für ProductMatcher."""

    def setup_method(self) -> None:
        """Erstellt eine frische Matcher-Instanz."""
        self.matcher = ProductMatcher()

    def _make_advisory(
        self,
        tracking_id: str = "ADV-001",
        products: list[str] | None = None,
        severity: str = "high",
        title: str = "Test Advisory",
    ) -> CsafAdvisory:
        return CsafAdvisory(
            id=f"{tracking_id}_1",
            title=title,
            publisher="Test",
            tracking_id=tracking_id,
            tracking_version="1",
            initial_release="2026-01-01",
            current_release="2026-01-01",
            severity=severity,
            cvss_score=7.5,
            affected_products=products or [],
        )

    def test_exakter_match(self) -> None:
        """Matcher findet exakten Treffer (confidence=1.0)."""
        advisory = self._make_advisory(products=["OpenSSL"])
        inventory = [SoftwareComponent("OpenSSL", "3.0.2")]

        matches = self.matcher.match([advisory], inventory)
        assert len(matches) == 1
        assert matches[0].confidence == 1.0
        assert matches[0].matched_component == "OpenSSL"

    def test_teilstring_match(self) -> None:
        """Matcher findet Teilstring-Treffer (confidence=0.75)."""
        advisory = self._make_advisory(products=["Microsoft Office 2021"])
        inventory = [SoftwareComponent("Microsoft Office", "2021")]

        matches = self.matcher.match([advisory], inventory)
        assert len(matches) == 1
        assert matches[0].confidence >= 0.75

    def test_kein_match(self) -> None:
        """Matcher gibt keinen Treffer zurück wenn kein Match vorhanden."""
        advisory = self._make_advisory(products=["CompletlyUnknownProduct"])
        inventory = [SoftwareComponent("Python", "3.12")]

        matches = self.matcher.match([advisory], inventory)
        assert len(matches) == 0

    def test_leeres_inventar(self) -> None:
        """Matcher gibt leere Liste zurück bei leerem Inventar."""
        advisory = self._make_advisory(products=["OpenSSL"])
        matches = self.matcher.match([advisory], [])
        assert len(matches) == 0

    def test_leere_advisories(self) -> None:
        """Matcher gibt leere Liste zurück bei leerer Advisory-Liste."""
        inventory = [SoftwareComponent("OpenSSL", "3.0.2")]
        matches = self.matcher.match([], inventory)
        assert len(matches) == 0

    def test_action_update_fuer_critical(self) -> None:
        """Matcher empfiehlt 'update' für kritische Treffer."""
        advisory = self._make_advisory(products=["OpenSSL"], severity="critical")
        inventory = [SoftwareComponent("OpenSSL", "3.0.2")]

        matches = self.matcher.match([advisory], inventory)
        assert matches[0].action_required == "update"

    def test_action_monitor_fuer_medium(self) -> None:
        """Matcher empfiehlt 'monitor' für mittlere Schwere."""
        advisory = self._make_advisory(products=["SomeLib"], severity="medium")
        inventory = [SoftwareComponent("SomeLib", "1.0")]

        matches = self.matcher.match([advisory], inventory)
        assert matches[0].action_required == "monitor"

    def test_mehrere_matches_sortiert_nach_confidence(self) -> None:
        """Matches werden nach Confidence absteigend sortiert."""
        adv1 = self._make_advisory("ADV-001", ["Python"], severity="medium")
        adv2 = self._make_advisory(
            "ADV-002", ["Microsoft Office 2021"], severity="high"
        )
        inventory = [
            SoftwareComponent("Python", "3.12"),
            SoftwareComponent("Microsoft Office", "2021"),
        ]

        matches = self.matcher.match([adv1, adv2], inventory)
        assert len(matches) >= 2
        # Höchste Confidence zuerst
        assert matches[0].confidence >= matches[-1].confidence

    def test_match_ueber_advisory_titel(self) -> None:
        """Matcher findet Treffer auch über den Advisory-Titel."""
        advisory = self._make_advisory(
            products=[],  # Keine Produkte im product_tree
            title="OpenSSL Buffer Overflow Vulnerability",
        )
        inventory = [SoftwareComponent("OpenSSL", "3.0")]

        matches = self.matcher.match([advisory], inventory)
        # Mindestens ein Token-Match über den Titel
        assert len(matches) >= 1


# ---------------------------------------------------------------------------
# CsafAdvisory Domain-Modell Tests
# ---------------------------------------------------------------------------


class TestCsafAdvisory:
    """Tests für das CsafAdvisory Domain-Modell."""

    def test_severity_order_critical(self) -> None:
        """critical hat Sortierorder 0 (höchste Priorität)."""
        advisory = CsafAdvisory(
            id="x",
            title="T",
            publisher="P",
            tracking_id="ID",
            tracking_version="1",
            initial_release="",
            current_release="",
            severity="critical",
            cvss_score=9.8,
        )
        assert advisory.severity_order() == 0

    def test_severity_order_low(self) -> None:
        """low hat Sortierorder 3."""
        advisory = CsafAdvisory(
            id="x",
            title="T",
            publisher="P",
            tracking_id="ID",
            tracking_version="1",
            initial_release="",
            current_release="",
            severity="low",
            cvss_score=2.0,
        )
        assert advisory.severity_order() == 3

    def test_severity_order_unbekannt(self) -> None:
        """Unbekannter Schweregrad hat Sortierorder 4."""
        advisory = CsafAdvisory(
            id="x",
            title="T",
            publisher="P",
            tracking_id="ID",
            tracking_version="1",
            initial_release="",
            current_release="",
            severity="unknown",
            cvss_score=None,
        )
        assert advisory.severity_order() == 4


# ---------------------------------------------------------------------------
# CsafProvider Domain-Modell Tests
# ---------------------------------------------------------------------------


class TestCsafProvider:
    """Tests für das CsafProvider Domain-Modell."""

    def test_is_curated_true(self) -> None:
        """CsafProvider.is_curated gibt True zurück für source='curated'."""
        provider = CsafProvider(
            id="csaf-bsi",
            name="BSI",
            provider_url="https://example.com",
            source="curated",
        )
        assert provider.is_curated is True

    def test_is_curated_false(self) -> None:
        """CsafProvider.is_curated gibt False zurück für source='user'."""
        provider = CsafProvider(
            id="user-001",
            name="Eigener Provider",
            provider_url="https://my.example.com",
            source="user",
        )
        assert provider.is_curated is False


# ---------------------------------------------------------------------------
# AdvisoryService Integration-Tests (mit Mock-Repository)
# ---------------------------------------------------------------------------


class TestAdvisoryService:
    """Integration-Tests für AdvisoryService mit Mock-Repository."""

    def setup_method(self) -> None:
        """Erstellt eine Mock-Repository-Instanz und den Service."""
        from tools.csaf_advisor.application.advisory_service import AdvisoryService
        from tools.csaf_advisor.domain.advisory_repository import IAdvisoryRepository

        self.repo = MagicMock(spec=IAdvisoryRepository)
        self.service = AdvisoryService(repository=self.repo)

    def test_list_providers_delegiert_an_repo(self) -> None:
        """list_providers delegiert an das Repository."""
        providers = [CsafProvider(id="p1", name="BSI", provider_url="https://bsi.de")]
        self.repo.list_providers.return_value = providers

        result = self.service.list_providers()
        assert result == providers
        self.repo.list_providers.assert_called_once()

    def test_add_provider_speichert_im_repo(self) -> None:
        """add_provider ruft repo.save_provider auf."""
        provider = CsafProvider(
            id="user-001",
            name="Test",
            provider_url="https://test.com",
        )
        self.service.add_provider(provider)
        self.repo.save_provider.assert_called_once_with(provider)

    def test_toggle_provider_deaktiviert(self) -> None:
        """toggle_provider aktualisiert den enabled-Status."""
        provider = CsafProvider(
            id="p1", name="BSI", provider_url="https://bsi.de", enabled=True
        )
        self.repo.get_provider.return_value = provider

        self.service.toggle_provider("p1", False)

        self.repo.save_provider.assert_called_once()
        saved = self.repo.save_provider.call_args[0][0]
        assert saved.enabled is False

    def test_toggle_provider_unbekannte_id(self) -> None:
        """toggle_provider wirft keinen Fehler bei unbekannter ID."""
        self.repo.get_provider.return_value = None
        self.service.toggle_provider("unbekannt", False)  # Kein Fehler

    def test_list_advisories_sortiert_nach_severity(self) -> None:
        """list_advisories sortiert Ergebnisse nach Schweregrad."""
        advisories = [
            CsafAdvisory("id3", "T", "P", "ID3", "1", "", "2026-01-01", "low", 2.0),
            CsafAdvisory(
                "id1", "T", "P", "ID1", "1", "", "2026-01-03", "critical", 9.8
            ),
            CsafAdvisory("id2", "T", "P", "ID2", "1", "", "2026-01-02", "high", 7.5),
        ]
        self.repo.list_advisories.return_value = advisories

        result = self.service.list_advisories()
        assert result[0].severity == "critical"
        assert result[-1].severity == "low"

    def test_load_techstack_kein_fehler_ohne_datei(self, tmp_path: Path) -> None:
        """load_techstack_inventory gibt leere Liste zurück wenn keine Datei vorhanden."""
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = self.service.load_techstack_inventory()
        assert result == []

    def test_load_techstack_laedt_aus_json(self, tmp_path: Path) -> None:
        """load_techstack_inventory lädt aus techstack.json."""
        stack_dir = tmp_path / ".finlai"
        stack_dir.mkdir(parents=True)
        stack_file = stack_dir / "techstack.json"
        stack_data = [
            {
                "name": "Python",
                "version": "3.12",
                "kategorie": "Runtime",
                "aktiv": True,
            },
            {
                "name": "OpenSSL",
                "version": "3.0",
                "kategorie": "Security",
                "aktiv": True,
            },
            {"name": "Inaktiv", "version": "1.0", "kategorie": "App", "aktiv": False},
        ]
        stack_file.write_text(json.dumps(stack_data), encoding="utf-8")

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = self.service.load_techstack_inventory()

        assert len(result) == 2  # Inaktiver Provider wird übersprungen
        names = [c.name for c in result]
        assert "Python" in names
        assert "OpenSSL" in names
        assert "Inaktiv" not in names


# ---------------------------------------------------------------------------
# _validate_advisory_url — URL-Validator gegen Provider-Inhalt-Tampering
# ---------------------------------------------------------------------------


class TestValidateAdvisoryUrl:
    """Tests für die URL-Validierung in csaf_downloader."""

    def _validator(self):
        from tools.csaf_advisor.application.csaf_downloader import (
            _validate_advisory_url,
        )

        return _validate_advisory_url

    def test_relative_url_im_gleichen_verzeichnis_wird_aufgeloest(self) -> None:
        v = self._validator()
        result = v("cve-2024-1.json", "https://provider.example/dir/")
        assert result == "https://provider.example/dir/cve-2024-1.json"

    def test_relative_url_im_unterverzeichnis_erlaubt(self) -> None:
        v = self._validator()
        result = v("2024/cve.json", "https://provider.example/feeds/feed.json")
        assert result == "https://provider.example/feeds/2024/cve.json"

    def test_absolute_https_im_gleichen_host_erlaubt(self) -> None:
        v = self._validator()
        result = v(
            "https://provider.example/dir/x.json", "https://provider.example/dir/"
        )
        assert result == "https://provider.example/dir/x.json"

    def test_http_schema_blockt(self) -> None:
        v = self._validator()
        assert v("http://provider.example/x.json", "https://provider.example/") is None

    def test_fremder_host_blockt(self) -> None:
        v = self._validator()
        assert (
            v("https://attacker.example/x.json", "https://provider.example/") is None
        )

    def test_path_escape_via_dotdot_blockt(self) -> None:
        v = self._validator()
        #../../../etc/passwd würde sich aus /dir/ nach / befreien
        assert v("../../../etc/passwd", "https://provider.example/dir/feed.json") is None

    def test_javascript_schema_blockt(self) -> None:
        v = self._validator()
        assert v("javascript:alert(1)", "https://provider.example/") is None

    def test_leerer_string_blockt(self) -> None:
        v = self._validator()
        assert v("", "https://provider.example/") is None

    def test_zu_lange_url_blockt(self) -> None:
        v = self._validator()
        long_url = "https://provider.example/" + "a" * 3000
        assert v(long_url, "https://provider.example/") is None
