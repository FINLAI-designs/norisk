"""
csaf_parser — Parst CSAF 2.0 JSON-Dokumente in CsafAdvisory-Objekte.

Extrahiert die relevanten Felder aus dem CSAF 2.0 JSON-Schema:
  - document.title, publisher, tracking, aggregate_severity
  - vulnerabilities[].cve, scores[].cvss_v3.baseScore
  - product_tree.branches (rekursiv)
  - vulnerabilities[].notes

Schichtzugehörigkeit: application/ — kein GUI-Import, kein DB-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from core.logger import get_logger
from tools.csaf_advisor.domain.advisory import CsafAdvisory

log = get_logger(__name__)

# Maximaler CVSS-Score im CVSS v3-Bereich
_CVSS_MAX = 10.0


class CsafParser:
    """Parst ein CSAF 2.0 JSON-Dictionary in ein CsafAdvisory-Objekt.

    Alle Felder werden defensiv extrahiert — fehlendes JSON führt zu
    sinnvollen Standardwerten statt Exceptions.
    """

    def parse(self, csaf_json: dict, source_url: str = "") -> CsafAdvisory:
        """Parst ein CSAF 2.0 JSON-Dokument.

        Args:
            csaf_json: Bereits geparsertes CSAF 2.0 JSON als dict.
            source_url: URL von der das Dokument abgerufen wurde.

        Returns:
            CsafAdvisory mit allen extrahierten Feldern.
        """
        doc = csaf_json.get("document", {})
        tracking = doc.get("tracking", {})
        publisher = doc.get("publisher", {})

        tracking_id = tracking.get("id", "")
        tracking_version = tracking.get("version", "1")
        advisory_id = f"{tracking_id}_{tracking_version}".replace("/", "_").replace(
            " ", "_"
        )

        title = doc.get("title", "Kein Titel")
        publisher_name = publisher.get("name", "Unbekannt")
        initial_release = tracking.get("initial_release_date", "")
        current_release = tracking.get("current_release_date", "")

        severity = self._extract_severity(doc, csaf_json)
        cvss_score = self._extract_max_cvss(csaf_json)
        cve_ids = self._extract_cve_ids(csaf_json)
        affected_products = self._extract_products(csaf_json)
        summary = self._extract_summary(doc, csaf_json)

        return CsafAdvisory(
            id=advisory_id,
            title=title,
            publisher=publisher_name,
            tracking_id=tracking_id,
            tracking_version=tracking_version,
            initial_release=initial_release[:10] if initial_release else "",
            current_release=current_release[:10] if current_release else "",
            severity=severity,
            cvss_score=cvss_score,
            cve_ids=cve_ids,
            affected_products=affected_products,
            summary=summary,
            source_url=source_url,
        )

    # ------------------------------------------------------------------
    # Hilfsmethoden
    # ------------------------------------------------------------------

    def _extract_severity(self, doc: dict, csaf_json: dict) -> str:
        """Extrahiert den Schweregrad.

        Priorisierung:
        1. document.aggregate_severity.text (normiert auf lowercase)
        2. Höchster CVSS-Score der Vulnerabilities
        3. Fallback: "medium"

        Args:
            doc: document-Abschnitt des CSAF JSON.
            csaf_json: Vollständiges CSAF JSON.

        Returns:
            Normierter Schweregrad-String (critical/high/medium/low).
        """
        agg_sev = doc.get("aggregate_severity", {})
        text = agg_sev.get("text", "").lower()
        normalized = self._normalize_severity(text)
        if normalized:
            return normalized

        # Fallback: aus CVSS Score ableiten
        score = self._extract_max_cvss(csaf_json)
        if score is not None:
            return self._cvss_to_severity(score)

        return "medium"

    @staticmethod
    def _normalize_severity(raw: str) -> str:
        """Normiert einen Schweregrad-String auf einen der vier Standardwerte.

        Args:
            raw: Rohtext des Schweregrades.

        Returns:
            "critical", "high", "medium", "low" oder "" wenn nicht erkennbar.
        """
        mapping = {
            "kritisch": "critical",
            "critical": "critical",
            "hoch": "high",
            "high": "high",
            "mittel": "medium",
            "medium": "medium",
            "moderate": "medium",
            "niedrig": "low",
            "low": "low",
        }
        for key, value in mapping.items():
            if key in raw:
                return value
        return ""

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        """Leitet den Schweregrad aus einem CVSS-Score ab (CVSS v3-Skala).

        Args:
            score: CVSS Base Score (0.0–10.0).

        Returns:
            Schweregrad-String.
        """
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    def _extract_max_cvss(self, csaf_json: dict) -> float | None:
        """Extrahiert den höchsten CVSS v3 Base Score aus allen Vulnerabilities.

        Args:
            csaf_json: Vollständiges CSAF JSON.

        Returns:
            Höchster CVSS Base Score oder None wenn nicht vorhanden.
        """
        max_score: float | None = None
        vulns = csaf_json.get("vulnerabilities", [])
        for vuln in vulns:
            for score_entry in vuln.get("scores", []):
                for cvss_key in ("cvss_v3", "cvss_v31", "cvss_v30"):
                    cvss = score_entry.get(cvss_key, {})
                    base_score = cvss.get("baseScore")
                    if isinstance(base_score, (int, float)):
                        score = float(base_score)
                        if 0.0 <= score <= _CVSS_MAX:
                            if max_score is None or score > max_score:
                                max_score = score
        return max_score

    def _extract_cve_ids(self, csaf_json: dict) -> list[str]:
        """Extrahiert alle CVE-Bezeichner aus den Vulnerabilities.

        Args:
            csaf_json: Vollständiges CSAF JSON.

        Returns:
            Deduplizierte, sortierte Liste von CVE-IDs.
        """
        cves: set[str] = set()
        for vuln in csaf_json.get("vulnerabilities", []):
            cve = vuln.get("cve", "")
            if cve and cve.startswith("CVE-"):
                cves.add(cve)
        return sorted(cves)

    def _extract_products(self, csaf_json: dict) -> list[str]:
        """Extrahiert Produktnamen aus dem product_tree (rekursiv).

        Args:
            csaf_json: Vollständiges CSAF JSON.

        Returns:
            Deduplizierte Liste der Produktnamen (max. 50).
        """
        products: set[str] = set()
        product_tree = csaf_json.get("product_tree", {})
        self._collect_branch_names(product_tree.get("branches", []), products)

        # Auch full_product_names berücksichtigen
        for p in product_tree.get("full_product_names", []):
            name = p.get("name", "").strip()
            if name:
                products.add(name)

        # Auf sinnvolle Länge begrenzen
        return sorted(products)[:50]

    def _collect_branch_names(self, branches: list, products: set[str]) -> None:
        """Durchsucht Branches rekursiv nach Produktnamen.

        Args:
            branches: CSAF branch-Array.
            products: Mutable Set zum Sammeln der Namen.
        """
        for branch in branches:
            if not isinstance(branch, dict):
                continue
            category = branch.get("category", "")
            name = branch.get("name", "").strip()
            if name and category in ("product_name", "product_version", "architecture"):
                products.add(name)
            # Produkt im Blatt-Knoten
            product = branch.get("product", {})
            if isinstance(product, dict):
                pname = product.get("name", "").strip()
                if pname:
                    products.add(pname)
            # Rekursion
            self._collect_branch_names(branch.get("branches", []), products)

    def _extract_summary(self, doc: dict, csaf_json: dict) -> str:
        """Extrahiert eine Zusammenfassung aus den Notizen.

        Priorisierung:
        1. Vulnerability-Note mit category "summary" oder "description"
        2. Document-Note mit category "summary" oder "description"
        3. Leerer String

        Args:
            doc: document-Abschnitt des CSAF JSON.
            csaf_json: Vollständiges CSAF JSON.

        Returns:
            Zusammenfassung oder leerer String.
        """
        # Zuerst Vulnerability-Notes durchsuchen
        for vuln in csaf_json.get("vulnerabilities", []):
            for note in vuln.get("notes", []):
                if note.get("category") in ("summary", "description", "general"):
                    text = note.get("text", "").strip()
                    if text:
                        return text[:500]

        # Dann Document-Notes
        for note in doc.get("notes", []):
            if note.get("category") in ("summary", "description", "general"):
                text = note.get("text", "").strip()
                if text:
                    return text[:500]

        return ""
