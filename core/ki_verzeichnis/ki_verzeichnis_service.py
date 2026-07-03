"""
core/ki_verzeichnis/ki_verzeichnis_service.py — KI-Verzeichnis nach EU KI-VO Art. 4.

Generiert eine Übersicht der KI-Einsätze von NoRisk:
  * FINLAI-Assistent (lokales Ollama-LLM): Bedienung + IT-Sicherheit
  * Cyber-Lagebild / Briefing (lokales Ollama-LLM)

Seit (28.05.2026) ist NoRisk zu 100% lokal — der frühere
DeepL-Übersetzer-Eintrag (Cloud) ist entfernt.

 (13.06.2026): Die früher getrennten Einträge „Security Chat" und
„Handbuch-Assistent (RAG)" sind zum EINEN vereinten FINLAI-Assistenten
verschmolzen (Bedienung + IT-Sicherheit hinter einer Pipeline).

NoRisk-spezifisch: Diese Datei listet ausschließlich NoRisk-KI-Einsätze.
Buchprüfung ist ein FINLAI-Tool und in NoRisk nicht vorhanden. Andere
FINLAI-Apps pflegen eine eigene, ABWEICHENDE Copy dieses Service (mit
KI-Agenten-DB/Buchprüfung) — diese Datei NICHT blind zwischen den Repos
spiegeln.

 (06.06.2026): Die realen NoRisk-KI-Einsätze cyber_dashboard-Briefing
(Lagebild) und handbuch_assistent-RAG sind ergänzt. customer_audit und
security_scoring nutzen aktuell kein LLM und sind daher nicht gelistet.

Das Verzeichnis wird als JSON unter ~/.finlai/ki_verzeichnis.json gespeichert.

Author: Patrick Riederich
Version: 1.2-followup: NoRisk-spezifisch, Buchprüfung entfernt)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from core.finlai_paths import finlai_dir
from core.logger import get_logger

_log = get_logger(__name__)


@dataclass
class KiEintrag:
    """Ein Eintrag im KI-Verzeichnis nach EU KI-VO Art. 4."""

    name: str
    kategorie: str  # "Agent" | "Chat" | "Übersetzung" | "Analyse"
    zweck: str
    datenarten: list[str]
    modell: str
    lokal: bool  # True = lokal; False = Cloud
    verantwortlich: str
    erstellt_am: str
    zuletzt_aktiv: str = ""
    url_allowlist: list[str] = field(default_factory=list)
    aktiv: bool = True
    human_review: bool = True


class KiVerzeichnisService:
    """Generiert das KI-Verzeichnis nach EU KI-VO Art. 4.

    Sammelt die NoRisk-KI-Einsätze (lokaler FINLAI-Assistent / Ollama) und
    schreibt das Ergebnis als JSON-Datei.
    """

    VERZEICHNIS_PATH = finlai_dir() / "ki_verzeichnis.json"

    def generiere_verzeichnis(self) -> list[KiEintrag]:
        """Generiert das NoRisk-KI-Verzeichnis und speichert es.

        Erfasst die lokalen Ollama-KI-Einsätze von NoRisk: den vereinten
        FINLAI-Assistenten (Bedienung + IT-Sicherheit) und das Cyber-Lagebild
        (Briefing). Buchprüfung ist ein FINLAI-Tool und in NoRisk nicht
        vorhanden — daher hier nicht gelistet. customer_audit/security_scoring
        nutzen kein LLM.

        Returns:
            Liste der NoRisk-KI-Einträge.
        """
        eintraege: list[KiEintrag] = [
            self._assistent_eintrag(),
            self._briefing_eintrag(),
        ]
        self._speichern(eintraege)
        return eintraege

    def _assistent_eintrag(self) -> KiEintrag:
        """Erstellt den Eintrag für den vereinten FINLAI-Assistenten.

        Verschmilzt die früher getrennten Einträge „Security Chat" und
        „Handbuch-Assistent (RAG)": EIN lokaler Ollama-Assistent beantwortet
        Bedien- UND IT-Sicherheitsfragen hinter einer gehärteten Pipeline.

        Returns:
            KiEintrag für den FINLAI-Assistenten.
        """
        return KiEintrag(
            name="FINLAI-Assistent",
            kategorie="Chat",
            zweck=(
                "Lokaler KI-Assistent (Bedienung + IT-Sicherheit): beantwortet "
                "Bedienfragen aus der Handbuch-Dokumentation und erklärt CVEs, "
                "Schwachstellen und Sicherheitswarnungen, bewertet Phishing-/"
                "Malware-Indizien — Retrieval-Augmented über Handbuch und "
                "kuratierten Sicherheits-Korpus, mit Quellenangabe. Ein "
                "3-wertiges Scope-Gate weist Off-Topic-Fragen ab; der "
                "System-Prompt schließt sicherheitsrelevante Interna "
                "(SECURITY/THREAT_MODEL, Code) aus; ein Ausgabefilter entfernt "
                "sensible Muster, CVE-Antworten tragen einen Quellen-Disclaimer."
            ),
            datenarten=[
                "Nutzerfragen (Bedienung + IT-Sicherheit)",
                "Handbuch-Dokumentation (Markdown, lokal indiziert)",
                "Sicherheits-Korpus (lokal indiziert)",
                "Gesprächsverlauf (ephemer, lokal)",
            ],
            modell="Ollama (lokal)",
            lokal=True,
            verantwortlich="admin",
            erstellt_am=datetime.now().isoformat(),
            human_review=True,
        )

    def _briefing_eintrag(self) -> KiEintrag:
        """Erstellt den Eintrag für das Cyber-Lagebild (Briefing, Ollama).

        Returns:
            KiEintrag für das tägliche KI-Briefing des cyber_dashboard.
        """
        return KiEintrag(
            name="Cyber-Lagebild (Briefing)",
            kategorie="Analyse",
            zweck=(
                "Erstellt das tägliche Cyber-Lagebild im Dashboard: "
                "reformuliert aktuelle CVEs, Sicherheitswarnungen und "
                "Consumer-Software-Advisories zu kurzen, sachlichen "
                "deutschen Hinweisen und priorisiert sie nach dem "
                "persönlichen Tech-Stack."
            ),
            datenarten=[
                "Öffentliche CVE-/Sicherheitswarnungen (Feeds)",
                "Consumer-Software-Advisories",
                "Persönlicher Tech-Stack (lokal)",
            ],
            modell="Ollama (lokal)",
            lokal=True,
            verantwortlich="admin",
            erstellt_am=datetime.now().isoformat(),
            human_review=True,
        )

    # ------------------------------------------------------------------
    def _speichern(self, eintraege: list[KiEintrag]) -> None:
        """Schreibt das Verzeichnis als JSON-Datei.

        Args:
            eintraege: Liste aller KiEintrag-Objekte.
        """
        self.VERZEICHNIS_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "generiert_am": datetime.now().isoformat(),
            "finlai_version": "1.0",
            "eintraege": [vars(e) for e in eintraege],
        }
        self.VERZEICHNIS_PATH.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        _log.info("KI-Verzeichnis gespeichert: %d Einträge", len(eintraege))
