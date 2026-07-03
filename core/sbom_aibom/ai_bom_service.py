"""core/sbom_aibom/ai_bom_service.py — AI-BOM (AI Bill of Materials).

Erzeugt eine strukturierte, exportierbare Uebersicht aller KI-Komponenten,
die NoRisk einsetzt:

* **Lokale Ollama-Modelle** — installierte Modelle mit Name + Digest aus
  ``/api/tags`` (vollstaendig lokale Inferenz).

NoRisk ist seit// zu 100% lokal — alle
Cloud-KI-Provider (DeepL, OpenAI, Anthropic) sind entfernt. Die AI-BOM
listet daher ausschliesslich lokale Komponenten. Das ``location``-Feld
auf ``AiComponent`` bleibt fuer zukuenftige opt-in-Erweiterungen erhalten.

Treiber: EU AI Act (Transparenz-/Dokumentationspflichten); ergaenzt das
bestehende KI-Verzeichnis nach EU KI-VO Art. 4
(:mod:`core.ki_verzeichnis.ki_verzeichnis_service`).

-aibom.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import requests

from core.logger import get_logger
from core.ollama_utils import get_default_ollama_tags_url
from core.version import __version__ as _NORISK_VERSION

_log = get_logger(__name__)

_OLLAMA_TAGS_TIMEOUT_SECONDS = 3.0

_KIND_MODEL = "model"


@dataclass
class AiComponent:
    """Ein Eintrag im AI-BOM.

    Args:
        name: Anzeigename (z. B. ``"qwen3:8b"``).
        kind: ``"model"`` fuer Inferenz-Modelle, ``"service"`` fuer APIs.
        location: ``"local"`` oder ``"cloud"`` — Hinweis zum Datenfluss.
        purpose: Einsatzzweck in NoRisk (kurz, deutsch).
        data_flow: Beschreibung was an die Komponente uebertragen wird.
        version: Modell-Tag oder API-Version.
        digest: Optionaler Modell-Digest (nur fuer Ollama-Modelle).
        size_bytes: Optionale Modellgroesse in Byte (nur fuer Ollama).
        data_sources: Freier Text zur Datenquelle (z. B. Trainingsdaten).
    """

    name: str
    kind: str
    location: str
    purpose: str
    data_flow: str
    version: str = ""
    digest: str = ""
    size_bytes: int = 0
    data_sources: str = ""


def _fetch_ollama_models() -> list[dict[str, object]]:
    """Holt die Liste der installierten Ollama-Modelle inkl. Digest/Size.

    Nutzt ``/api/tags`` mit kurzem Timeout — wenn Ollama nicht laeuft,
    wird eine leere Liste zurueckgegeben (kein Fehler).

    Returns:
        Liste der ``models``-Eintraege aus der Ollama-Antwort. Jeder Eintrag
        enthaelt mindestens ``name``; ``digest`` und ``size`` sind optional.
    """
    try:
        response = requests.get(
            get_default_ollama_tags_url(),
            timeout=_OLLAMA_TAGS_TIMEOUT_SECONDS,
        )
        if response.status_code != 200:
            return []
        payload = response.json()
    except (requests.RequestException, ValueError, OSError) as err:
        _log.debug("Ollama-Tags nicht erreichbar: %s", type(err).__name__)
        return []
    models = payload.get("models")
    if not isinstance(models, list):
        return []
    return [m for m in models if isinstance(m, dict) and m.get("name")]


def _build_ollama_components() -> list[AiComponent]:
    """Erzeugt AI-BOM-Eintraege fuer alle installierten Ollama-Modelle.

    Returns:
        Liste der lokalen Inferenz-Modelle (kann leer sein).
    """
    components: list[AiComponent] = []
    for entry in _fetch_ollama_models():
        name = str(entry.get("name", ""))
        if not name:
            continue
        digest_raw = entry.get("digest", "")
        digest = str(digest_raw) if digest_raw else ""
        size_raw = entry.get("size", 0)
        try:
            size_bytes = int(size_raw)
        except (TypeError, ValueError):
            size_bytes = 0
        components.append(
            AiComponent(
                name=name,
                kind=_KIND_MODEL,
                location="local",
                purpose="Lokale Inferenz fuer Security-Chat, Erklaerungen und Zusammenfassungen.",
                data_flow="Eingaben verbleiben ausschliesslich auf dem Geraet (localhost:11434).",
                version=name,
                digest=digest,
                size_bytes=size_bytes,
                data_sources=(
                    "Trainingsdaten des Modells laut Modell-Anbieter "
                    "(siehe Ollama-Modellkarte)."
                ),
            )
        )
    return components


def build_ai_bom() -> list[AiComponent]:
    """Aggregiert die lokalen KI-Komponenten zu einer AI-BOM-Liste.

    NoRisk ist seit vollstaendig lokal — die Liste enthaelt nur
    Ollama-Modelle. Die Sortier-Reihenfolge (local-first, alphabetisch)
    ist fuer kuenftige Cloud-Erweiterungen bewusst stabil gehalten.

    Returns:
        Sortierte Liste (alphabetisch nach Name).
    """
    components = _build_ollama_components()
    components.sort(key=lambda c: (c.location != "local", c.name.lower()))
    return components


class AiBomService:
    """Erzeugt strukturierte AI-BOM-Exports.

    Das exportierte JSON-Format ist intern stabil (kein etablierter
    AI-BOM-Standard zum Zeitpunkt der Implementierung — CycloneDX-ML/
    NTIA-AIBOM-Drafts werden beobachtet). Versions-Feld ermoeglicht
    spaetere Format-Migration.
    """

    AI_BOM_FORMAT = "FINLAI-AIBOM"
    AI_BOM_SPEC_VERSION = "0.1"

    def generate(self) -> dict[str, object]:
        """Erzeugt das vollstaendige AI-BOM-Dokument als Dict.

        Returns:
            JSON-serialisierbares Dict mit Metadaten + Komponenten.
        """
        components = build_ai_bom()
        document: dict[str, object] = {
            "aibomFormat": self.AI_BOM_FORMAT,
            "specVersion": self.AI_BOM_SPEC_VERSION,
            "generatedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "application": {
                "name": "NoRisk by FINLAI",
                "version": _NORISK_VERSION,
            },
            "components": [asdict(c) for c in components],
        }
        local_count = sum(1 for c in components if c.location == "local")
        cloud_count = len(components) - local_count
        _log.info(
            "AI-BOM generiert: %d lokal, %d cloud",
            local_count,
            cloud_count,
        )
        return document

    def export_json(self, document: dict[str, object], target: Path) -> Path:
        """Schreibt das AI-BOM-Dokument als JSON-Datei.

        Args:
            document: Dokument aus:meth:`generate`.
            target: Zielpfad (Eltern-Verzeichnis wird angelegt).

        Returns:
            Der geschriebene Pfad.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(document, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        _log.info("AI-BOM exportiert: %s", target)
        return target
