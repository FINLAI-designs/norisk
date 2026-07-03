"""
provider_registry — Vordefinierte CSAF Trusted Provider für NoRisk.

Kuratierte Provider werden beim ersten Start in die DB geschrieben.
Beim Update synchronisiert ``AdvisoryRepository._sync_curated_providers``
vorhandene Eintraege auf die aktuellen URLs/``enabled``-Werte aus
dieser Datei — Patrick muss bei URL-Migrationen kein DB-Reset machen.

Quelle der Wahrheit: BSI CSAF-Aggregator
(``https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json``).
Stand der URLs: 2026-05-14 — alle gegen ``HTTP 200`` verifiziert.

Auswahl-Kriterium fuer die DACH-Mittelstand-Zielgruppe:
  * **Default-Enabled (6)**: BSI, CISA, Red Hat, Siemens, Schneider
    Electric, Open-Xchange — decken Steuerkanzlei-/KMU-Stacks ab
    (Mailserver, Linux-Server, OT-Komponenten, US-Advisories).
  * **Default-Disabled (8)**: ABB, Huawei, SICK, KUNBUS, Intevation,
    Stackable, IDS Innomic, Nozomi — nur fuer Spezial-Stacks
    relevant, kosten sonst Fetch-Zeit.

Schichtzugehörigkeit: data/ — keine GUI-Imports, nur Datenzugriff.

Author: Patrick Riederich
Version: 2.0 follow-up, 2026-05-14: URLs an BSI-Aggregator
              angeglichen, CISA-/Red-Hat-URLs migriert, 11 weitere
              Trusted-Provider ergaenzt.)
"""

from __future__ import annotations

from tools.csaf_advisor.domain.csaf_provider import CsafProvider

# ---------------------------------------------------------------------------
# Kuratierte Provider (Stand: 2026-05-14)
# ---------------------------------------------------------------------------

CURATED_CSAF_PROVIDERS: list[CsafProvider] = [
    # --- Default-Enabled (6) ---------------------------------------------
    CsafProvider(
        id="csaf-bsi",
        name="BSI (Deutschland)",
        provider_url=(
            "https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json"
        ),
        # Kein hardcoded ``feed_url``: die fruehere
        # ``white/feed.json`` liefert seit 2026-05 HTTP 404. Strategie 2
        # in ``CsafDownloader._extract_advisory_urls`` ermittelt die
        # aktuellen Feed-URLs dynamisch aus der provider-metadata.json
        # (BSI listet dort heute 6 rolie-Feeds, white + green TLP).
        feed_url="",
        source="curated",
        enabled=True,
    ),
    CsafProvider(
        id="csaf-cisa",
        name="CISA (USA)",
        # Neue URL seit 2026-05: well-known-Pfad existiert nicht mehr,
        # provider-metadata wurde unter ``/sites/default/files/csaf/``
        # weiter veroeffentlicht.
        provider_url=(
            "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=True,
    ),
    CsafProvider(
        id="csaf-redhat",
        name="Red Hat",
        # Neue URL seit 2025-12: alter access.redhat.com/.well-known/csaf
        # -Pfad ist weg, autoritativer Endpoint ist security.access.
        provider_url=(
            "https://security.access.redhat.com/data/csaf/v2/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=True,
    ),
    CsafProvider(
        id="csaf-siemens",
        name="Siemens ProductCERT",
        provider_url=(
            "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=True,
    ),
    CsafProvider(
        id="csaf-schneider-electric",
        name="Schneider Electric",
        provider_url="https://www.se.com/.well-known/csaf/provider-metadata.json",
        feed_url="",
        source="curated",
        enabled=True,
    ),
    CsafProvider(
        id="csaf-open-xchange",
        name="Open-Xchange (E-Mail-Server)",
        provider_url=(
            "https://www.open-xchange.com/.well-known/csaf/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=True,
    ),
    # --- Default-Disabled (8): Spezial-Stack-relevant --------------------
    CsafProvider(
        id="csaf-abb",
        name="ABB (OT/Automation)",
        provider_url="https://psirt.abb.com/.well-known/csaf/provider-metadata.json",
        feed_url="",
        source="curated",
        enabled=False,
    ),
    CsafProvider(
        id="csaf-huawei",
        name="Huawei PSIRT",
        provider_url="https://www.huawei.com/.well-known/csaf/provider-metadata.json",
        feed_url="",
        source="curated",
        enabled=False,
    ),
    CsafProvider(
        id="csaf-sick",
        name="SICK (Industrie-Sensorik)",
        provider_url="https://www.sick.com/.well-known/csaf/provider-metadata.json",
        feed_url="",
        source="curated",
        enabled=False,
    ),
    CsafProvider(
        id="csaf-kunbus",
        name="KUNBUS (Industrie-Gateways)",
        provider_url=(
            "https://psirt.kunbus.com/.well-known/csaf/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=False,
    ),
    CsafProvider(
        id="csaf-intevation",
        name="Intevation GmbH",
        provider_url="https://intevation.de/.well-known/csaf/provider-metadata.json",
        feed_url="",
        source="curated",
        enabled=False,
    ),
    CsafProvider(
        id="csaf-stackable",
        name="Stackable (Big-Data)",
        provider_url=(
            "https://advisories.stackable.tech/.well-known/csaf/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=False,
    ),
    CsafProvider(
        id="csaf-nozomi",
        name="Nozomi Networks (OT-Monitoring)",
        provider_url=(
            "https://csaf.data.security.nozominetworks.com/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=False,
    ),
    CsafProvider(
        id="csaf-innomic",
        name="IDS Innomic Schwingungsmesstechnik",
        provider_url=(
            "https://www.innomic.com/.well-known/csaf/provider-metadata.json"
        ),
        feed_url="",
        source="curated",
        enabled=False,
    ),
]
