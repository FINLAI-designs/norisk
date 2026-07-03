"""finding_templates — Initiale Templates für die Storytelling-Engine (S1a).

Fünf kuratierte Templates, je eines aus den Bereichen Cert / API /
Network / CSAF / Dependency. Jedes Template ist eine reine Funktion::

    render(input: FindingInput) -> tuple[Urgency, headline, explanation, action]

Templates leben in einem Modul-Konstanten-Dict (:data:`TEMPLATES`),
indexiert nach ``(tool, finding_type)``. Der:mod:`narrative_builder`
schlägt darin nach.

Tonalität (Patrick-Vorgabe):
  - Du-Form, KMU-tauglich, kein Sicherheits-Buzzword-Salat.
  - Konkret und handlungsorientiert: "in {days_left} Tagen" statt
    "zeitnah", "ca. 5 Min" statt "kurzfristig umsetzbar".
  - Klare Aktion mit Werkzeug-Hinweis ("Let's Encrypt mit certbot",
    "WireGuard"), wo das hilft, nicht nur "härten".

STOP nach Sprint S1a (per Strategie): Patrick reviewt diese 5 Templates
anhand von:doc:`/docs/internal/STORYTELLING_EXAMPLES.md`. Erst danach
Roll-out auf die vollen 25 Templates der Strategie.

Schichtzugehörigkeit: core/ — kein PySide6, kein DB-Zugriff.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from collections.abc import Callable

from core.storytelling.schemas import FindingInput, Urgency
from core.vulnerability.domain.severity import Severity

# Render-Funktion: ``(FindingInput) -> (urgency, headline, explanation, action)``.
RenderFn = Callable[[FindingInput], tuple[Urgency, str, str, str]]


# ---------------------------------------------------------------------------
# Generische Severity → Urgency Mapping-Helper
# ---------------------------------------------------------------------------


def _urgency_from_severity(severity: Severity) -> Urgency:
    """Default-Mapping für Templates ohne kontextspezifische Modulation.

    ``CRITICAL`` → AKUT, ``HIGH`` → WICHTIG, ``MEDIUM`` → TREND, sonst
    ``KONTEXT``. Templates dürfen dieses Mapping überschreiben (z. B.
    cert_expiring lässt ``days_left`` einfließen).
    """
    if severity == Severity.CRITICAL:
        return Urgency.AKUT
    if severity == Severity.HIGH:
        return Urgency.WICHTIG
    if severity == Severity.MEDIUM:
        return Urgency.TREND
    return Urgency.KONTEXT


# ---------------------------------------------------------------------------
# Template 1 — cert_monitor / cert_expiring
# ---------------------------------------------------------------------------


def _render_cert_expiring(input: FindingInput) -> tuple[Urgency, str, str, str]:
    """Render-Funktion für ablaufende TLS-Zertifikate.

    Erwartet in ``input.details``:
        - ``days_left`` (int): Tage bis Ablauf. Negativ = bereits abgelaufen.
        - ``expires_at`` (str): ISO-Datum des Ablaufs ("2026-05-15").

    Urgency-Mapping (Tage dominieren über Severity, weil Cert-Ablauf
    zeitkritisch und nicht severity-skalierbar ist):
        - ≤ 0 Tage (abgelaufen) → AKUT
        - ≤ 7 Tage → AKUT
        - ≤ 30 Tage → WICHTIG
        - ≤ 90 Tage → TREND
        - > 90 Tage → KONTEXT
    """
    days_left = int(input.details.get("days_left", 999))
    expires_at = str(input.details.get("expires_at", "unbekannt"))

    if days_left <= 7:
        urgency = Urgency.AKUT
    elif days_left <= 30:
        urgency = Urgency.WICHTIG
    elif days_left <= 90:
        urgency = Urgency.TREND
    else:
        urgency = Urgency.KONTEXT

    if days_left <= 0:
        headline = (
            f"TLS-Zertifikat für {input.subject} ist seit "
            f"{abs(days_left)} Tagen abgelaufen"
        )
        explanation = (
            f"Das Zertifikat ist seit {abs(days_left)} Tagen ungültig. "
            f"Browser zeigen jetzt eine Sicherheitswarnung — "
            f"Kund:innen kommen nicht mehr durch."
        )
    else:
        headline = (
            f"TLS-Zertifikat für {input.subject} läuft "
            f"in {days_left} Tagen ab"
        )
        explanation = (
            f"Das Zertifikat läuft am {expires_at} aus, in {days_left} Tagen. "
            f"Danach erscheint im Browser eine Sicherheitswarnung und "
            f"der Zugriff wird blockiert."
        )

    action = (
        "Jetzt erneuern (Let's Encrypt mit certbot: ca. 5 Min) "
        "oder Auto-Renewal aktivieren."
    )
    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Template 2 — api_security / missing_security_header
# ---------------------------------------------------------------------------


def _render_missing_security_header(
    input: FindingInput,
) -> tuple[Urgency, str, str, str]:
    """Render-Funktion für fehlende Sicherheits-Header (HSTS, CSP, …).

    Erwartet in ``input.details``:
        - ``header_name`` (str): z. B. ``"Content-Security-Policy"``.
        - ``recommended_value`` (str): empfohlener Wert.
        - ``risk`` (str): Risiko-Substantiv im Dativ Plural, weil das
          Template ``"vor {risk}"`` formuliert
          (z. B. ``"Cross-Site-Scripting-Angriffen"``,
          ``"HTTPS-Downgrade-Angriffen"``).
    """
    urgency = _urgency_from_severity(input.severity)
    header_name = str(input.details.get("header_name", "?"))
    recommended_value = str(input.details.get("recommended_value", "?"))
    risk = str(input.details.get("risk", "typischen Angriffen"))

    headline = f"Sicherheits-Header '{header_name}' fehlt auf {input.subject}"
    explanation = (
        f"Der HTTP-Header '{header_name}' wird vom Server nicht gesetzt. "
        f"Ohne diesen Header schützt der Browser nicht zuverlässig vor "
        f"{risk} — Angreifer haben es leichter."
    )
    action = (
        f"Im Webserver hinzufügen: '{header_name}: {recommended_value}'. "
        f"Bei nginx/Apache: ~5 Min, kein Neustart nötig."
    )
    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Template 3 — network_scanner / exposed_admin_port
# ---------------------------------------------------------------------------


def _render_exposed_admin_port(
    input: FindingInput,
) -> tuple[Urgency, str, str, str]:
    """Render-Funktion für öffentlich erreichbare Admin-Ports (RDP, SSH, …).

    Erwartet in ``input.details``:
        - ``port`` (int): Port-Nummer.
        - ``protocol`` (str): ``"TCP"`` / ``"UDP"``.
        - ``service_name`` (str): ``"RDP"``, ``"SSH"``, ``"MySQL"`` …
    """
    urgency = _urgency_from_severity(input.severity)
    port = int(input.details.get("port", 0))
    protocol = str(input.details.get("protocol", "TCP"))
    service_name = str(input.details.get("service_name", "?"))

    headline = (
        f"{service_name}-Port {port}/{protocol} öffentlich "
        f"erreichbar auf {input.subject}"
    )
    explanation = (
        f"Port {port}/{protocol} ({service_name}) ist von außen ansprechbar. "
        f"Bruteforce-Angriffe auf Admin-Logins sind tagtäglicher Standard — "
        f"der Port wird bereits gescannt, garantiert."
    )
    action = (
        f"Im Router/Firewall: Port {port} nur für deine Office-IP erlauben "
        f"oder per VPN tunneln (z. B. WireGuard). Aufwand: ~15 Min."
    )
    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Template 4 — csaf_advisor / active_advisory_match
# ---------------------------------------------------------------------------


def _render_csaf_advisory_match(
    input: FindingInput,
) -> tuple[Urgency, str, str, str]:
    """Render-Funktion für CSAF-Advisories, die zum Techstack passen.

    Erwartet in ``input.details``:
        - ``vendor`` (str): z. B. ``"OpenSSL Project"``.
        - ``product`` (str): ``"openssl"``.
        - ``version`` (str): installierte Version.
        - ``advisory_id`` (str): ``"CVE-2024-3094"`` o. ä.
        - ``summary`` (str): kurze Hersteller-Zusammenfassung.
        - ``fixed_version`` (str): empfohlene Version mit Fix.
        - ``url`` (str): Link zum Advisory.
    """
    urgency = _urgency_from_severity(input.severity)
    vendor = str(input.details.get("vendor", "Hersteller"))
    product = str(input.details.get("product", input.subject))
    version = str(input.details.get("version", "?"))
    advisory_id = str(input.details.get("advisory_id", "?"))
    summary = str(input.details.get("summary", "")).strip()
    fixed_version = str(input.details.get("fixed_version", "?"))
    url = str(input.details.get("url", ""))

    headline = (
        f"Hersteller-Warnung: {vendor} meldet {advisory_id} für "
        f"{product} {version}"
    )
    explanation = (
        f"{vendor} hat {advisory_id} veröffentlicht"
        + (f": {summary}." if summary else ".")
        + " Diese Software läuft laut deinem Techstack bei dir — "
        "der Patch ist verfügbar."
    )
    action_url = f" Anleitung im Advisory: {url}" if url else ""
    action = f"Auf Version {fixed_version} updaten.{action_url}"
    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Template 5 — dependency_auditor / vulnerable_package
# ---------------------------------------------------------------------------


def _render_vulnerable_package(
    input: FindingInput,
) -> tuple[Urgency, str, str, str]:
    """Render-Funktion für bekannte CVEs in Python-Dependencies.

    Erwartet in ``input.details``:
        - ``package`` (str): Package-Name (z. B. ``"requests"``).
        - ``version`` (str): aktuell gepinnte Version.
        - ``cve_id`` (str): ``"CVE-2024-..."``.
        - ``summary`` (str): kurze CVE-Zusammenfassung.
        - ``fixed_version`` (str): erste Version mit Fix.
    """
    urgency = _urgency_from_severity(input.severity)
    package = str(input.details.get("package", input.subject))
    version = str(input.details.get("version", "?"))
    cve_id = str(input.details.get("cve_id", "?"))
    summary = str(input.details.get("summary", "")).strip()
    fixed_version = str(input.details.get("fixed_version", "?"))

    headline = (
        f"{package} {version} hat eine bekannte Schwachstelle ({cve_id})"
    )
    explanation = (
        f"{package} {version} ist in deiner requirements.txt gepinnt. "
        f"{cve_id}"
        + (f": {summary}." if summary else ".")
        + f" Fix verfügbar in {fixed_version}."
    )
    action = (
        f"In requirements.txt: '{package}=={fixed_version}', "
        f"dann 'pip install -r requirements.txt'. Aufwand: ~3 Min."
    )
    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Template 5b — dependency_auditor / unpinned_dependency
# ---------------------------------------------------------------------------


def _render_unpinned_dependency(
    input: FindingInput,
) -> tuple[Urgency, str, str, str]:
    """Render-Funktion für den aggregierten Versions-Pin-Hinweis.

    Genau EIN Hinweis-Finding pro Audit statt einer Task pro CVE:
    Packages ohne ``==``-Pin und ohne ermittelbare installierte Version
    können nicht gegen Advisories abgeglichen werden — das ist ein
    Hygiene-Hinweis, keine bestätigte Schwachstelle.

    Erwartet in ``input.details``:
        - ``count`` (int): Anzahl Packages mit nicht-abgleichbaren
          Advisories (ohne verifizierbare Version).
        - ``packages`` (str): kommagetrennte Package-Namen (gekürzt).
        - ``advisories`` (int): Anzahl nicht abgleichbarer Advisories.
        - ``source_file`` (str): geprüfte requirements-Datei.
    """
    urgency = _urgency_from_severity(input.severity)
    count = int(input.details.get("count", 0))
    packages = str(input.details.get("packages", "")).strip()
    advisories = int(input.details.get("advisories", 0))

    headline = (
        f"{count} Pakete ohne verifizierbare Version — "
        f"Versionsabgleich nicht möglich"
    )
    explanation = (
        f"Für {count} Pakete ({packages}) ist weder eine ==-Version gepinnt "
        f"noch eine installierte Version ermittelbar. {advisories} bekannte "
        f"Advisories konnten deshalb nicht abgeglichen werden — ob du "
        f"betroffen bist, ist unklar."
    )
    action = (
        "Versionen in der requirements.txt exakt pinnen (==), dann den "
        "Dependency-Audit erneut laufen lassen. Aufwand: ~10 Min."
    )
    return urgency, headline, explanation, action


def _render_hardening_check_failed(
    input: FindingInput,
) -> tuple[Urgency, str, str, str]:
    """Render-Funktion fuer fehlgeschlagene Hardening-Checks.

    Generisches Template fuer alle SH-001..SH-010-Checks aus dem
    Windows-Hardening-Scanner. Pro Check eine eigene Render-Funktion
    waere Overkill — die check-spezifische Information liegt in
    ``input.subject`` (= ``HardeningCheck.label``) und in den
    ``input.details``-Feldern.

    Erwartet in ``input.details``:
        - ``check_id`` (str): Stabile SH-XXX-ID fuer Audit-Referenz.
        - ``label`` (str): User-lesbarer Check-Name (deutsch).
        - ``detail`` (str): Optional eine kurze Beschreibung warum
          der Check fehlgeschlagen ist (z. B. ``"EnableLUA=0"``).
    """
    urgency = _urgency_from_severity(input.severity)
    check_id = str(input.details.get("check_id", "?"))
    label = str(input.details.get("label", input.subject))
    detail = str(input.details.get("detail", "")).strip()

    headline = f"Hardening-Check fehlgeschlagen: {label}"

    if detail:
        explanation = (
            f"Der Check {check_id} ({label}) ist auf diesem System nicht "
            f"erfuellt: {detail}. Diese Basis-Schutzmechanismen entscheiden "
            f"ob ein Angriff stoppt oder durchgeht — sie sollten ohne "
            f"Ausnahme aktiv sein."
        )
    else:
        explanation = (
            f"Der Check {check_id} ({label}) ist auf diesem System nicht "
            f"erfuellt. Diese Basis-Schutzmechanismen entscheiden ob ein "
            f"Angriff stoppt oder durchgeht — sie sollten ohne Ausnahme "
            f"aktiv sein."
        )

    action = (
        f"Im Lagebild → Risikobriefing-Sektion 'System-Hardening': "
        f"die Konfiguration fuer {label} pruefen und nachziehen. Bei "
        f"Windows-Defaults reichen meist 1-2 Klicks in den System-"
        f"einstellungen."
    )
    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Templates 6–10 — patch_monitor
# ---------------------------------------------------------------------------


def _render_patch_recommendation(
    input: FindingInput,
) -> tuple[Urgency, str, str, str]:
    """Generisches Template fuer alle 5 Patch-Recommendation-Klassen.

    Eine einzige Render-Funktion fuer alle finding_types, die der
    ``storytelling_adapter`` aus ``PatchScanResult.recommendation``
    ableitet. Die individuelle Action-Tonalitaet kommt aus dem
    ``recommendation``-Detail-Feld.

    Erwartet in ``input.details``:
        - ``recommendation`` (str): originale Recommendation-Klasse aus
          ``core.patch_result.Recommendation``.
        - ``name`` (str): User-lesbarer Paket-Name.
        - ``vendor`` (str): Hersteller (optional).
        - ``installed_version`` (str): aktuell installierte Version.
        - ``available_version`` (str): neuste verfuegbare Version
          (leer bei EOL).
        - ``cve_ids`` (list[str]): zugehoerige CVE-IDs (kann leer sein).
        - ``cvss_max`` (float): hoechster CVSS-Score der gematchten CVEs.
        - ``exploit_available`` (bool): KEV-Hit oder Exploit-DB-Match.
        - ``eol`` (bool): Vendor-EOL-Status.
    """
    recommendation = str(input.details.get("recommendation", ""))
    name = str(input.details.get("name", input.subject))
    installed = str(input.details.get("installed_version", "?"))
    available = str(input.details.get("available_version", ""))
    cve_ids = input.details.get("cve_ids", []) or []
    cvss_max = float(input.details.get("cvss_max", 0.0) or 0.0)
    exploit = bool(input.details.get("exploit_available", False))

    if recommendation == "update_urgent":
        urgency = Urgency.AKUT
        headline = f"{name} jetzt updaten — aktive Bedrohung"
        cve_note = (
            f" (CVE: {', '.join(cve_ids[:2])}{'…' if len(cve_ids) > 2 else ''})"
            if cve_ids else ""
        )
        exploit_note = " mit oeffentlich verfuegbarem Exploit" if exploit else ""
        explanation = (
            f"Fuer {name} {installed} liegt ein aktives Sicherheits-Update "
            f"vor{cve_note}. CVSS {cvss_max:.1f}{exploit_note} — das ist "
            f"die Sorte Schwachstelle, die in Crimeware-Kits zuerst "
            f"eingebaut wird."
        )
        action = (
            f"``winget upgrade {name}`` (oder per Patch-Monitor-Button) "
            f"jetzt durchfuehren. Aufwand: 1-2 Minuten."
        )
    elif recommendation == "eol_no_patch":
        urgency = Urgency.WICHTIG
        headline = f"{name} ist End-of-Life — Migration einplanen"
        explanation = (
            f"{name} (Version {installed}) wird vom Hersteller nicht mehr "
            f"mit Sicherheits-Updates versorgt. Auch bekannte Schwachstellen "
            f"bleiben offen, weil kein Patch mehr kommt."
        )
        action = (
            "Nachfolge-Version oder Alternativ-Produkt evaluieren und "
            "migrieren. Bei Server-Anwendungen typisch Wartungsfenster "
            "+ Konfigurations-Anpassung — kein Quick-Win."
        )
    elif recommendation == "workaround_available":
        urgency = Urgency.WICHTIG
        headline = f"{name}: Workaround aktivieren, Patch fehlt noch"
        cve_note = f" ({', '.join(cve_ids[:1])})" if cve_ids else ""
        explanation = (
            f"Fuer {name} {installed} ist eine Schwachstelle bekannt{cve_note}, "
            f"aber noch kein Patch verfuegbar. Der Hersteller hat einen "
            f"Workaround dokumentiert (Feature deaktivieren / Konfiguration "
            f"anpassen)."
        )
        action = (
            "Workaround aus dem CSAF-Advisor anwenden, dann auf Patch-"
            "Release pruefen (in der Regel innerhalb von Wochen)."
        )
    elif recommendation == "patch_with_csaf_context":
        urgency = Urgency.WICHTIG
        version_hint = f" auf {available}" if available else ""
        cve_note = f" (CVE: {', '.join(cve_ids[:1])})" if cve_ids else ""
        headline = f"{name}{version_hint} updaten mit Hersteller-Hinweis"
        explanation = (
            f"Update fuer {name} ist verfuegbar{cve_note}. Der Hersteller "
            f"hat im Advisory zusaetzliche Schritte dokumentiert "
            f"(z. B. Konfigurations-Migration nach dem Update)."
        )
        action = (
            "Update durchfuehren, dann den CSAF-Advisor oeffnen und die "
            "Vendor-Anweisungen pruefen. Aufwand: 10-30 Minuten."
        )
    else:  # patch_update_available (Default-Pfad fuer update/update_available)
        urgency = Urgency.TREND
        version_hint = f" {available}" if available else ""
        headline = f"{name}: Version{version_hint} verfuegbar"
        explanation = (
            f"Eine neuere Version von {name} ist veroeffentlicht "
            f"({installed} → {available or 'aktuell'}). Keine bekannten "
            f"Sicherheits-CVEs in der alten Version — Update bei "
            f"Gelegenheit einplanen."
        )
        action = (
            f"Update bei naechstem Wartungsfenster durchfuehren "
            f"(``winget upgrade {name}``). Kein Sofort-Druck."
        )

    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Templates 11–16 — network_monitor E)
# ---------------------------------------------------------------------------


def _fmt_bytes_de(num_bytes: int) -> str:
    """Byte-Menge dezimal mit deutscher Komma-Notation (lokaler Helfer)."""
    if num_bytes < 1000:
        return f"{int(num_bytes)} B"
    value = float(num_bytes)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1000.0
        if value < 1000:
            return f"{value:.1f} {unit}".replace(".", ",")
    return f"{value:.1f} PB".replace(".", ",")


def _render_network_anomaly(input: FindingInput) -> tuple[Urgency, str, str, str]:
    """Generisches Template fuer alle 6 network_monitor-Anomalie-Typen.

    Differenzierung via ``input.finding_type`` (der Adapter mappt jeden
    ``AnomalyType`` auf einen finding_type). Erwartet in ``input.details``:
    ``process_name``, ``value_bytes`` (bei DNS: Query-Anzahl), ``remote_ip``,
    ``detail`` (Pfad / Sample-Query / CDN-Name).
    """
    ftype = input.finding_type
    proc = str(input.details.get("process_name") or input.subject)
    value = int(input.details.get("value_bytes", 0) or 0)
    remote_ip = str(input.details.get("remote_ip", "") or "")
    detail = str(input.details.get("detail", "") or "")

    if ftype == "volume_anomaly":
        urgency = Urgency.AKUT
        headline = f"{proc}: {_fmt_bytes_de(value)} Upload in einer Stunde"
        explanation = (
            f"Der Prozess {proc} hat in einer Stunde {_fmt_bytes_de(value)} "
            f"hochgeladen — weit ueber dem Normalwert. Das kann ein legitimer "
            f"Bulk-Upload sein oder ein Hinweis auf Daten-Abfluss."
        )
        action = (
            "Im Netzwerkmonitor pruefen, wohin die Daten gehen, und den Prozess "
            "bei Verdacht im Task-Manager beenden. Aufwand: ca. 5 Min."
        )
    elif ftype == "single_ip_exfil":
        urgency = Urgency.AKUT
        ip_note = f" ({remote_ip})" if remote_ip else ""
        headline = f"{proc}: {_fmt_bytes_de(value)} an eine einzelne IP{ip_note}"
        explanation = (
            f"{proc} hat {_fmt_bytes_de(value)} an eine einzelne externe "
            f"IP{ip_note} gesendet. Solche Bulk-Transfers an EINE Adresse sind "
            f"ein typisches Exfiltrations-Muster (Datendiebstahl)."
        )
        action = (
            f"Die Verbindung pruefen und {remote_ip or 'die IP'} bei Verdacht in "
            f"der Firewall blockieren; Prozess untersuchen. Aufwand: ca. 10 Min."
        )
    elif ftype == "unknown_process":
        urgency = Urgency.AKUT
        path = detail or "%TEMP%/%APPDATA%"
        headline = f"{proc} sendet aus einem Temp-Verzeichnis"
        explanation = (
            f"{proc} laeuft aus einem Benutzer-/Temp-Pfad ({path}) und sendet "
            f">10 MB nach aussen. Schadsoftware startet oft aus solchen "
            f"Verzeichnissen — fuer regulaere Software ist das untypisch."
        )
        action = (
            "Pfad und Signatur des Programms pruefen; bei Unklarheit den Prozess "
            "beenden und einen Viren-Scan starten. Aufwand: ca. 10 Min."
        )
    elif ftype == "dns_tunneling":
        urgency = Urgency.WICHTIG
        headline = f"{proc}: ungewoehnlich viele DNS-Anfragen ({value}/Min)"
        sample = f" Beispiel: {detail}." if detail else ""
        explanation = (
            f"{proc} stellt sehr viele DNS-Anfragen ({value} pro Minute). Das "
            f"kann auf DNS-Tunneling oder eine DGA-Malware hindeuten, die Daten "
            f"ueber DNS schmuggelt.{sample}"
        )
        action = (
            "Die abgefragten Domains im Netzwerkmonitor pruefen; bei "
            "verdaechtigen Mustern den Prozess isolieren. Aufwand: ca. 10 Min."
        )
    elif ftype == "off_hours":
        urgency = Urgency.WICHTIG
        headline = f"{proc}: {_fmt_bytes_de(value)} Outbound in der Nacht"
        explanation = (
            f"{proc} hat zwischen 22 und 7 Uhr {_fmt_bytes_de(value)} nach "
            f"aussen gesendet. Naechtlicher Traffic ohne Nutzer-Aktivitaet ist "
            f"erklaerungsbeduerftig — legitimes Backup/Sync oder unerwuenschte "
            f"Hintergrund-Aktivitaet."
        )
        action = (
            "Pruefen, ob der Prozess ein bekannter Backup-/Sync-Dienst ist; "
            "sonst Autostart deaktivieren und beobachten. Aufwand: ca. 5 Min."
        )
    else:  # game_download (Default)
        urgency = Urgency.TREND
        cdn = f" ({detail})" if detail else ""
        headline = f"{proc}: Verbindung zu einem Game-/Download-CDN"
        explanation = (
            f"{proc} kommuniziert mit einem bekannten Spiele-/Download-"
            f"Netzwerk{cdn}. Meist harmlos (Spiele-Update), auf einem "
            f"Arbeitsgeraet aber ggf. unerwuenscht."
        )
        action = (
            "Falls auf einem Arbeitsgeraet unerwuenscht: die Anwendung pruefen "
            "oder entfernen. Sonst ignorieren. Aufwand: ca. 2 Min."
        )

    return urgency, headline, explanation, action


# ---------------------------------------------------------------------------
# Registry — der einzige Lookup-Punkt für den narrative_builder
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Template — system_tuner (Datenschutz-/Telemetrie-Empfehlungen)
# ---------------------------------------------------------------------------


def _render_privacy_default(input: FindingInput) -> tuple[Urgency, str, str, str]:
    """Template fuer system_tuner-Empfehlungen (``privacy_default_risky``).

    Ein generisches Template fuer alle Datenschutz-/Telemetrie-/Dienst-
    Empfehlungen. Erwartet in ``input.details``: ``rationale``, ``docs_url``,
    ``category``, ``risk_tier``, ``current_value``, ``desired_value``.
    """
    urgency = _urgency_from_severity(input.severity)
    title = input.subject
    rationale = str(input.details.get("rationale", "")).strip()
    headline = f"Datenschutz-Empfehlung offen: {title}"
    explanation = (
        (f"{rationale} " if rationale else "")
        + "Diese Windows-Standardeinstellung gibt mehr Daten preis als noetig. "
        "Die Aenderung ist umkehrbar und wird vor dem Anwenden im Detail gezeigt."
    ).strip()
    action = (
        "Unter 'System optimieren' die Empfehlung pruefen und (als Pro) anwenden "
        "— mit Wiederherstellungspunkt und Ein-Klick-Ruecknahme."
    )
    return urgency, headline, explanation, action


# Schlüssel: ``(tool, finding_type)``. Wird vom:func:`narrative_builder.build_story`
# konsumiert. Neue Templates werden hier registriert; im Sprint S1a sind es
# 5 — die volle Strategie sieht 25 vor (folgt nach Patrick-Tonalitäts-Review).
TEMPLATES: dict[tuple[str, str], RenderFn] = {
    ("cert_monitor", "cert_expiring"): _render_cert_expiring,
    ("api_security", "missing_security_header"): _render_missing_security_header,
    ("network_scanner", "exposed_admin_port"): _render_exposed_admin_port,
    ("csaf_advisor", "active_advisory_match"): _render_csaf_advisory_match,
    ("dependency_auditor", "vulnerable_package"): _render_vulnerable_package,
    # aggregierter Hinweis statt Task-Flut bei unbekannter Version.
    ("dependency_auditor", "unpinned_dependency"): _render_unpinned_dependency,
    # ein Template fuer alle 10 SH-Checks (system_scanner).
    ("system_scanner", "hardening_check_failed"): _render_hardening_check_failed,
    # ein generisches Template fuer alle 5 Patch-Recommendation-
    # Klassen (patch_monitor). Differenzierung via input.details.recommendation.
    (
        "patch_monitor", "patch_update_urgent",
    ): _render_patch_recommendation,
    (
        "patch_monitor", "patch_eol_no_patch",
    ): _render_patch_recommendation,
    (
        "patch_monitor", "patch_workaround_available",
    ): _render_patch_recommendation,
    (
        "patch_monitor", "patch_with_csaf_context",
    ): _render_patch_recommendation,
    (
        "patch_monitor", "patch_update_available",
    ): _render_patch_recommendation,
    # E: ein generisches Template fuer alle 6 network_monitor-Anomalie-
    # Typen. Differenzierung via input.finding_type.
    ("network_monitor", "volume_anomaly"): _render_network_anomaly,
    ("network_monitor", "off_hours"): _render_network_anomaly,
    ("network_monitor", "single_ip_exfil"): _render_network_anomaly,
    ("network_monitor", "game_download"): _render_network_anomaly,
    ("network_monitor", "unknown_process"): _render_network_anomaly,
    ("network_monitor", "dns_tunneling"): _render_network_anomaly,
    # system_tuner (Phase 1c): ein Template fuer alle Datenschutz-Empfehlungen.
    ("system_tuner", "privacy_default_risky"): _render_privacy_default,
}


def list_template_keys() -> list[tuple[str, str]]:
    """Gibt alle registrierten ``(tool, finding_type)``-Kombinationen zurück.

    Reihenfolge ist deterministisch (alphabetisch nach Tool, dann Type),
    damit Examples-Doku reproduzierbar ist.
    """
    return sorted(TEMPLATES.keys())
