"""
scoring_service — Score-Berechnung für das Kunden-Assessment.

Berechnet Kategorie-Scores und den gewichteten Gesamtscore.
Pure Logik ohne Seiteneffekte — alle Inputs als Parameter.

Schichtzugehörigkeit: domain/ — keine Imports aus application/data/gui.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from tools.customer_audit.domain.entities import (
    IR_SCORE_MAX_PRIVAT,
    BackupAuditResult,
    CategoryScore,
    IncidentResponsePlan,
    InfrastructureData,
    NetworkData,
    OrganizationalData,
    SovereigntyAuditResult,
    compute_backup_score,
    compute_ir_score,
    compute_sovereignty_score,
)

# ---------------------------------------------------------------------------
# Gewichtungen der Kategorien im Gesamtscore
# ---------------------------------------------------------------------------
#
# Bestehende drei Kategorien (Infra/Org/Netzwerk)
# behalten zusammen 70 % Gewicht (vorher 100 %). Die drei neuen
# Kategorien aus Paket 1 (Backup / Souveraenitaet / IR-Plan) bekommen
# je 10 % — sie deuten organisatorische Resilienz an, was technisch-
# hartes Scoring (Infra) ergaenzt aber nicht ersetzt.

WEIGHT_INFRASTRUCTURE: float = 0.25
WEIGHT_ORGANIZATIONAL: float = 0.25
WEIGHT_NETWORK: float = 0.20
WEIGHT_BACKUP: float = 0.10
WEIGHT_SOVEREIGNTY: float = 0.10
WEIGHT_INCIDENT_RESPONSE: float = 0.10

#: Max-Werte der Subscores fuer Normalisierung auf 0..100.
_BACKUP_MAX: int = 15
_IR_MAX: int = 15
_SOVEREIGNTY_MIN: int = -50
_SOVEREIGNTY_MAX: int = 10

# ---------------------------------------------------------------------------
# Risikostufen
# ---------------------------------------------------------------------------

_RISK_THRESHOLDS: list[tuple[float, str]] = [
    (75.0, "Niedrig"),
    (55.0, "Mittel"),
    (35.0, "Hoch"),
]
_RISK_KRITISCH = "Kritisch"


def score_to_risk_level(score: float) -> str:
    """Wandelt einen Score in eine Risikostufe um.

    Args:
        score: Score 0–100.

    Returns:
        Risikostufe: "Niedrig", "Mittel", "Hoch" oder "Kritisch".
    """
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return _RISK_KRITISCH


def _ja_nein_score(value: str) -> float:
    """Wertet eine Ja/Nein/Teilweise-Antwort in einen Score um.

    Args:
        value: "Ja", "Nein" oder "Teilweise".

    Returns:
        Score 0–100.
    """
    mapping = {"Ja": 100.0, "Teilweise": 50.0, "Nein": 0.0}
    return mapping.get(value, 0.0)


def _status_score(value: str) -> float:
    """Wertet einen aktiv/inaktiv/unbekannt-Status in einen Score um.

    Args:
        value: "aktiv", "inaktiv" oder "unbekannt".

    Returns:
        Score 0–100.
    """
    mapping = {"aktiv": 100.0, "inaktiv": 0.0, "unbekannt": 40.0}
    return mapping.get(value, 40.0)


# ---------------------------------------------------------------------------
# Kategorie-Score-Funktionen
# ---------------------------------------------------------------------------


def calculate_infrastructure_score(data: InfrastructureData) -> float:
    """Berechnet den Infrastruktur-Score.

    Gewichtung der Teilbereiche:
      - Antivirus: 30 %
      - Firewall: 25 %
      - Verschlüsselung: 30 %
      - Remote-Access: 15 % (Penalty für Risiko-Tools)

    Args:
        data: InfrastructureData des Kunden.

    Returns:
        Score 0–100.
    """
    av_score = _status_score(data.antivirus_status)
    fw_score = _status_score(data.firewall_status)

    # Verschlüsselung: "Keine" = 0, "Unbekannt" = 30, sonst = 100
    if not data.verschluesselung or data.verschluesselung == ["Keine"]:
        enc_score = 0.0
    elif data.verschluesselung == ["Unbekannt"] or "Keine" in data.verschluesselung:
        enc_score = 30.0
    else:
        enc_score = 100.0

    # Remote-Access: Risiko-Tools senken den Score
    _RISKY_TOOLS = {"TeamViewer", "AnyDesk", "VNC"}
    risky_count = sum(1 for t in data.remote_access_tools if t in _RISKY_TOOLS)
    remote_score = max(0.0, 100.0 - risky_count * 25.0)
    # Wenn "Keine" gesetzt → kein Risiko
    if "Keine" in data.remote_access_tools:
        remote_score = 100.0

    score = av_score * 0.30 + fw_score * 0.25 + enc_score * 0.30 + remote_score * 0.15
    return round(min(100.0, max(0.0, score)), 1)


def calculate_organizational_score(
    data: OrganizationalData, *, ist_privatperson: bool = False
) -> float:
    """Berechnet den Organisationssicherheits-Score.

    Alle Kategorien gleichgewichtet (1/n je Kategorie). Seit 3f-ii
-Backlog, 2026-05-17) ist `avv_key_separate_storage` Teil der
    Bewertung — Encryption-Audit nach NoRisk-Audit-Paket-3 §6.3.

    Args:
        data: OrganizationalData des Kunden.
        ist_privatperson: Wenn ``True``, fallen enterprise-typische Items
            (``zugangskontrollen``) aus dem Nenner statt als 0 zu zaehlen — eine
            Privatperson/ein Kleinstbetrieb wird fuer ihr Fehlen nicht bestraft.

    Returns:
        Score 0–100 (100.0, wenn — theoretisch — kein Item zaehlt).
    """
    values = [
        _ja_nein_score(data.backup_strategie),
        _ja_nein_score(data.update_management),
        _ja_nein_score(data.mitarbeitersensibilisierung),
        _ja_nein_score(data.incident_response_plan),
        _ja_nein_score(data.dsgvo_konformitaet),
        _ja_nein_score(data.avv_key_separate_storage),
    ]
    # Zugangskontrollen sind nur bei Mehr-Personen-Betrieben sinnvoll.
    if not ist_privatperson:
        values.append(_ja_nein_score(data.zugangskontrollen))
    return round(sum(values) / len(values), 1) if values else 100.0


def calculate_network_score(
    data: NetworkData, *, ist_privatperson: bool = False
) -> float:
    """Berechnet den Netzwerksicherheits-Score.

    Gewichtung der Teilbereiche:
      - Netzwerksegmentierung: 25 %
      - WLAN-Sicherheit: 25 %
      - Offene Ports bekannt: 20 %
      - IDS/IPS: 15 %
      - Letzter Pentest: 15 %

    Args:
        data: NetworkData des Kunden.
        ist_privatperson: Wenn ``True``, fallen enterprise-typische Items
            (Netzwerksegmentierung, IDS/IPS, letzter Pentest) aus der Wertung —
            ihre Gewichte werden entfernt und der Rest re-normalisiert, sodass
            ihr Fehlen den Score nicht drueckt.

    Returns:
        Score 0–100.
    """
    seg_score = _ja_nein_score(data.netzwerksegmentierung)

    _WLAN_SCORES = {
        "WPA3": 100.0,
        "WPA2": 80.0,
        "WEP": 10.0,
        "Offen": 0.0,
        "Unbekannt": 40.0,
    }
    wlan_score = _WLAN_SCORES.get(data.wlan_sicherheit, 40.0)

    ports_score = 100.0 if data.offene_ports_bekannt == "Ja" else 50.0
    ids_score = 100.0 if data.ids_ips_vorhanden == "Ja" else 50.0

    # Pentest: anhand von Keywords beurteilen
    pt = data.letzter_pentest.lower().strip()
    if pt in ("nie", ""):
        pentest_score = 0.0
    elif pt == "unbekannt":
        pentest_score = 40.0
    else:
        # Versuch: Jahreszahl parsen
        import re  # noqa: PLC0415

        year_match = re.search(r"(20\d{2})", pt)
        if year_match:
            from datetime import date  # noqa: PLC0415

            year = int(year_match.group(1))
            age = date.today().year - year
            if age <= 1:
                pentest_score = 100.0
            elif age <= 3:
                pentest_score = 60.0
            else:
                pentest_score = 20.0
        else:
            pentest_score = 40.0

    # (Score, Gewicht, enterprise-only?). Enterprise-Items fallen bei
    # Privatpersonen weg; die verbleibenden Gewichte werden re-normalisiert.
    weighted = [
        (wlan_score, 0.25, False),
        (ports_score, 0.20, False),
        (seg_score, 0.25, True),
        (ids_score, 0.15, True),
        (pentest_score, 0.15, True),
    ]
    aktiv = [
        (s, w) for s, w, ent in weighted if not (ist_privatperson and ent)
    ]
    total_weight = sum(w for _, w in aktiv)
    if total_weight <= 0:
        return 100.0
    score = sum(s * w for s, w in aktiv) / total_weight
    return round(min(100.0, max(0.0, score)), 1)


def calculate_backup_audit_score(audit: BackupAuditResult) -> float:
    """Normalisiert den Backup-Score (0..15) auf 0..100.

    das Backup-Score-Rohformat liegt im Bereich
    0..15. Hier auf die Gesamtscore-Skala (0..100) hochgerechnet,
    damit die Gewichtung in:func:`calculate_overall_score` greift.

    Wenn der Audit nicht durchlaufen wurde (``info_block_shown=False``),
    liefern wir 0.0 — das genuegt der Caller-Konvention, dass
:func:`build_category_scores` die Kategorie nur dann aufnimmt,
    wenn explizit ``was_completed=True`` uebergeben wird.
    """
    if not audit.info_block_shown:
        return 0.0
    raw = audit.score if audit.score else compute_backup_score(audit)
    return round((raw / _BACKUP_MAX) * 100.0, 1)


def calculate_ir_plan_score(
    plan: IncidentResponsePlan, *, ist_privatperson: bool = False
) -> float:
    """Normalisiert den IR-Plan-Score (0..15 bzw. 0..10) auf 0..100.

    Bei nicht-durchlaufenem Plan (``info_block_shown=False``): 0.0.

    Args:
        plan: Der IR-Plan-Eintrag.
        ist_privatperson: Wenn ``True``, entfallen Eskalationskette + Forensik-
            Vendor (enterprise-only) aus Punkten UND Maximum — frisch gerechnet,
            ohne den ``plan.score``-Cache (der das volle Maximum annimmt).
    """
    if not plan.info_block_shown:
        return 0.0
    if ist_privatperson:
        raw = compute_ir_score(plan, ist_privatperson=True)
        return round((raw / IR_SCORE_MAX_PRIVAT) * 100.0, 1)
    raw = plan.score if plan.score else compute_ir_score(plan)
    return round((raw / _IR_MAX) * 100.0, 1)


def calculate_sovereignty_audit_score(audit: SovereigntyAuditResult) -> float:
    """Normalisiert den Sovereignty-Score (-50..+10) auf 0..100.

    Linear: ``score=-50`` -> 0, ``score=+10`` -> 100, ``score=0``
    (alles EU-souveraen) -> ca. 83.

    Bei nicht-durchlaufenem Audit (``info_block_shown=False``): 0.0 —
    der reine Default-Wert score=0 wuerde sonst auf 83 normalisiert
    werden und die Kategorie faelschlich als "sehr gut" anzeigen.
    """
    if not audit.info_block_shown:
        return 0.0
    raw = audit.score if audit.score else compute_sovereignty_score(audit)
    normalized = (raw - _SOVEREIGNTY_MIN) / (_SOVEREIGNTY_MAX - _SOVEREIGNTY_MIN)
    return round(max(0.0, min(100.0, normalized * 100.0)), 1)


def calculate_overall_score(
    infra: float,
    org: float,
    network: float,
    backup: float | None = None,
    sovereignty: float | None = None,
    incident_response: float | None = None,
) -> float:
    """Berechnet den gewichteten Gesamtscore mit dynamischer Normalisierung.

    Review-Followup: die optionalen Sub-Audit-Scores
    werden nur in den Score eingerechnet, wenn sie tatsaechlich
    uebergeben wurden (``None`` = "nicht durchlaufen"). Die verbleibenden
    Gewichte werden auf die aktiven Kategorien re-normalisiert. Damit
    bleibt ein altes 3-Kategorien-Audit (vor) auf der 100 %-
    Skala — eine Re-Save-Operation drueckt den Score nicht stumm um die
    fehlenden 30 % nach unten.

    Args:
        infra: Infrastruktur-Score (0..100).
        org: Organisationssicherheits-Score.
        network: Netzwerksicherheits-Score.
        backup: Backup-Audit-Score; ``None`` = nicht durchlaufen.
        sovereignty: Sovereignty-Audit-Score; ``None`` analog.
        incident_response: IR-Plan-Score; ``None`` analog.

    Returns:
        Gewichteter Gesamtscore 0–100.
    """
    components: list[tuple[float, float]] = [
        (infra, WEIGHT_INFRASTRUCTURE),
        (org, WEIGHT_ORGANIZATIONAL),
        (network, WEIGHT_NETWORK),
    ]
    if backup is not None:
        components.append((backup, WEIGHT_BACKUP))
    if sovereignty is not None:
        components.append((sovereignty, WEIGHT_SOVEREIGNTY))
    if incident_response is not None:
        components.append((incident_response, WEIGHT_INCIDENT_RESPONSE))

    total_weight = sum(w for _, w in components)
    if total_weight <= 0:
        return 0.0
    weighted = sum(value * w for value, w in components)
    score = weighted / total_weight
    return round(min(100.0, max(0.0, score)), 1)


def build_category_scores(
    infra_score: float,
    org_score: float,
    network_score: float,
    backup_score: float | None = None,
    sovereignty_score: float | None = None,
    ir_score: float | None = None,
) -> list[CategoryScore]:
    """Erstellt die CategoryScore-Liste aus allen Teilscores.

    Args:
        infra_score: Infrastruktur-Score.
        org_score: Organisationssicherheits-Score.
        network_score: Netzwerksicherheits-Score.
        backup_score: Backup-Audit-Score, ``None`` wenn der
                            Sub-Audit nicht durchlaufen wurde.
        sovereignty_score: Sovereignty-Audit-Score, ``None`` wenn
                            nicht durchlaufen.
        ir_score: IR-Plan-Score, ``None`` wenn nicht
                            durchlaufen.

    Returns:
        Liste mit allen CategoryScore-Eintraegen (3-6 je nach Audit-
        Vollstaendigkeit). Echte Score-Werte von ``0.0`` werden gezeigt
        (heisst: "Sub-Audit durchgelaufen, Ergebnis miserabel"); nur
        ``None`` blendet die Kategorie aus.
    """
    out = [
        CategoryScore(
            name="IT-Infrastruktur",
            score=infra_score,
            label=score_to_risk_level(infra_score),
        ),
        CategoryScore(
            name="Organisatorische Sicherheit",
            score=org_score,
            label=score_to_risk_level(org_score),
        ),
        CategoryScore(
            name="Netzwerksicherheit",
            score=network_score,
            label=score_to_risk_level(network_score),
        ),
    ]
    if backup_score is not None:
        out.append(
            CategoryScore(
                name="Backup-Audit",
                score=backup_score,
                label=score_to_risk_level(backup_score),
            )
        )
    if sovereignty_score is not None:
        out.append(
            CategoryScore(
                name="Datensouveraenitaet",
                score=sovereignty_score,
                label=score_to_risk_level(sovereignty_score),
            )
        )
    if ir_score is not None:
        out.append(
            CategoryScore(
                name="Incident-Response-Plan",
                score=ir_score,
                label=score_to_risk_level(ir_score),
            )
        )
    return out
