"""Tests für das Privatpersonen-/Kleinstbetrieb-Scoring (customer_audit).

Enterprise-typische Items (Zugangskontrollen, Netzwerksegmentierung, IDS/IPS,
Pentest) dürfen bei ``ist_privatperson`` NICHT als 0 den Score drücken, sondern
fallen aus dem Nenner (Org) bzw. ihre Gewichte werden re-normalisiert (Netzwerk).
"""

from __future__ import annotations

from tools.customer_audit.domain.entities import (
    CustomerData,
    IncidentResponsePlan,
    NetworkData,
    OrganizationalData,
)
from tools.customer_audit.domain.scoring_service import (
    calculate_ir_plan_score,
    calculate_network_score,
    calculate_organizational_score,
)


def test_org_privatperson_ignoriert_zugangskontrolle():
    """Fehlende Zugangskontrolle senkt den Org-Score einer Privatperson nicht."""
    data = OrganizationalData(
        zugangskontrollen="Nein",
        backup_strategie="Ja",
        update_management="Ja",
        mitarbeitersensibilisierung="Ja",
        incident_response_plan="Ja",
        dsgvo_konformitaet="Ja",
        avv_key_separate_storage="Ja",
    )
    normal = calculate_organizational_score(data)
    privat = calculate_organizational_score(data, ist_privatperson=True)
    assert normal == 85.7  # (6x100 + 0) / 7
    assert privat == 100.0  # zugangskontrollen faellt aus dem Nenner
    assert privat > normal


def test_network_privatperson_ignoriert_enterprise_items():
    """Schlechte Segmentierung/IDS/Pentest drücken den Privatpersonen-Score nicht."""
    data = NetworkData(
        netzwerksegmentierung="Nein",
        wlan_sicherheit="WPA3",
        offene_ports_bekannt="Ja",
        ids_ips_vorhanden="Nein",
        letzter_pentest="Nie",
    )
    normal = calculate_network_score(data)
    privat = calculate_network_score(data, ist_privatperson=True)
    assert privat == 100.0  # nur WLAN(100) + Ports(100), re-normalisiert
    assert privat > normal


def test_network_privatperson_renormalisiert_korrekt():
    """Re-Normalisierung der verbleibenden Gewichte (WLAN 0.25 + Ports 0.20)."""
    data = NetworkData(
        netzwerksegmentierung="Ja",
        wlan_sicherheit="WPA2",  # 80
        offene_ports_bekannt="Nein",  # 50
        ids_ips_vorhanden="Ja",
        letzter_pentest="2026",
    )
    # (80*0.25 + 50*0.20) / 0.45 = 30 / 0.45 = 66.7
    assert calculate_network_score(data, ist_privatperson=True) == 66.7


def test_unternehmen_unveraendert():
    """Ohne ist_privatperson bleibt das Scoring exakt wie bisher."""
    org = OrganizationalData(zugangskontrollen="Ja")
    net = NetworkData(netzwerksegmentierung="Ja", wlan_sicherheit="WPA2")
    assert calculate_organizational_score(org, ist_privatperson=False) == (
        calculate_organizational_score(org)
    )
    assert calculate_network_score(net, ist_privatperson=False) == (
        calculate_network_score(net)
    )


def test_customerdata_ist_privatperson_roundtrip():
    """Flag persistiert; Alt-Audits ohne Flag defaulten auf False."""
    cd = CustomerData(firmenname="X", ist_privatperson=True)
    assert CustomerData.from_dict(cd.to_dict()).ist_privatperson is True
    old = cd.to_dict()
    del old["ist_privatperson"]
    assert CustomerData.from_dict(old).ist_privatperson is False


# ---------------------------------------------------------------------------
# Incident-Response — Enterprise-Items (Eskalationskette, Forensik-Vendor)
# ---------------------------------------------------------------------------


def test_ir_privatperson_ignoriert_eskalation_und_forensik():
    """Eskalationskette + Forensik-Vendor fallen aus Punkten UND Maximum (15→10)."""
    plan = IncidentResponsePlan(
        info_block_shown=True,
        coordinator_name="A",
        coordinator_contact="a@example.com",
        critical_systems="Server",
        backup_location_ref="NAS",
        cyber_insurance=True,
    )
    # Verdiente Punkte (ohne Eskalation/Forensik): 3 + 2 + 1 + 1 = 7
    normal = calculate_ir_plan_score(plan)  # 7/15 -> 46.7
    privat = calculate_ir_plan_score(plan, ist_privatperson=True)  # 7/10 -> 70.0
    assert normal == 46.7
    assert privat == 70.0
    assert privat > normal


def test_ir_unternehmen_unveraendert():
    """Ohne Flag bleibt das IR-Scoring exakt wie bisher."""
    plan = IncidentResponsePlan(
        info_block_shown=True,
        coordinator_name="A",
        coordinator_contact="a@example.com",
    )
    assert calculate_ir_plan_score(plan, ist_privatperson=False) == (
        calculate_ir_plan_score(plan)
    )
