"""network_monitor.gui.labels — Klartext-Mappings für die Verbindungstabelle.

Sprint S1b: Eliminiert Unix-Jargon und nackte Port-Nummern in der
Verbindungstabelle. Frau M. (Steuerberaterin, KMU-Persona aus dem
NETWORK_MONITOR_UX-Report) sieht jetzt "Aktiv verbunden" statt
"ESTABLISHED" und "443 (HTTPS)" statt "443".

Zwei Mappings + Helfer:
  -:data:`STATUS_LABELS` +:func:`friendly_status` für TCP-Status-Strings.
  -:data:`PORT_SERVICES` +:func:`port_with_service` für gut bekannte
    Well-Known-Ports.

Schichtzugehörigkeit: gui/ — pure Python-Konstanten, kein PySide6.
Wird vom:mod:`connection_table` konsumiert.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TCP-Status — Klartext-Übersetzung (V1)
# ---------------------------------------------------------------------------

# Quelle: psutil-Status-Konstanten (RFC 793 + BSD-Erweiterungen). Die
# psutil-Werte sind die Schlüssel; die deutsch-laienverständlichen Texte
# die Werte. Konsumenten zeigen den Klartext in der Tabelle und das
# Original als Tooltip — damit bleiben technisch versierte Nutzer:innen
# nicht unterversorgt, während Frau M. nicht mit "TIME_WAIT" konfrontiert
# wird.
STATUS_LABELS: dict[str, str] = {
    "ESTABLISHED": "Aktiv verbunden",
    "LISTEN": "Wartet auf Verbindung",
    "SYN_SENT": "Verbindet",
    "SYN_RECV": "Wird verbunden",
    "FIN_WAIT1": "Beendet",
    "FIN_WAIT2": "Beendet",
    "TIME_WAIT": "Wird geschlossen",
    "CLOSE": "Geschlossen",
    "CLOSED": "Geschlossen",
    "CLOSE_WAIT": "Schließt",
    "LAST_ACK": "Beendet",
    "CLOSING": "Schließt",
    "NONE": "Unbekannt",
    # psutil liefert manchmal das Pseudo-Status für UDP — UDP ist
    # verbindungslos, deshalb sprachlich anders behandelt.
    "DELETE": "Geschlossen",
}


def friendly_status(status: str | None) -> str:
    """Wandelt einen TCP-Status-String in laienverständlichen Klartext.

    Args:
        status: psutil-Status (z. B. ``"ESTABLISHED"``). ``None`` und
            unbekannte Werte werden auf ``"Unbekannt"`` gemappt — defensiv,
            damit kein Crash bei psutil-Versionsdrift.

    Returns:
        Deutsch-laienverständlicher Status. Niemals leerer String.
    """
    if status is None:
        return "Unbekannt"
    return STATUS_LABELS.get(status.strip().upper(), "Unbekannt")


# ---------------------------------------------------------------------------
# Well-Known-Ports — Service-Anreicherung (V3)
# ---------------------------------------------------------------------------

# Auswahl orientiert sich an dem, was eine Steuerberaterin in einer
# KMU-Umgebung tatsächlich sehen wird (E-Mail, Web, Datenbank, Remote-
# Zugang). Bewusst kuratiert statt vollständige IANA-Liste — der Nutzen
# ist UX, nicht Vollständigkeit. Für unbekannte Ports liefert
#:func:`port_with_service` nur die Port-Nummer ohne Klammer-Suffix.
PORT_SERVICES: dict[int, str] = {
    20: "FTP-Daten",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Mail",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL Server",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def port_with_service(port: int | None) -> str:
    """Anreicherung einer Port-Nummer mit dem zugehörigen Service-Namen.

    Args:
        port: Port-Nummer. ``None``, 0 und negative Werte werden auf
            den leeren Platzhalter ``"–"`` gemappt (gleicher Stil wie der
            Rest der Tabelle bei fehlenden Werten).

    Returns:
        Bei bekanntem Well-Known-Port: ``"443 (HTTPS)"``. Bei unbekanntem
        Port: nur die Zahl als String. Bei fehlendem Port: ``"–"``.
    """
    if port is None or port <= 0:
        return "–"
    name = PORT_SERVICES.get(port)
    if name is None:
        return str(port)
    return f"{port} ({name})"


# ---------------------------------------------------------------------------
# Byte-Mengen — laienverständliche Formatierung Live-View)
# ---------------------------------------------------------------------------


def format_bytes(num_bytes: int) -> str:
    """Formatiert eine Byte-Menge dezimal (1000er) mit deutscher Notation.

    Dezimal (KB=1000 B), weil die Alert-Schwellen (z. B. „>10 GB") dezimal
    gedacht sind und Datenvolumen ueblicherweise so kommuniziert wird.

    Args:
        num_bytes: Byte-Anzahl (>= 0).

    Returns:
        Z. B. ``"0 B"``, ``"512 B"``, ``"1,23 MB"``, ``"4,70 GB"``
        (Komma als Dezimaltrenner).
    """
    if num_bytes < 1000:
        return f"{int(num_bytes)} B"
    value = float(num_bytes)
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1000.0
        if value < 1000:
            return f"{value:.2f} {unit}".replace(".", ",")
    return f"{value:.2f} PB".replace(".", ",")
