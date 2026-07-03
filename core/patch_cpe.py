"""
patch_cpe — Konstruiert CPE-2.3-Strings fuer Software-Inventar-Items.

PM-1.2. Wird von PM-1.5 (CVE-Matcher) konsumiert, um
gegen die NVD/CSAF-Datenbank zu queryen.

CPE 2.3 String-Format::

    cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:windows:*:*

Wir setzen die Plattform-Komponente fix auf ``windows`` (statt ``*``)
— damit fallen Linux/macOS-Eintraege bei Cross-Reference-Suchen
sofort raus.

Aufloesung von vendor/product:

1. **Override-Tabelle** (:data:`_CPE_OVERRIDES`): bekannte Faelle, in
   denen die winget-Id von der NVD-CPE-Notation abweicht
   (``Notepad++.Notepad++`` → ``notepad-plus-plus`` /
   ``notepad\\+\\+``). Override hat Vorrang.
2. **winget-Id-Heuristik**: ``"Vendor.Product"`` wird gesplittet —
   ``Vendor`` lowercase ist der Vendor, ``Product`` lowercase ist
   das Produkt.
3. **Display-Name-Heuristik (single-token only)**: wenn kein
   winget-Id und:func:`core.patch_normalizer.normalize_name`
   genau ein Token liefert (z.B. ``"7-zip"``), wird das als
   Vendor und Product gleichzeitig verwendet. Multi-Token-Namen
   ohne winget-Id sind zu unzuverlaessig —:func:`build_cpe`
   liefert dann ``None``.
"""

from __future__ import annotations

from core.logger import get_logger
from core.patch_collector import SoftwareItem
from core.patch_normalizer import normalize_name, normalize_version

log = get_logger(__name__)


# Bekannte Abweichungen winget-Id ↔ NVD-CPE-Notation.
# Format: ``"<winget_id>": (vendor, product)``. Beide lowercase,
# entsprechend dem CPE-2.3-Standard.
_CPE_OVERRIDES: dict[str, tuple[str, str]] = {
    "Mozilla.Firefox": ("mozilla", "firefox"),
    "Google.Chrome": ("google", "chrome"),
    "Microsoft.VisualStudioCode": ("microsoft", "visual_studio_code"),
    "Python.Python.3.12": ("python", "python"),
    "Python.Python.3.13": ("python", "python"),
    "Python.Python.3.11": ("python", "python"),
    "Python.Python.3.10": ("python", "python"),
    "Python.Python.3.9": ("python", "python"),
    "7zip.7zip": ("7-zip", "7-zip"),
    "VideoLAN.VLC": ("videolan", "vlc_media_player"),
    "Notepad++.Notepad++": ("notepad-plus-plus", r"notepad\+\+"),
    "KeePass.KeePass": ("dominik_reichl", "keepass_password_safe"),
    "KeePassXCTeam.KeePassXC": ("keepassxc", "keepassxc"),
    "Bitwarden.Bitwarden": ("bitwarden", "bitwarden"),
    "OBSProject.OBSStudio": ("obsproject", "obs-studio"),
    "Audacity.Audacity": ("audacityteam", "audacity"),
    "WireGuard.WireGuard": ("wireguard", "wireguard"),
    "OpenVPN.OpenVPN": ("openvpn", "openvpn"),
    "Malwarebytes.Malwarebytes": ("malwarebytes", "malwarebytes"),
    "Piriform.CCleaner": ("piriform", "ccleaner"),
}


def build_cpe(item: SoftwareItem) -> str | None:
    """Baut einen CPE-2.3-String fuer ein:class:`SoftwareItem`.

    Returns:
        ``"cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:windows:*:*"``
        bei erfolgreicher Aufloesung, sonst ``None``.

        ``None`` wird zurueckgegeben, wenn vendor oder product nicht
        verlaesslich ermittelbar sind — meistens fuer Registry- /
        MSIX-Eintraege ohne winget-Id und mit Multi-Token-Anzeige-
        Namen, die weder Vendor noch Product klar trennen
        (``"Unknown App 1.0"``).

    Args:
        item: Quelle aus:func:`core.patch_collector.collect_all`.
    """
    vendor, product = _resolve_vendor_product(item)
    if not vendor or not product or vendor == "*" or product == "*":
        return None

    version = normalize_version(item.version) or "*"

    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:windows:*:*"


def _resolve_vendor_product(item: SoftwareItem) -> tuple[str, str]:
    """Bestimmt vendor + product anhand der Aufloesungs-Hierarchie.

    Reihenfolge:
        1.:data:`_CPE_OVERRIDES` (exakter winget-Id-Match)
        2. winget-Id-Heuristik (split bei ``"."``)
        3. Single-Token-Display-Name-Heuristik

    Returns:
        ``(vendor, product)``-Tupel, beides lowercase. ``("*", "*")``
        wenn keine zuverlaessige Aufloesung moeglich ist.
    """
    # 1) Override-Tabelle
    if item.winget_id and item.winget_id in _CPE_OVERRIDES:
        return _CPE_OVERRIDES[item.winget_id]

    # 2) winget-Id-Heuristik
    if item.winget_id:
        parts = item.winget_id.split(".")
        non_empty = [p for p in parts if p]
        if len(non_empty) >= 2:
            vendor = non_empty[0].lower()
            product = non_empty[1].lower()
            return (vendor, product)
        if len(non_empty) == 1:
            token = non_empty[0].lower()
            return (token, token)

    # 3) Single-Token-Display-Name-Heuristik
    normalized = normalize_name(item.name)
    tokens = normalized.split()
    if len(tokens) == 1:
        token = _slugify(tokens[0])
        return (token, token)

    # Multi-Token ohne winget-Id: zu fuzzy fuer eine zuverlaessige
    # NVD-CPE-Query.
    return ("*", "*")


def _slugify(text: str) -> str:
    """Konvertiert Display-Name-Token zu CPE-tauglichem Slug.

    Whitespace → Underscore, lowercase. Bereits Underscore-/Bindestrich-
    haltige Tokens (``"7-zip"``) bleiben unveraendert.
    """
    return text.lower().replace(" ", "_")
