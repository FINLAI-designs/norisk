"""
patch_policy — Update-Channel-Policy fuer das Software-Inventar.

PM-1.3. Definiert pro Software einen Update-Kanal:

* ``latest`` — immer neueste Version (Browser, Office, Media)
* ``stable`` — neueste stabile Release-Linie, kein Beta/RC
* ``patch_only`` — nur ``x.y.Z``, nie Minor/Major (Python, Node, JDK)
* ``pinned`` — eingefroren, nie updaten

:class:`PolicyDB` pflegt:

1. eine kuratierte Default-Policy fuer ~220 Programme (in dieser
   Datei einkompiliert),
2. User-Overrides in:class:`core.database.encrypted_db.EncryptedDatabase`
   (DB-Name ``"patch_policy"``).

Lookup-Reihenfolge in:meth:`PolicyDB.get`:

1. User-Override (case-insensitiv auf ``software_name``)
2. Default-Tabelle (case-insensitiv Substring-Match)
3.:data:`DEFAULT_POLICY` (``notify_only``)

Matching ist case-insensitive Substring-Match: der Default-Schluessel
muss als Substring im ``software_name`` vorkommen — z.B. ``"python"``
matcht ``"Python 3.12.10 Core Interpreter"``.

**Schluessel-Mindestlaenge:** Tokens unter 3 Zeichen werden in
:func:`_build_default_policy` aussortiert (siehe ``_SHORT_KEYS_FILTERED``).
Begruendung: ein 1-Zeichen-Schluessel wie ``"r"`` matcht via Substring
JEDE Software, die ein ``r`` im Namen hat — was 90 % des Inventars
faelschlich auf ``patch_only`` werfen wuerde. Wer R/Go als
``patch_only`` haben moechte, setzt einen User-Override; alternativ
greift einer der laengeren Aliase (``"rustlang.rust"``, ``"golang"``,
``"r-project.r"`` etc.).

Bekannte False-Positives durch Substring-Match (Beispiele):
``"java"`` matcht auch ``"JavaScript"``. Wort-Boundary-Match folgt
in v1.1+, falls die UI-Telemetrie zeigt, dass das ein Problem ist.

Normalisierungsregeln (Beispiele aus realen Windows-DisplayNames)::

    "Python 3.12.0 (64-bit)" → matcht "python" → patch_only
    "Google Chrome" → matcht "chrome" → latest
    "Microsoft Edge" → matcht "msedge"/"microsoft.edge" → latest
    "Visual Studio Code" → matcht "vscode"/"visual studio code" → stable
    "7-Zip 24.08 (x64)" → matcht "7-zip" / "7zip" → latest
    "Microsoft 365 Apps for business - en-us"
                                     → matcht "microsoft 365 apps for business" → latest
    "Microsoft Edge WebView2 Runtime" → matcht "webview2"/"microsoft.edgewebview2runtime" → patch_only

Prioritaeten (informativ, fuer kuenftige Severity-Sortierung):

* **Prio A (Security-kritisch, hohe CVE-Frequenz):** Browser, PDF-Reader,
  Office, E-Mail, VPN, Antivirus.
* **Prio B (Important):** Media, Archiver, Remote-Tools, Cloud-Storage.
* **Prio C (Runtimes, Dev-Tools):** ``patch_only`` — nur Patch-Releases.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.database.encrypted_db import EncryptedDatabase
from core.exceptions import ValidationError
from core.logger import get_logger
from core.patch_normalizer import (
    find_policy_key,
    is_runtime_noise,
    normalize_for_matching,
    normalize_name,
)

log = get_logger(__name__)


VALID_CHANNELS: frozenset[str] = frozenset(
    {"latest", "stable", "patch_only", "pinned"}
)
"""Alle kuratierten Kanal-Namen (Default-Policy-Buckets).

Historisch war ``"notify_only"`` KEIN setzbarer Kanal — nur der Fallback
fuer unbekannte Software. T-443 erlaubt ihn jetzt zusaetzlich als
**expliziten User-Override** (s. :data:`USER_OVERRIDE_CHANNELS`), damit der
User eine App bewusst auf "nur melden, nicht patchen" stellen kann.
"""

USER_OVERRIDE_CHANNELS: frozenset[str] = VALID_CHANNELS | {"notify_only"}
"""Kanaele, die ein User per :meth:`PolicyDB.set_user_override` setzen darf (T-443).

Schliesst ``"notify_only"`` ein: der GUI-Channel-Selektor (Patch-Console)
bietet alle fuenf Stufen an. ``notify_only`` als Override bedeutet "diese App
bewusst nicht ueber den Patch-Monitor patchen" (Recommendation bleibt
``notify_only`` -> Zeile nicht batch-upgradebar).
"""

DEFAULT_DEFAULT_CHANNEL = "notify_only"
"""Werks-Default fuer den globalen Default-Kanal (T-443).

Effekt: Solange der User in den Einstellungen keinen anderen globalen
Default-Kanal waehlt, behalten UNBEKANNTE Programme (kein kuratierter
Default-Match, kein User-Override, kein Runtime-Force) ``notify_only`` —
identisches Verhalten wie vor T-443. Setzt der User z.B. ``stable``, werden
unbekannte Programme upgradebar (s. :meth:`PolicyDB.get_default_channel`).
"""

# Interner Settings-Schluessel fuer den globalen Default-Kanal (patch_settings).
_DEFAULT_CHANNEL_KEY = "default_channel"

# Mindestlaenge fuer Default-Policy-Schluessel (siehe Modul-Docstring).
_MIN_KEY_LENGTH = 3


@dataclass(frozen=True)
class PatchPolicy:
    """Update-Strategie fuer eine Software.

    Attributes:
        channel: Einer aus:data:`VALID_CHANNELS` — oder
            ``"notify_only"`` (nur als:data:`DEFAULT_POLICY`-Sentinel).
        reason: Begruendung fuer die Wahl des Kanals — wird in der
            UI-Detail-Ansicht angezeigt.
        source: ``"default"`` oder ``"user"``.
    """

    channel: str
    reason: str
    source: str


DEFAULT_POLICY: PatchPolicy = PatchPolicy(
    channel="notify_only",
    reason="Unbekannte Software — nur melden",
    source="default",
)
"""Fallback fuer Software, die weder in der kuratierten Default-Tabelle
noch im User-Override liegt."""


# ---------------------------------------------------------------------
# Kuratierte Default-Policy, erweitert 2026-05-03)
# ---------------------------------------------------------------------
#
# Schluessel sind Substring-Tokens — case-insensitiv geprueft gegen
# software_name in:meth:`PolicyDB.get`. Reihenfolge der Eintraege
# bestimmt die Match-Prioritaet (erster Match gewinnt). Innerhalb
# jeder Bucket-Tabelle nach Kategorie gruppiert.
#
# vscode: einmal in "latest (stable bleibt moeglich)" und einmal in
# "stable" gelistet — die explizite Platzierung in `stable` gewinnt.

_LATEST_KEYS: tuple[str, ...] = (
    # --- BROWSER (Security-kritisch) ---
    "firefox", "mozilla firefox", "mozilla.firefox",
    "chrome", "google chrome", "googlechrome", "google.chrome",
    "msedge", "microsoft edge", "microsoft.edge",
    "brave", "brave browser", "brave.brave",
    "opera", "opera.opera",
    "vivaldi", "vivaldi.vivaldi",
    "tor browser", "torproject.torbrowser",
    # --- OFFICE & PRODUKTIVITAET ---
    "onlyoffice", "onlyoffice.desktopeditors",
    "libreoffice", "thedocumentfoundation.libreoffice",
    "openoffice", "apache openoffice",
    "wps office", "kingsoft.wpsoffice",
    "freeoffice", "softmaker.freeoffice",
    "notion", "notion.notion",
    "obsidian", "obsidian.obsidian",
    "joplin", "joplin.joplin",
    # --- MICROSOFT 365 / OFFICE (praezise statt Blob) ---
    "microsoft.office", "microsoft.office365",
    "microsoft 365 apps for business",
    "microsoft 365 apps for enterprise",
    "microsoft.word", "microsoft.excel", "microsoft.powerpoint",
    "onenote", "microsoft.onenote",
    # microsoft.outlook/onedrive/teams stehen bereits in
    # KOMMUNIKATION bzw. CLOUD STORAGE.
    # --- ADOBE PRO ---
    "adobe acrobat pro", "adobe acrobat", "adobe.acrobat",
    # --- KOMMUNIKATION & COLLABORATION ---
    "zoom", "zoom.zoom",
    "teams", "microsoft teams", "microsoft.teams",
    "slack", "slacktechnologies.slack",
    "discord", "discord.discord",
    "telegram", "telegram.telegramdesktop",
    "signal", "opensignaltech.signal",
    "skype", "microsoft.skype",
    "whatsapp", "whatsapp.whatsapp",
    "thunderbird", "mozilla.thunderbird",
    "outlook", "microsoft.outlook",
    "mattermost", "mattermost.mattermost",
    "rocketchat", "rocketchat.rocketchat",
    "webex", "cisco.webex",
    "gotomeeting", "logmein.gotomeeting",
    # --- E-MAIL ---
    "em client", "emclient", "emclient.emclient",
    # --- PDF (haeufig CVEs) ---
    "adobereader", "adobe acrobat reader",
    "adobe.acrobatreaderuniversal",
    "foxit reader", "foxitsoftware.foxitreader",
    "foxit pdf editor", "foxitsoftware.foxitpdfeditor",
    "sumatrapdf", "sumatrapdf.sumatrapdf",
    "nitro pdf", "nitro.nitropro",
    "pdfxchange", "tracker.pdfxchangeeditor",
    "okular", "kde.okular",
    "evince", "gnome.evince",
    # --- SICHERHEIT & ANTIVIRUS ---
    "malwarebytes", "malwarebytes.malwarebytes",
    "bitdefender", "bitdefender.bitdefender",
    "avast", "avast.avast",
    "avg", "avg.avg",
    "kaspersky", "kaspersky.kaspersky",
    "eset", "eset.esetnodsecurity",
    "norton", "norton.norton",
    "ccleaner", "piriform.ccleaner",
    "adwcleaner", "malwarebytes.adwcleaner",
    "glasswire", "glasswire.glasswire",
    "sandboxie", "sandboxie-plus", "sandboxie.sandboxieplus",
    # --- VPN & NETZWERK ---
    "nordvpn", "nordvpn.nordvpn",
    "expressvpn", "expressvpn.expressvpn",
    "protonvpn", "protonvpn.protonvpn",
    "mullvadvpn", "mullvad.mullvadvpn",
    "wireguard", "wireguard.wireguard",
    "openvpn", "openvpn.openvpn",
    "tailscale", "tailscale.tailscale",
    "zerotier", "zerotier.zerotier",
    "cisco anyconnect", "cisco secure client",
    "cisco.securesocketslayer",
    "cloudflare warp", "cloudflare one", "cloudflare.warp",
    "nmap", "nmap.nmap",
    "wireshark", "wireshark.wireshark",
    "putty", "putty.putty",
    "winscp", "winscp.winscp",
    "filezilla", "filezilla.filezilla",
    "mremoteng", "mremoteng.mremoteng",
    # --- PASSWORT-MANAGER ---
    "keepass", "keepass.keepass",
    "keepassxc", "keepassxc.keepassxc",
    "bitwarden", "bitwarden.bitwarden",
    "1password", "agilebits.1password",
    "lastpass", "lastpass.lastpass",
    "dashlane", "dashlane.dashlane",
    # --- ARCHIVIERUNG & KOMPRESSION ---
    "7-zip", "7zip", "sevenzip.sevenzip", "7zip.7zip",
    "winrar", "rarlab.winrar",
    "bandizip", "bandizip.bandizip",
    "peazip", "giorgiotani.peazip",
    "nanazip", "m2team.nanazip",
    # --- MEDIA PLAYER ---
    "vlc", "videolan.vlc",
    "mpv", "mpv.mpv",
    "mpc-hc", "clsid2.mpc-hc",
    "potplayer", "daum.potplayer",
    "foobar2000", "peterspetermann.foobar2000",
    "musicbee",
    "aimp", "aimp.aimp",
    "winamp", "winamp.winamp",
    "spotify", "spotify.spotify",
    "itunes", "apple.itunes",
    # --- MEDIA KONVERSION ---
    "handbrake", "handbrake.handbrake",
    "ffmpeg", "gyan.ffmpeg",
    "audacity", "audacity.audacity",
    "kdenlive", "kde.kdenlive",
    "davinci resolve", "blackmagicdesign.davinciresolve",
    "obs studio", "obs.obs",
    "sharex", "sharex.sharex",
    "voicemeeter", "vbcable.voicemeeter",
    # --- GRAFIK & DESIGN ---
    "gimp", "gimp.gimp",
    "inkscape", "inkscape.inkscape",
    "krita", "kde.krita",
    "paint.net", "dotpdn.paintdotnet",
    "irfanview", "irfanview.irfanview",
    "imagemagick", "imagemagick.imagemagick",
    "faststone", "faststone image viewer",
    "blender", "blender.blender",
    "figma", "figma.figma",
    "canva", "canva.canva",
    # --- CLOUD STORAGE ---
    "nextcloud", "nextcloud.nextclouddesktop",
    "dropbox", "dropbox.dropbox",
    "onedrive", "microsoft.onedrive",
    "googledrive", "google.drive",
    "box", "box.boxdrive",
    "megasync", "mega.megasync",
    "syncthing", "syncthing.syncthing",
    "resilio sync", "resilio.resiliosync",
    "icloud", "icloud for windows", "apple.icloud",
    # --- REMOTE ACCESS ---
    "rustdesk", "rustdesk.rustdesk",
    "teamviewer", "teamviewer.teamviewer",
    "anydesk", "anydesk.anydesk",
    "vnc", "realvnc.vncviewer",
    "parsec", "parsec.parsec",
    "remote desktop", "microsoft.rdclient",
    "chrome remote desktop", "google.chromeremotedesktop",
    "splashtop", "splashtop.splashtopbusiness",
    # --- GAMING ---
    "steam", "valve.steam",
    "epicgameslauncher", "epicgames.epicgameslauncher",
    "goggalaxy", "gogcom.galaxyclient",
    "origin", "ea.eaapp",
    "eaapp", "electronic arts.eaapp",
    "ubisoft connect", "ubisoft.ubisoft-connect",
    "battlenet", "blizzard.battlenet",
    "xboxapp", "microsoft.gamingservices",
    "playnite", "playnite.playnite",
    "retroarch", "libretro.retroarch",
    # --- KOMMUNIKATIONS-TOOLS BUSINESS ---
    "jabber", "cisco.jabber",
    "skypeforwork", "microsoft.skypeforwork",
    "ringcentral", "ringcentral.ringcentralapp",
    "3cx", "3cx.3cxdesktopapp",
    "twilio", "twilio.twilio",
    # --- SONSTIGES ---
    "calibre", "calibre-ebook.calibre",
    "qbittorrent", "qbittorrent.qbittorrent",
    "deluge", "deluge-torrent.deluge",
    "f.lux", "flux.flux",
    "lively wallpaper", "rocksdanister.livelywallpaper",
    "rainmeter", "rainmeter.rainmeter",
    "keypirinha",
    "launchy",
    "ditto", "ditto.ditto",
    "greenshot", "greenshot.greenshot",
    "flameshot", "flameshot.flameshot",
    "snagit", "techsmith.snagit",
    "camtasia", "techsmith.camtasia",
    "loom", "loom.loom",
    "grammarly", "grammarly.grammarlyforwindows",
)

_STABLE_KEYS: tuple[str, ...] = (
    # --- DEVELOPER TOOLS ---
    "vscode", "visual studio code", "microsoft.visualstudiocode",
    "visualstudio", "microsoft.visualstudio",
    "notepadplusplus", "notepad++", "notepadplusplus.notepadplusplus",
    "sublimetext", "sublimehq.sublimetext",
    "jetbrains toolbox", "jetbrains.toolbox",
    "pycharm", "jetbrains.pycharm",
    "intellij", "jetbrains.intellijidea",
    "webstorm", "jetbrains.webstorm",
    "goland", "jetbrains.goland",
    "rider", "jetbrains.rider",
    "clion", "jetbrains.clion",
    "datagrip", "jetbrains.datagrip",
    "vim", "vim.vim",
    "neovim", "neovim.neovim",
    "git", "git.git",
    "github desktop", "github.githubdesktop",
    "gitkraken", "axosoft.gitkraken",
    "sourcetree", "atlassian.sourcetree",
    "postman", "postman.postman",
    "insomnia", "kong.insomnia",
    "docker desktop", "docker.dockerdesktop",
    "powershell", "microsoft.powershell",
    "windows terminal", "microsoft.windowsterminal",
    "wsl", "microsoft.wsl",
    "vagrant", "hashicorp.vagrant",
    "terraform", "hashicorp.terraform",
    # --- DATENBANKEN ---
    "dbeaver", "dbeaver.dbeaver",
    "heidisql", "heidisql.heidisql",
    "pgadmin", "postgresql.pgadmin",
    "sqlitebrowser", "sqlitebrowser.sqlitebrowser",
    "tableplus", "tableplus.tableplus",
    "mongodb compass", "mongodb.compass",
    "redis insight", "redislabs.redisinsight",
    # --- SYSTEM TOOLS ---
    "everything", "voidtools.everything",
    "powertoys", "microsoft.powertoys",
    "autoruns", "sysinternals.autoruns",
    "procexp", "sysinternals.processexplorer",
    "procmon", "sysinternals.processmonitor",
    "windirstat", "windirstat.windirstat",
    "treesize", "jamsoft.treesizefreepersonal",
    "hwinfo", "hwinfo.hwinfo",
    "cpu-z", "cpuid.cpu-z",
    "gpu-z", "techpowerup.gpu-z",
    "crystaldiskinfo", "crystaldewworld.crystaldiskinfo",
    "crystaldiskmark", "crystaldewworld.crystaldiskmark",
    "speccy", "piriform.speccy",
    "furmark", "geeks3d.furmark",
    "prime95", "mersenne.prime95",
    "memtest86", "passmark.memtest86",
    "rufus", "rufus.rufus",
    "etcher", "balena.etcher",
    "ventoy", "ventoy.ventoy",
    "wintoflash", "novicorp.wintoflash",
    "macrium reflect", "macrium.reflect",
    # --- VIRTUALISIERUNG ---
    # (Hyper-V ist Windows-Feature, kein winget-Paket — nicht gelistet.)
    "virtualbox", "oracle.virtualbox",
    "vmware workstation", "vmware.workstationplayer",
    "vmware.workstation",
    # --- BACKUP ---
    "duplicati", "duplicati.duplicati",
    "veeam", "veeam.agentforwindows",
    "acronis", "acronis.trueimageforwindows",
    "cobian backup",
    "aomei backupper", "aomeitech.backupper",
    # --- BUCHHALTUNG & BUSINESS ---
    "lexoffice", "lexware.lexoffice",
    "datev", "datev.datev",
    "sevdesk", "sevdesk.sevdesk",
    "sage", "sage.sageaccounting",
    "quickbooks", "intuit.quickbooks",
)

_PATCH_ONLY_KEYS: tuple[str, ...] = (
    # --- Hard-Override-Ziele (siehe core.patch_normalizer._HARD_OVERRIDES) ---
    # Werden nach normalize_name als kanonische Form erkannt:
    # "Microsoft Visual C++ 2022 Redistributable (x64)" → "microsoft visual c++"
    # "Microsoft.NET Runtime 8.0.10" → "microsoft.net"
    # "Java(TM) SE Runtime Environment" → "java(tm) se" (→ Hard-Override "java" → "java runtime")
    "microsoft visual c++",
    "microsoft .net",
    "java runtime",
    # --- Python ---
    # Versions-Eintraege zuerst (laengere Tokens), damit "python 3.12"
    # vor "python" greift — funktional egal (gleicher Channel), aber
    # praeziser fuer zukuenftige per-Key-Reasons.
    "python 3.13", "python 3.12", "python 3.11", "python 3.10",
    "python 3.9",
    "python software foundation.python",
    "python3", "python",
    # --- Node.js ---
    "openjs.nodejs", "node.js", "nodejs",
    # --- Java / JDK / JRE ---
    "eclipse foundation.temurin", "adoptopenjdk", "microsoft.openjdk",
    "oracle.jdk", "oracle.jre",
    "java", "jdk", "jre",
    # ---.NET (versioniert + generisch) ---
    # Versions-Eintraege zuerst (laengere Tokens) — sie sind die
    # praeziseren Default-Match-Schluessel. Dann generische Fallbacks.
    "microsoft.dotnet.desktopruntime.9",
    "microsoft.dotnet.desktopruntime.8",
    "microsoft.dotnet.desktopruntime.7",
    "microsoft.dotnet.desktopruntime.6",
    "microsoft.dotnet.runtime.9",
    "microsoft.dotnet.runtime.8",
    "microsoft.dotnet.runtime.7",
    "microsoft.dotnet.runtime.6",
    "microsoft.dotnet.aspnetcore.9",
    "microsoft.dotnet.aspnetcore.8",
    "microsoft.dotnet.aspnetcore.7",
    "microsoft.dotnet.aspnetcore.6",
    "dotnet 9", "dotnet 8", "dotnet 7", "dotnet 6",
    "asp.net core", "dotnetcore",
    "dotnet runtime", "dotnetruntime",
    "microsoft.dotnet", ".net runtime", "dotnet",
    "windowsdesktopruntime",
    "microsoft.xamarin", "xamarin",
    # --- Edge WebView2 (Runtime-Komponente — patch_only wegen
    # Abhaengigkeiten von Apps wie Teams, Office etc.) ---
    "microsoft.edgewebview2runtime",
    "microsoft edge webview2", "webview2",
    # --- Visual C++ Redistributables ---
    "vcredist2022", "vcredist2019", "vcredist2017", "vcredist2015",
    "microsoft.vc++", "visual c++", "vcredist",
    "microsoft.directx", "directx",
    # --- weitere Sprach-Runtimes ---
    "rubyinstallerteam.ruby", "rubyinstaller", "ruby",
    "strawberry.strawberry", "strawberry perl", "perl",
    "lua.lua", "lua",
    "r-project.r", "r project",  # Schluessel "r" (1 Zeichen) wird gefiltert
    "julialang.julia", "julia",
    "google.go", "golang",        # Schluessel "go" (2 Zeichen) wird gefiltert
    "rustlang.rust", "rust",
)

_PINNED_KEYS: tuple[str, ...] = ()
# Pinned hat keine Default-Eintraege — nur User-Overrides.


# Tokens, die wegen Mindestlaenge < 3 Zeichen aussortiert werden.
# Quelle der Wahrheit::func:`_build_default_policy`. Hier nur als
# Doku-Anker fuer Tests + Code-Review.
_SHORT_KEYS_FILTERED: frozenset[str] = frozenset({"r", "go"})


_REASON_TEMPLATES: dict[str, str] = {
    "latest": "Browser/Office/Media — Sicherheits-Updates moeglichst sofort.",
    "stable": "Entwickler-Tool — neueste stabile Linie, kein Beta/RC.",
    "patch_only": (
        "Sprach-/Runtime-Toolchain — nur Patch-Versionen, "
        "keine Minor/Major (Risiko Workflow-Bruch)."
    ),
    "pinned": "Eingefroren auf installierte Version (User-Override).",
}


_CHANNEL_PRIORITY: dict[str, int] = {
    "latest": 0,
    "stable": 1,
    "patch_only": 2,
    "pinned": 3,
}


def _build_default_policy() -> tuple[tuple[str, PatchPolicy], ...]:
    """Baut die geordnete Default-Policy-Liste aus den Channel-Buckets.

    Filter: Schluessel mit Laenge <:data:`_MIN_KEY_LENGTH` werden
    uebersprungen (Substring-Match-False-Positive-Schutz). Die
    aussortierten Tokens sind in:data:`_SHORT_KEYS_FILTERED`
    dokumentiert.

    Match-Reihenfolge: **Laengster Schluessel gewinnt**, bei Gleichstand
    nach Channel-Prioritaet ``latest`` → ``stable`` → ``patch_only`` →
    ``pinned``. Begruendung: ein kurzer Schluessel wie ``"box"`` (LATEST,
    Cloud-Storage) wuerde sonst eine speziellere Software wie
    ``"VirtualBox"`` (STABLE, ``"virtualbox"`` 10 Zeichen) faelschlich
    auf ``latest`` werfen, weil ``"box"`` als Substring zuerst
    iteriert. Mit Laengen-Sortierung gewinnt der spezifischere Match.

    Returns:
        Tupel von ``(key_lowercase, PatchPolicy)``-Paaren in
        Match-Prioritaets-Reihenfolge (laengster Key zuerst).
    """
    entries: list[tuple[str, PatchPolicy]] = []
    for channel, keys in (
        ("latest", _LATEST_KEYS),
        ("stable", _STABLE_KEYS),
        ("patch_only", _PATCH_ONLY_KEYS),
        ("pinned", _PINNED_KEYS),
    ):
        reason = _REASON_TEMPLATES[channel]
        seen: set[str] = set()
        for raw_key in keys:
            key = raw_key.lower().strip()
            if len(key) < _MIN_KEY_LENGTH:
                continue
            if key in seen:
                continue  # Duplikat innerhalb der Bucket — einmal reicht
            seen.add(key)
            entries.append(
                (
                    key,
                    PatchPolicy(
                        channel=channel, reason=reason, source="default"
                    ),
                )
            )

    # Laengster Schluessel zuerst, dann Channel-Prioritaet als Tiebreak.
    entries.sort(
        key=lambda kp: (-len(kp[0]), _CHANNEL_PRIORITY[kp[1].channel])
    )
    return tuple(entries)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_overrides (
    software_name_lower TEXT PRIMARY KEY,
    software_name_original TEXT NOT NULL,
    channel TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS patch_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class PolicyDB:
    """Verwaltung der Patch-Policy: kuratierte Defaults + User-Overrides.

    User-Override hat immer Vorrang vor Default-Policy. Default-Policy
    nutzt case-insensitive Substring-Match. Wenn keine Default-Regel
    greift, ist das Ergebnis:data:`DEFAULT_POLICY` (``notify_only``).

    Beispiel::

        db = PolicyDB
        db.get("Mozilla Firefox 120.0.1")
        # → PatchPolicy(channel="latest", source="default",...)

        db.set_user_override(
            "Mozilla Firefox 120.0.1", "pinned",
            reason="Veraltete Version vor Audit-Termin",
)
        db.get("Mozilla Firefox 120.0.1")
        # → PatchPolicy(channel="pinned", source="user",...)
    """

    def __init__(self) -> None:
        """Initialisiert die DB und legt das Schema bei Bedarf an."""
        self._db = EncryptedDatabase("patch_policy")
        self._defaults: tuple[tuple[str, PatchPolicy], ...] = (
            _build_default_policy()
        )
        with self._db.connection() as conn:
            conn.executescript(_SCHEMA)
        # globaler Default-Kanal fuer unbekannte Software. Einmal beim
        # Konstruieren gecacht (get laeuft pro Scan ~220x — kein SELECT je Call).
        self._default_channel: str = self._load_default_channel()

    # ------------------------------------------------------------------
    # Globaler Default-Kanal
    # ------------------------------------------------------------------

    def _load_default_channel(self) -> str:
        """Liest den globalen Default-Kanal aus ``patch_settings``."""
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT value FROM patch_settings WHERE key = ?",
                (_DEFAULT_CHANNEL_KEY,),
            ).fetchone()
        if row is None or row[0] not in USER_OVERRIDE_CHANNELS:
            return DEFAULT_DEFAULT_CHANNEL
        return row[0]

    def get_default_channel(self) -> str:
        """Liefert den globalen Default-Kanal fuer unbekannte Software.

        Returns:
            Einer aus:data:`USER_OVERRIDE_CHANNELS`; Werks-Default
:data:`DEFAULT_DEFAULT_CHANNEL` (``notify_only``), solange der User
            keinen anderen waehlt.
        """
        return self._default_channel

    def set_default_channel(self, channel: str) -> None:
        """Setzt den globalen Default-Kanal fuer unbekannte Software.

        Effekt: Programme ohne kuratierten Default-Match, ohne User-Override und
        ohne Runtime-Force bekommen ab sofort diesen Kanal in:meth:`get` — ein
        anschliessender (Re-)Scan macht sie damit upgradebar (sofern winget-Id
        vorhanden). Aendert KEINE bestehenden User-Overrides und keine kuratierten
        Defaults.

        Args:
            channel: Einer aus:data:`USER_OVERRIDE_CHANNELS` (inkl. ``notify_only``).

        Raises:
            ValidationError: Bei ungueltigem Kanal.
        """
        if channel not in USER_OVERRIDE_CHANNELS:
            raise ValidationError(
                f"Ungueltiger Default-Kanal {channel!r}. "
                f"Erlaubt: {sorted(USER_OVERRIDE_CHANNELS)}"
            )
        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO patch_settings (key, value) "
                "VALUES (?, ?)",
                (_DEFAULT_CHANNEL_KEY, channel),
            )
        self._default_channel = channel

    def _fallback_policy(self) -> PatchPolicy:
        """Fallback-Policy fuer unbekannte Software.

        Nutzt den globalen Default-Kanal statt des fixen ``notify_only``. Bleibt
        identisch zu:data:`DEFAULT_POLICY`, solange der Default ``notify_only``
        ist (Werks-Zustand).
        """
        channel = self._default_channel
        if channel == DEFAULT_DEFAULT_CHANNEL:
            return DEFAULT_POLICY
        return PatchPolicy(
            channel=channel,
            reason=(
                "Unbekannte Software — globaler Default-Kanal "
                f"'{channel}' (Einstellungen)."
            ),
            source="default",
        )

    @property
    def policy_keys(self) -> list[str]:
        """Liste aller Default-Policy-Schluessel in Match-Reihenfolge.

        Wird vom:class:`core.patch_channel_resolver.ChannelResolver`
        gebraucht, um die Match-Confidence eigenstaendig nachzurechnen
        (PolicyDB.get verliert die Confidence-Information beim
        Aufloesen).
        """
        return [key for key, _policy in self._defaults]

    def get(self, software_name: str) -> PatchPolicy:
        """Liefert die effektive Policy fuer einen Software-Namen.

        Ablauf:

        1. ``software_name`` durch
:func:`core.patch_normalizer.normalize_name` jagen
           (Storage-Schluessel fuer User-Override-Lookup).
        2. User-Override unter dem normalisierten Namen suchen.
        3. **Runtime-Force**: Wenn
:func:`core.patch_normalizer.is_runtime_noise` auf den
           Original-Namen zutrifft (z.B. ``"Microsoft Visual C++
           2022 Redistributable"``), Channel zwingend auf
           ``patch_only`` setzen — Redistributables sind
           Abhaengigkeiten von Apps, nie eigenstaendige
           Update-Kandidaten.
        4. Default-Policy via
:func:`core.patch_normalizer.find_policy_key`
           aufloesen, gefuettert mit
:func:`core.patch_normalizer.normalize_for_matching`
           (entfernt zusaetzlich Semantik-Tokens wie ``"sdk"`` /
           ``"server"`` — damit landen z.B. ``".NET SDK"`` und
           ``".NET Runtime"`` auf demselben Key).
        5. Fallback:data:`DEFAULT_POLICY`.

        Args:
            software_name: Anzeigename (z.B. aus
                ``SoftwareItem.name``). Beliebige Schreibweise.

        Returns:
            User-Override (falls vorhanden), sonst forced
            ``patch_only`` (Runtime), sonst Default-Match,
            sonst:data:`DEFAULT_POLICY`.
        """
        name_clean = software_name.strip()
        if not name_clean:
            return DEFAULT_POLICY

        normalized_storage = normalize_name(name_clean)
        if not normalized_storage:
            return DEFAULT_POLICY

        # 1) User-Override (Lookup unter normalize_name-Form, weil
        # set/remove den selben Storage-Schluessel verwenden).
        with self._db.connection() as conn:
            row = conn.execute(
                "SELECT channel, reason FROM user_overrides "
                "WHERE software_name_lower = ?",
                (normalized_storage,),
            ).fetchone()
        if row is not None:
            return PatchPolicy(channel=row[0], reason=row[1], source="user")

        # 2) Runtime-/Redistributable-Force — System-Komponenten
        # sind ALWAYS patch_only.
        if is_runtime_noise(name_clean):
            return PatchPolicy(
                channel="patch_only",
                reason=(
                    "Runtime-/Redistributable-Komponente — wird mit "
                    "der zugehoerigen App aktualisiert, kein "
                    "eigenstaendiges Update."
                ),
                source="default",
            )

        # 3) Default-Tabelle ueber find_policy_key, gefuettert mit
        # der Matching-Form (entfernt sdk/jdk/server/...).
        normalized_match = normalize_for_matching(name_clean)
        if not normalized_match:
            return DEFAULT_POLICY
        policy_keys = [key for key, _policy in self._defaults]
        match = find_policy_key(normalized_match, policy_keys)
        if match is None:
            # unbekannte Software -> globaler Default-Kanal (Werks-Default
            # notify_only, vom User in den Einstellungen aenderbar).
            return self._fallback_policy()
        matched_key, _confidence = match
        for key, policy in self._defaults:
            if key == matched_key:
                return policy

        # Defensiv: matched_key kommt zwingend aus policy_keys.
        return self._fallback_policy()

    def set_user_override(
        self, software_name: str, channel: str, reason: str = ""
    ) -> None:
        """Setzt oder ueberschreibt einen User-Override.

        Speichert unter dem **normalisierten Namen** als
        Lookup-Schluessel — z.B. ``"Python 3.12.0 (64-bit)"`` und
        ``"Python 3.11.5"`` schreiben beide unter ``"python"``.
        Ein Override gilt damit fuer das Software-"Label", nicht pro
        spezifischer Version. Die Original-Schreibweise wird fuer
:meth:`list_user_overrides` separat aufbewahrt.

        Args:
            software_name: Anzeigename. Wird via
:func:`core.patch_normalizer.normalize_name`
                normalisiert.
            channel: Einer aus:data:`VALID_CHANNELS`.
            reason: Optionale Begruendung.

        Raises:
            ValueError: Wenn ``channel`` nicht in
:data:`VALID_CHANNELS` ist, ``software_name`` leer
                ist oder die Normalisierung einen leeren String
                liefert.
        """
        if channel not in USER_OVERRIDE_CHANNELS:
            # notify_only ist jetzt ein zulaessiger expliziter Override
            # ("App bewusst nicht patchen"), nicht nur der Fallback-Sentinel.
            raise ValidationError(
                f"Ungueltiger Kanal {channel!r}. "
                f"Erlaubt: {sorted(USER_OVERRIDE_CHANNELS)}"
            )
        name_clean = software_name.strip()
        if not name_clean:
            raise ValidationError("software_name darf nicht leer sein")
        normalized = normalize_name(name_clean)
        if not normalized:
            raise ValidationError(
                f"software_name {software_name!r} normalisiert zu "
                f"leerem String — kein gueltiger Override-Schluessel."
            )

        with self._db.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO user_overrides "
                "(software_name_lower, software_name_original, "
                "channel, reason) VALUES (?, ?, ?, ?)",
                (normalized, name_clean, channel, reason),
            )

    def remove_user_override(self, software_name: str) -> None:
        """Loescht einen User-Override (no-op falls keiner existiert).

        Lookup ueber den normalisierten Namen — symmetrisch zu
:meth:`set_user_override`.

        Args:
            software_name: Anzeigename (beliebige Schreibweise).
        """
        name_clean = software_name.strip()
        if not name_clean:
            return
        normalized = normalize_name(name_clean)
        if not normalized:
            return
        with self._db.connection() as conn:
            conn.execute(
                "DELETE FROM user_overrides WHERE software_name_lower = ?",
                (normalized,),
            )

    def list_user_overrides(self) -> dict[str, PatchPolicy]:
        """Liefert alle aktiven User-Overrides.

        Returns:
            Dict ``software_name_original -> PatchPolicy(source="user")``,
            alphabetisch nach ``software_name_original``. Leeres Dict,
            wenn keine Overrides gesetzt sind.
        """
        with self._db.connection() as conn:
            rows = conn.execute(
                "SELECT software_name_original, channel, reason "
                "FROM user_overrides ORDER BY software_name_original"
            ).fetchall()
        return {
            r[0]: PatchPolicy(channel=r[1], reason=r[2], source="user")
            for r in rows
        }
