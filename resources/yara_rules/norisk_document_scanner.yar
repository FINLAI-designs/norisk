/*
   norisk_document_scanner.yar — NoRisk-eigene YARA-Regeln fuer den
   Document Scanner Iter 3 (T-094, 2026-05-14).

   Bewusst kleine, gezielte Auswahl statt vollem YARA-Forge-Import:
   - Schnellster Pattern-Match (< 100 ms je Datei).
   - False-Positive-Rate niedrig fuer Kanzleialltag.
   - Keine Yara-Lib-Module (PE/ELF), damit yara-python ohne crypto/
     dotnet-Modul lauffaehig bleibt.

   Update-Pfad: ergaenze Regeln in dieser Datei. Aenderungen werden
   beim naechsten App-Start automatisch geladen (Cache-Invalidation
   ueber mtime).

   Tagging-Konvention:
     - severity:critical / severity:high / severity:medium
     - family:malware-loader / family:phishing / family:exploit-doc
*/

rule NoRisk_PS_Empire_Stager
{
    meta:
        author       = "FINLAI / NoRisk"
        date         = "2026-05-14"
        severity     = "high"
        family       = "malware-loader"
        description  = "PowerShell-Empire-aehnlicher Stager (Base64 + IEX)."
    strings:
        $iex      = "iex" nocase
        $b64_long = /[A-Za-z0-9+\/]{500,}={0,2}/
        $from_b64 = "frombase64string" nocase
    condition:
        $iex and ($b64_long or $from_b64)
}

rule NoRisk_PS_Encoded_Command
{
    meta:
        author      = "FINLAI / NoRisk"
        date        = "2026-05-14"
        severity    = "high"
        family      = "malware-loader"
        description = "PowerShell ``-EncodedCommand`` Aufruf — fast immer Loader."
    strings:
        $enc1 = "-encodedcommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "powershell -nop -w hidden" nocase
    condition:
        any of them
}

rule NoRisk_VBA_AutoExec_Shell
{
    meta:
        author      = "FINLAI / NoRisk"
        date        = "2026-05-14"
        severity    = "critical"
        family      = "exploit-doc"
        description = "Office-Makro mit AutoExec-Trigger + Shell-Aufruf."
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $shell = /Shell\s*\(/ nocase
        $wscript = "WScript.Shell" nocase
    condition:
        any of ($auto*) and ($shell or $wscript)
}

rule NoRisk_Phishing_Brand_Spoofing
{
    meta:
        author      = "FINLAI / NoRisk"
        date        = "2026-05-14"
        severity    = "medium"
        family      = "phishing"
        description = "Bekannte Marken-Tarnung in Office/PDF/HTML."
    strings:
        $login    = "verify your account" nocase
        $confirm  = "ihr Konto wurde gesperrt" nocase
        $urgent1  = "innerhalb von 24 Stunden" nocase
        $urgent2  = "sofortige Bestaetigung" nocase
        $finanz   = "FinanzOnline" nocase
        $paypal   = "paypa1" nocase
        $microsft = "micros0ft" nocase
    condition:
        ($login or $confirm or $finanz) and any of ($urgent*, $paypal, $microsft)
}

rule NoRisk_Suspicious_URL_Shortener
{
    meta:
        author      = "FINLAI / NoRisk"
        date        = "2026-05-14"
        severity    = "medium"
        family      = "phishing"
        description = "URL-Shortener in Office-/PDF-Dokumenten — oft Tarnung von Phishing-Links."
    strings:
        $bitly  = /https?:\/\/bit\.ly\// nocase
        $tco    = /https?:\/\/t\.co\// nocase
        $tinyurl= /https?:\/\/tinyurl\.com\// nocase
        $is_gd  = /https?:\/\/is\.gd\// nocase
        $cutt   = /https?:\/\/cutt\.ly\// nocase
    condition:
        any of them
}

rule NoRisk_JS_Eval_Obfuscation
{
    meta:
        author      = "FINLAI / NoRisk"
        date        = "2026-05-14"
        severity    = "high"
        family      = "malware-loader"
        description = "JavaScript mit eval()-basierter Obfuscation."
    strings:
        $eval         = "eval(" nocase
        $string_fromcharcode = "String.fromCharCode" nocase
        $unescape     = "unescape(" nocase
        $atob         = "atob(" nocase
    condition:
        ($eval or $unescape or $atob) and $string_fromcharcode
}

rule NoRisk_LNK_Indicator
{
    meta:
        author      = "FINLAI / NoRisk"
        date        = "2026-05-14"
        severity    = "high"
        family      = "exploit-doc"
        description = "Windows-Shortcut (.lnk) mit PowerShell/cmd-Aufruf — typischer Phishing-Vektor."
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $ps        = "powershell" nocase
        $cmd       = "cmd.exe" nocase
    condition:
        $lnk_magic and ($ps or $cmd)
}
