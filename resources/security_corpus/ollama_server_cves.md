# Ollama-Server: Schwachstellen und Härtung

## Fehlende native Authentifizierung

Der lokale Ollama-Server verlangt beim Zugriff auf die lokale API keine Authentifizierung. Ein
`OLLAMA_API_KEY`/Bearer-Token gilt nur für die ollama.com-Cloud, nicht für den lokalen Endpoint. Folge:
Jeder lokale Prozess kann den Port (Standard 11434) ansprechen. Härtung: Bindung explizit auf 127.0.0.1,
lokale Firewall-Regel für den Port, keine Modell-Management-Endpoints (create/pull/push) aus der
Anwendung anbieten. Quelle: docs.ollama.com (API authentication). Stand: 2026.

## CVE-2024-37032 „Probllama"

Path-Traversal über den Modell-Pull-Pfad, der zu Remote Code Execution führen kann; behoben in Ollama
0.1.34. Öffentliche Proof-of-Concepts existieren. Da der Auslöser ein Modell-Import ist, schützt die
Bindung auf den eigenen Rechner allein nicht. Quelle: NVD https://nvd.nist.gov/vuln/detail/CVE-2024-37032,
Wiz „Probllama". Stand: 2024.

## CVE-2024-7773 (ZipSlip)

ZipSlip-Schwachstelle beim Verarbeiten von Modell-Archiven, die zu beliebigem Schreibzugriff auf das
Dateisystem (RCE) führen kann; behoben in Ollama 0.1.37. Quelle: GitHub Security Advisory / NVD.
Stand: 2024.

## CVE-2024-39719 bis -39722 (Oligo-Serie)

Mehrere Schwachstellen (u. a. File-Existence-Disclosure und Denial-of-Service über create/push), behoben
in Ollama 0.1.46; zusätzlich „by design"-Risiken wie Modell-Poisoning beim Pull und Modell-Diebstahl beim
Push. Quelle: Oligo „More Models, More ProbLLMs", https://www.oligo.security/blog/more-models-more-probllms.
Stand: 2024.

## GGUF-Parsing-Schwachstellen (DoS)

Fehler beim Parsen von GGUF-Modelldateien können Denial-of-Service auslösen (z. B. Null-Pointer,
unbegrenzter Speicher). Da file-getriggert, schützt die localhost-Bindung nicht. Quelle: NVD/GHSA.
Stand: 2025.

## Empfohlene Mindestversion und Betrieb

Wegen mehrerer file-getriggerter Schwachstellen ist eine Mindestversion des Servers Pflicht; als
konservative Untergrenze deckt Version 0.17.1 die hier genannten Bugs ab, empfohlen ist die jeweils
aktuelle Stable-Version. Der Versionsvergleich muss semantisch erfolgen (echter Versionsvergleich, nicht
Zeichenkettenvergleich — sonst gilt „0.9" fälschlich als neuer als „0.17"). Betrieb: lokal, ohne
Tool-/Aktionsvollmacht, Modellnamen gegen eine Allowlist validiert. Quelle: NVD/docs.ollama.com.
Stand: 2026-06-06.
