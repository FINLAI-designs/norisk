# r-tec Cyber Security Lagebericht 2025 — Incident-Erkenntnisse

## Verzögerte Erkennung mangels kontinuierlichem SOC

In einem dokumentierten Vorfall erfolgte die Erkennung bzw. Eindämmung erst drei
Tage nach dem auslösenden Ereignis, weil kein kontinuierlicher SOC-Betrieb bestand
und zusätzlich eine Fehlkonfiguration die automatische Eindämmung verhinderte.
Nachgewiesen wurde der Abfluss von im Browser gespeicherten Zugangsdaten. Lehre:
Ohne durchgehende Überwachung und korrekt konfigurierte automatische Eindämmung
bleiben Angriffe lange unbemerkt; im Browser gespeicherte Anmeldedaten sind ein
bevorzugtes Abfluss-Ziel. (Der einleitende Kontext dieses Fallbeispiels lag im
zugrunde liegenden Auszug nur abgeschnitten vor und wurde nicht ergänzt.) Quelle:
r-tec Cyber Security Lagebericht 2025. Stand: 2025.

## Malvertising-Kampagne „PDF-zu-JPG-RAT" (gefälschte Dateikonverter)

In einem als „PDF-zu-JPG-RAT" bezeichneten Fall (rund 70 Stunden CERT-Aufwand)
wurden über Suchanzeigen gefälschte Dateikonverter-Websites (z. B. PDF→DOCX/JPG)
verbreitet. Die angebotene Software funktionierte im Vordergrund wie erwartet,
während im Hintergrund ein Remote Access Trojan (RAT) persistierte. Als
Persistenzmechanismus dienten Scheduled Tasks, die aus `%LOCALAPPDATA%` ausgeführt
wurden. Lehre: Bei „kostenlosen" Konvertern aus Suchanzeigen ist Vorsicht geboten —
eine sichtbare, erwartungsgemäße Funktion schließt eine im Hintergrund laufende
Schadkomponente nicht aus. (Die Beschreibung des Persistenzmechanismus war im Auszug
abgeschnitten; weiterführende Details lagen nicht vor und wurden nicht erfunden.)
Quelle: r-tec Cyber Security Lagebericht 2025. Stand: 2025.
