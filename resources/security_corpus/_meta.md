# Security-Wissenskorpus — Metadaten

Kuratierter, **datierter Offline-Snapshot** offizieller Sicherheitsquellen für das RAG-Grounding
des NoRisk Security-Chats (Plan P1-1, Variante A). Der Chat beantwortet IT-Sicherheitsfragen
bevorzugt aus diesem Korpus und nennt die Quelle; ist nichts Belegtes vorhanden, abstrahiert er
(„keine gesicherte Information") oder kennzeichnet allgemeine Erklärungen als nicht quellenbelegt.

- **Snapshot-Stichtag:** 2026-06-06
- **Quellen (Snapshot):** OWASP GenAI (Top 10 for LLM Apps 2025), NIST (AI 600-1, AI 100-2e2025, AI RMF),
  BSI („Generative KI-Modelle"), MITRE ATLAS, NVD/GitHub Security Advisories (Ollama-CVEs).
- **Kuratoren-Erweiterungen (nach dem Snapshot ergänzte Sekundärquellen):** IT-SICHERHEIT 3/2026
  (Security Awareness / CEO Fraud), r-tec Cyber Security Lagebericht 2025 (anonymisierte
  Incident-Lehren), DSGVO-Checkliste Version 2.0 (Datenschutz/Regulatorik). Redaktionell kuratiert
  (kein User-Upload); werbliche Produkt-/Herstellernamen wurden bewusst nicht übernommen.
- **Kuratierung:** Inhalte sind verifizierte Paraphrasen mit Quellen- und Stand-Angabe je Abschnitt
  (kein vollständiger Spiegel der Quellen). Erweiterbar.

## Integrität & Pflege (LLM08 Vector/Embedding Weaknesses)

- **Kein User-Upload** in den Korpus — nur kuratierte, offizielle Quellen (verhindert Korpus-Poisoning).
- Produktionsweg: serverseitig bei FINLAI gebaut, **signiert** und als datiertes Datenpaket per
  App-Update ausgerollt (entkoppelt von Live-Internet → keine SSRF-/Indirect-Injection-Fläche).
- Aktualität ist der teure Teil (nicht die Suche). Der Stichtag MUSS in der UI sichtbar sein, sonst
  Haftungsvektor „veraltete Aussage wirkt aktuell".

## Hinweis zur Vollständigkeit

Dies ist ein **Starter-Korpus**, der das Grounding-Verhalten trägt und demonstriert. Die vollständige,
laufende Ingestion (u. a. CISA-KEV-Feed CC0, NVD-Auszug inkrementell via `lastModStartDate/End`) ist
der Produktivierungsschritt und bewusst nicht Teil dieses Snapshots.
