# BSI- und NIST-Leitlinien zu LLM-Sicherheit, Halluzination und Prompt-Injection

## BSI zu Halluzination und RAG

Das BSI hält in „Generative KI-Modelle — Chancen und Risiken" fest, dass die Auswirkungen von
Halluzinationen durch Retrieval-Augmented Generation (RAG) gemildert werden können, weil Nutzer die
zugrundeliegenden Textauszüge einsehen und die Antwort überprüfen können. Halluzination bleibt eine
intrinsische Eigenschaft der Modelle; menschliche Prüfung und Quellentransparenz sind daher
unverzichtbar. Quelle: BSI, „Generative KI-Modelle" v2.0 (17.01.2025),
https://www.bsi.bund.de/ (Publikationen Künstliche Intelligenz). Stand: 2025-01-17.

## BSI zu Prompt-Injection

Das BSI ordnet Prompt-Injection als intrinsische Schwachstelle von LLM-Anwendungen ein, für die es keine
bekannte, zuverlässig und nachhaltig sichere Gegenmaßnahme gibt, die nicht zugleich die Funktionalität
erheblich einschränkt. Konsequenz: mehrschichtige Verteidigung und die Annahme, dass Injection gelingen
kann. Quelle: BSI (Cyber-Sicherheitswarnung/Hinweise zu LLM). Stand: 2025.

## NIST zu generativer KI (AI 600-1)

Das NIST Generative AI Profile (AI 600-1) benennt Confabulation (Halluzination) als zentrales Risiko und
empfiehlt unter anderem, Ausgaben an Quellen zu erden und deren Provenienz nachvollziehbar zu machen
(MS-2.5-005) sowie Quellen und Zitate zu verifizieren (MS-2.5-003). Quelle: NIST AI 600-1,
https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf. Stand: 2024.

## NIST zu adversarialem ML und Prompt-Injection (AI 100-2e2025)

NIST stellt fest, dass aktuelle Modelle gegenüber Prompt-Injection hoch verwundbar bleiben; Systeme
sollten unter der Annahme gebaut werden, dass Injection gelingt. Die Taxonomie unterscheidet u. a.
Evasion, Poisoning, Privacy- und Abuse-Angriffe sowie direkte und indirekte Prompt-Injection. Quelle:
NIST AI 100-2e2025, https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf. Stand: 2025.

## Wirksame Anti-Halluzinations-Techniken

Nach Stand der Forschung und der Leitlinien wirken vor allem: (1) Abstention erlauben („ich weiß es
nicht" statt zu raten) — ein struktureller, nachweislich wirksamer Hebel; (2) RAG-Grounding mit
„antworte nur aus dem bereitgestellten Kontext"; (3) Quellen-/Zitatpflicht in Verbindung mit echtem
Kontext; (4) optional eine unabhängige Groundedness-Prüfung. Eine niedrige Temperatur erhöht die
Reproduzierbarkeit, ist aber kein Halluzinationsschutz. Quelle: NIST/BSI/OWASP sowie veröffentlichte
Forschung. Stand: 2025.

## Eingabe-Verschleierung (Character Smuggling)

Unsichtbare Zeichen (Zero-Width-Zeichen, der Unicode-Tag-Block, bidirektionale Steuerzeichen) und
homoglyphe Zeichen können Wort- und Mustererkennung umgehen und Klassifikatoren täuschen. Eine
deterministische Unicode-Normalisierung (NFKC plus Entfernen unsichtbarer/Steuerzeichen) muss daher als
erste Stufe der Eingabeverarbeitung laufen, bevor weitere Filter greifen. Stand: 2025.
