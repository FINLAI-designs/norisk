"""
core.assistant — Fundament des vereinten FINLAI-Assistenten.

Verschmilzt den früheren Security-Chat (``tools/ki_integration``) und den
Handbuch-Assistenten (``tools/handbuch_assistent``) zu EINER gehärteten
Pipeline (Bedienung + IT-Sicherheit), erreichbar über den Handbuch-Dialog.

Module:
    rag_service — RetrievedSource (domänen-getaggter Treffer),
                                Retriever-Port, RagService (Domänen-Dispatch),
                                SecurityCorpusRetriever (Security-Domäne)
    unified_assistant_service — UnifiedAssistantService: orchestriert die volle
                                Pipeline (Scope-Gate → RAG → domänen-geroutete
                                Prompts/Output-Filter → Audit), eine Quelle der
                                Wahrheit.

Schichtzugehörigkeit: core/ (Shared Utilities). Importiert ``core/guardrails``
und ``core/llm``, NIEMALS aus ``tools/`` — der Handbuch-Retriever-Adapter lebt
in ``tools/handbuch_assistent`` und implementiert den hier definierten Port.
"""
