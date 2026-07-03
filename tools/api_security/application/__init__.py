"""Application-Schicht für API-Security.

Use-Case-Services orchestrieren die Domain-Logik und rufen die `data/`-Adapter
(HTTP-Scanner, Repositories) auf. Keine GUI-Imports, keine direkten HTTP-/DB-Calls.
"""
