"""core/registry — Plattformweite Lookup-/Registry-Services.

Aktuell: ``last_scan_registry`` als zentraler Indirektionspunkt für die
Frage "Wann wurde Tool X zuletzt gescannt?". Wird vom kommenden
Score-Vollständigkeits-Banner (Sprint S3c) und vom Dashboard-Hero
(Sprint S4b) konsumiert, damit diese Konsumenten nicht 8 verschiedene
Tool-APIs kennen müssen.

Schichtzugehörigkeit: core/ — framework-agnostisch (kein PySide6).
"""
