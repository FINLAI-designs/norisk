"""network_monitor.data.etw_sanitize — Fail-safe-Bereinigung feindlicher ETW-Strings F-C).

Lokale Prozesse beeinflussen ETW-Nutzdaten direkt: ein beliebiger Prozess kann
**DNS-Query-Namen** und **Image-Pfade** in die Kernel-Provider-Events einspeisen.
Diese laufen im **elevated** Collector (RunLevel HIGHEST) durch die Normalizer in
die verschluesselte DB und ggf. ins Log. Ohne Klemme flösse ein unbegrenzt langer
oder steuerzeichen-behafteter String weiter — Risiken: Log-/Anzeige-Injection
(CR/LF/NUL), DB-Bloat, Render-Probleme.

Dieser Helfer begrenzt Laenge und entfernt nicht-druckbare Zeichen. Pure Funktion,
headless-testbar, wirft nie (beliebiger Input -> sicherer String). Genutzt von
:mod:`~tools.network_monitor.data.dns_event_normalizer` und
:mod:`~tools.network_monitor.data.process_path_tracker`.
"""

from __future__ import annotations

from typing import Any


def sanitize_text(value: Any, *, max_len: int) -> str:
    """Bereinigt einen feindlich beeinflussbaren ETW-Text fail-safe.

    Entfernt **nicht-druckbare** Zeichen (Steuerzeichen inkl. NUL/CR/LF/Tab,
    Lone-Surrogates, ungewoehnliche Separatoren) und begrenzt das Ergebnis auf
    ``max_len`` Zeichen. Wirft nie — beliebiger Input ergibt einen sicheren,
    druckbaren String.

    Args:
        value: Roh-Wert aus dem ETW-Event (beliebiger Typ; ``str`` ist der
            Normalfall, alles andere wird via ``str`` defensiv stringifiziert).
        max_len: Maximale Zeichenanzahl des Ergebnisses (positiv).

    Returns:
        Ein druckbarer, auf ``max_len`` begrenzter String (ggf. leer, wenn der
        Input nach dem Strippen keine druckbaren Zeichen enthielt).
    """
    if isinstance(value, str):
        text = value
    else:
        try:
            text = str(value)
        except Exception:  # noqa: BLE001 — fail-safe: ein werfendes __str__ darf den elevated Collector nicht stoppen
            return ""
    cleaned = "".join(ch for ch in text if ch.isprintable())
    return cleaned[: max(max_len, 0)]
