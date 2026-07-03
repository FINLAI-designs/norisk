"""
token_ledger — Persistenter Single-Use-Token-Store (A2-voll, Replay-Schutz).

Append-only Liste verbrauchter Plan-Tokens. Liegt in der admin-only Ablage
(`secure_store`), damit ein Non-Admin den Ledger nicht leeren kann, um einen
gueltigen Plan erneut abzuspielen. Ergaenzt die Single-Use-Datei-Loeschung
(T5) um Schutz ueber Prozess-/Lauf-Grenzen hinweg (commit-then-act:
``mark_used`` VOR dem Apply).

Schichtzugehoerigkeit: data/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from pathlib import Path

from core.logger import get_logger

log = get_logger(__name__)

_LEDGER_NAME = "used_tokens.txt"
#: Obergrenze gegen unbegrenztes Wachstum (Tokens sind uuid4-hex).
_MAX_TOKENS = 100_000


class FileTokenLedger:
    """Append-only Token-Ledger (eine Zeile pro verbrauchtem Token)."""

    def __init__(self, store_dir: Path) -> None:
        self._path = store_dir / _LEDGER_NAME

    def load_used(self) -> frozenset[str]:
        """Liefert die Menge bereits verbrauchter Tokens."""
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return frozenset()
        return frozenset(line.strip() for line in lines if line.strip())

    def mark_used(self, token: str) -> bool:
        """Traegt ``token`` als verbraucht ein (idempotent, append-only).

        Returns:
            ``True`` bei Erfolg; ``False`` wenn nicht geschrieben werden konnte
            (Caller behandelt das fail-closed — ohne Eintrag kein Apply).
        """
        if not token:
            return False
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(token.strip() + "\n")
        except OSError as exc:
            log.error("Token-Ledger nicht schreibbar (fail-closed): %s", exc)
            return False
        return True
