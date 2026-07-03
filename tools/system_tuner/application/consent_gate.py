"""
consent_gate — Einmaliges Pro-Apply-Consent (R7).

Vor der ERSTEN echten Anwendung muss der Nutzer dem Apply-Haftungs-/EULA-Delta
zugestimmt haben (getrennt vom Per-Tweak-Confirm). Die Zustimmung wird persistent
+ versioniert festgehalten; aendert sich die EULA-Version, ist erneut zuzustimmen.

Zusaetzlich Apply-Vorbedingung (neben Pro-Lizenz, gueltiger Katalog-Signatur und
dem ``allow_apply``-Sign-off-Gate). Reine Datei-Persistenz (JSON), Pfad injizierbar.

Schichtzugehoerigkeit: application/.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

import json
from pathlib import Path

from core.logger import get_logger
from tools.system_tuner.application.apply_terms import APPLY_TERMS_VERSION

log = get_logger(__name__)

#: Aktuelle Apply-Delta-Version — Single Source ist:mod:`apply_terms`. Bei
#: Textaenderung dort die Version erhoehen → erneute Zustimmung wird erzwungen.
CURRENT_EULA_VERSION = APPLY_TERMS_VERSION


class ConsentGate:
    """Persistiert + prueft das einmalige Pro-Apply-Consent."""

    def __init__(self, store_path: Path) -> None:
        self._path = store_path

    def has_consent(self, eula_version: str = CURRENT_EULA_VERSION) -> bool:
        """``True`` nur, wenn fuer genau diese EULA-Version zugestimmt wurde."""
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return bool(data.get("consented")) and data.get("eula_version") == eula_version

    def record_consent(
        self, *, recorded_at: str, eula_version: str = CURRENT_EULA_VERSION
    ) -> None:
        """Hält die Zustimmung fest (idempotent ueberschreibend)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(
                {
                    "consented": True,
                    "eula_version": eula_version,
                    "recorded_at": recorded_at,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        log.info("system_tuner Apply-Consent erfasst (EULA %s)", eula_version)
