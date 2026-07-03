"""finlai_progress — Kanonischer Ladebalken.

Vereinheitlicht ueber 20 Stellen im Code — gleiche Hoehe (8 px), gleicher
Border-Radius, gleiches Theme-Hook-Verhalten. Wer einen Ladebalken braucht,
nutzt:class:`FinlaiProgressBar` — kein eigenes ``setStyleSheet`` mehr.

Drei typische Verwendungsmuster:

1. **Determinate** (Prozent oder X von Y bekannt)::

       bar = FinlaiProgressBar(total=100)
       bar.setValue(42)

2. **Indeterminate** (laufender Vorgang ohne bekanntem Ende)::

       bar = FinlaiProgressBar
       bar.start_indeterminate(label="Scan laeuft...")

3. **Hybrid** (erst indeterminate, spaeter determinate — z. B. Patch-Scan,
   Cert-Monitor, Dependency-Auditor)::

       bar = FinlaiProgressBar
       bar.start_indeterminate(label="Initialisiere...")
       #... spaeter, nachdem Total bekannt ist:
       bar.set_determinate(total=42, label="%v von %m geprueft")

4. **Stage-basiert** (mehrere Phasen mit Label KI-Briefing)::

       bar = FinlaiProgressBar
       bar.set_stage(idx=1, total=3, label="Daten sammeln")
       # spaeter:
       bar.set_stage(idx=2, total=3, label="Modell anfragen")

Schichtzugehoerigkeit: ``core/widgets`` (kein Tool-spezifisches Wissen).

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from PySide6.QtWidgets import QProgressBar, QWidget

# Kanonische Hoehe: 8 px (haeufigste Variante in der Inventur, gleich zu
# Startup-Window und Loading-Overlay). Aenderungen hier sind die zentrale
# Stellschraube fuer das gesamte UI.
_CANONICAL_HEIGHT = 8

# Object-Name wird vom Theme-Stylesheet (``core/theme.py``) gepickt:
# ``QProgressBar#FinlaiProgressBar {... }``. Damit erbt jeder
# FinlaiProgressBar dasselbe Aussehen, auch in Tests ohne explizites
# ``apply_theme``.
_OBJECT_NAME = "FinlaiProgressBar"


class FinlaiProgressBar(QProgressBar):
    """Kanonischer Ladebalken im FINLAI-Stil.

    Setzt automatisch ``objectName=FinlaiProgressBar``, eine fixe Hoehe von
    8 px und sinnvolle Defaults. Custom-Stylesheets sind nicht noetig — die
    visuelle Konsistenz kommt aus ``core/theme.py``.

    Args:
        total: ``None`` (Default) oder ``0`` → indeterminate (Range ``[0, 0]``).
            Positiver Integer → determinate mit Range ``[0, total]``.
            Negative Werte loesen ``ValueError`` aus.
        parent: Eltern-Widget.

 P2: ``None`` als expliziter Sentinel fuer
    "indeterminate" — sauberer als der Magic-Value ``0``. ``0`` bleibt
    aus Backward-Kompatibilitaet ebenfalls indeterminate (kein Bruch
    bestehender 18 Migrations-Stellen).

    Raises:
        ValueError: Wenn ``total`` negativ ist.
    """

    def __init__(
        self,
        total: int | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if total is not None and total < 0:
            raise ValueError(f"total muss >= 0 sein, war {total}")
        self.setObjectName(_OBJECT_NAME)
        self.setFixedHeight(_CANONICAL_HEIGHT)
        self.setTextVisible(False)
        if total is not None and total > 0:
            self.setRange(0, total)
            self.setValue(0)
        else:
            # ``None`` oder ``0`` = indeterminate
            self.setRange(0, 0)

    # ------------------------------------------------------------------
    # Mode-Helpers
    # ------------------------------------------------------------------

    def start_indeterminate(self, label: str | None = None) -> None:
        """Wechselt in den indeterminate-Modus (laufende Animation).

        Args:
            label: Optionaler Format-String (z. B. ``"Scan laeuft..."``).
                Aktiviert ``setTextVisible(True)`` wenn gesetzt.
        """
        self.setRange(0, 0)
        # Vorherigen Format-String IMMER zuruecksetzen — sonst leakt z. B.
        # ``"Schritt 2/3 —..."`` von einem vorherigen ``set_stage`` und
        # bleibt unsichtbar im Hintergrund. Beim naechsten setTextVisible(True)
        # waere er wieder da. Sauberer Reset.
        self.setFormat("")
        if label is not None:
            self.setFormat(label)
            self.setTextVisible(True)
        else:
            self.setTextVisible(False)

    def reset(self) -> None:
        """Setzt Bar auf indeterminate, Wert 0, leeren Format-String, Text aus.

        Aufzurufen beim Verstecken der Bar (``setVisible(False)``), damit
        ein spaeterer Re-Use mit ``set_stage`` keine Format-Reste
        sieht (Flicker-Vermeidung).
        """
        self.setRange(0, 0)
        self.setValue(0)
        self.setFormat("")
        self.setTextVisible(False)

    def set_determinate(
        self,
        total: int,
        current: int = 0,
        label: str | None = None,
    ) -> None:
        """Wechselt in den determinate-Modus mit fixem ``total``.

        Args:
            total: Maximalwert (>= 1).
            current: Aktueller Wert (Default 0).
            label: Optionaler Format-String. ``%v`` = aktueller Wert,
                ``%m`` = Maximum, ``%p`` = Prozent. Beispiel:
                ``"%v von %m geprueft"``. Aktiviert TextVisible wenn gesetzt.

        Raises:
            ValueError: Wenn ``total < 1``.
        """
        if total < 1:
            raise ValueError("total muss >= 1 sein")
        self.setRange(0, total)
        self.setValue(current)
        if label is not None:
            self.setFormat(label)
            self.setTextVisible(True)
        else:
            self.setTextVisible(False)

    def set_stage(self, idx: int, total: int, label: str) -> None:
        """Markiert einen einzelnen Stage-Pattern).

        Setzt den Bar auf ``idx`` von ``total`` und formatiert den Text als
        ``"Schritt idx/total — label"``. Damit reicht ein einziger
        Ladebalken fuer mehrstufige Prozesse (Daten sammeln → Modell
        anfragen → Antwort verarbeiten).

        Args:
            idx: Aktueller Stage (1-basiert, ``1..total``).
            total: Gesamtzahl Stages (>= 1).
            label: User-facing Stage-Beschriftung.

        Raises:
            ValueError: Wenn ``idx <= 0`` oder ``idx > total`` oder
                ``total < 1``.
        """
        if total < 1:
            raise ValueError("total muss >= 1 sein")
        if idx <= 0 or idx > total:
            raise ValueError(f"idx muss in [1, {total}] sein, war {idx}")
        self.setRange(0, total)
        self.setValue(idx)
        self.setFormat(f"Schritt {idx}/{total} — {label}")
        self.setTextVisible(True)
