"""Robuste Encoding-Wahl fuer die Ausgabe von Windows-Konsolen-Subprozessen.

Legacy-Konsolentools (winget-Tabular, ``net``, ``netsh``, ``manage-bde``, ``cscript``)
geben ihre Ausgabe in der **OEM-Codepage** aus (z.B. ``cp850`` auf deutschen
Systemen), NICHT in ``cp1252``/``utf-8``. Wird der Subprozess-Output mit dem
Locale-Default (``cp1252``) dekodiert, kann ein OEM-Byte einen
``UnicodeDecodeError`` im Subprocess-Reader-Thread werfen (Crash mitten im Scan,
) — und blosses ``utf-8`` wuerde Umlaute still verstuemmeln und damit die
Status-Parsing-Logik (z.B. ``Schutz aktiviert``) kippen.

Pflicht-Pattern fuer Windows-Konsolen-Subprozesse:

```python
subprocess.run(cmd, capture_output=True, encoding=console_encoding,
               errors="replace", timeout=...)
```
"""

from __future__ import annotations

import sys


def console_encoding() -> str:
    """Encoding fuer die Ausgabe von Windows-Konsolen-Subprozessen.

    Returns:
        ``"oem"`` auf Windows (die aktive OEM-Codepage, z.B. cp850), sonst
        ``"utf-8"`` (POSIX-Tools geben utf-8 aus).
    """
    return "oem" if sys.platform == "win32" else "utf-8"
