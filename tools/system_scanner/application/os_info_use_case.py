"""os_info_use_case — Headless OS-Eckdaten ohne vollen System-Scan.

Liefert nur die OS-Eckdaten (Name/Version/Build/Architektur) als:class:`OSInfo`,
**ohne** das teure Software-Inventar aus:meth:`PlatformScanner.scan`. Damit kann
ein Cross-Tool-Aufrufer (der ``security_scoring``-AuditPrefill-Adapter
Phase 2) die OS-Info über die **application**-Schicht beziehen, statt
``system_scanner/data`` direkt zu importieren — exakt das Muster von
:func:`tools.system_scanner.application.windows_hardening_scanner.run_hardening_baseline_scan`.

Schichtzugehörigkeit: application/ — orchestriert die plattform-spezifischen
``data``-Detektoren, kein GUI, keine Persistenz.

Author: Patrick Riederich
Version: 1.0 Phase 2, 2026-06-27)
"""

from __future__ import annotations

import platform

from core.logger import get_logger
from tools.system_scanner.domain.entities import OSInfo
from tools.system_scanner.domain.enums import OSPlatform

log = get_logger(__name__)


def detect_os_info() -> OSInfo:
    """Liest die OS-Eckdaten der laufenden Plattform (headless, fail-soft).

    Delegiert an den plattform-spezifischen ``_get_os_info``-Detektor in
    ``data/`` (derselbe, den der jeweilige System-Scanner intern nutzt — kein
    Parallelpfad, Regel 2). Auf einer nicht unterstützten Plattform oder bei
    einem Detektor-Fehler wird ein leeres:class:`OSInfo`
    (``platform=OSPlatform.UNKNOWN``) zurückgegeben — der Aufrufer behandelt das
    als „nicht gemessen".

    Returns:
:class:`OSInfo` mit Name/Version/Build der laufenden Plattform, oder ein
        leeres ``OSInfo(platform=OSPlatform.UNKNOWN)`` (fail-soft).
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            from tools.system_scanner.data.windows_scanner import (  # noqa: PLC0415
                _get_os_info,
            )

            return _get_os_info()
        if system == "darwin":
            from tools.system_scanner.data.macos_scanner import (  # noqa: PLC0415
                _get_os_info,
            )

            return _get_os_info()
        if system == "linux":
            from tools.system_scanner.data.linux_scanner import (  # noqa: PLC0415
                _get_os_info,
            )

            return _get_os_info()
    except Exception as exc:  # noqa: BLE001 — OS-Info ist optional, fail-soft
        log.warning("OS-Info-Erkennung fehlgeschlagen: %s", type(exc).__name__)

    return OSInfo(platform=OSPlatform.UNKNOWN)
