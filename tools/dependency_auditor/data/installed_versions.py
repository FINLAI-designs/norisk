"""
installed_versions — Aufloesung installierter Paket-Versionen.

Ermittelt fuer Dependencies ohne ``==``-Pin die tatsaechlich installierte
Version der LAUFENDEN Python-Umgebung via ``importlib.metadata``.

Nur fuer das Selbst-Audit gedacht (``AuditService.audit_self``): beim Scan
fremder requirements-Dateien waere die lokale Umgebung die falsche Quelle —
dort bleibt die Version unbekannt.

Schichtzugehoerigkeit: data/ — Environment-Zugriff, kein GUI-Import.

Author: Patrick Riederich
Version: 1.0
"""

from __future__ import annotations

from importlib import metadata

from core.logger import get_logger
from tools.dependency_auditor.domain.models import DependencyInfo

_log = get_logger(__name__)


def get_installed_version(package_name: str) -> str | None:
    """Liefert die installierte Version eines Packages oder None.

    Args:
        package_name: PyPI-Package-Name (PEP-503-normalisiert oder roh —
            ``importlib.metadata`` normalisiert selbst).

    Returns:
        Versions-String der laufenden Umgebung oder None wenn das Package
        nicht installiert ist.
    """
    try:
        return metadata.version(package_name)
    except metadata.PackageNotFoundError:
        _log.debug(
            "Package %s ist in der laufenden Umgebung nicht installiert",
            package_name,
        )
        return None


def resolve_installed_versions(
    dependencies: list[DependencyInfo],
) -> list[DependencyInfo]:
    """Setzt ``version_installed`` fuer alle Dependencies ohne ``==``-Pin.

    Gepinnte Dependencies werden uebersprungen — der Pin gewinnt im
    Analyzer ohnehin vor der installierten Version
    (:meth:`DependencyInfo.effective_version`).

    Args:
        dependencies: Geparste Dependencies (werden in-place ergaenzt).

    Returns:
        Dieselbe Liste (fuer bequemes Chaining).
    """
    for dep in dependencies:
        if dep.version_pinned is not None:
            continue
        dep.version_installed = get_installed_version(dep.name)
    return dependencies
