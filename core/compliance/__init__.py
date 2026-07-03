"""core.compliance — deterministisches Regulatorik-Mapping + KMU-Priorisierung.

Festes, auditierbares Mapping von Hardening-Findings auf Norm-Referenzen
(NIS2/IT-SiG/DSGVO/TISAX) plus eine deterministische KMU-Prioritaet
("fixbar mit 1 Person in X Wochen"). Rein, lokal, ohne KI/LLM, ohne Persistenz.

Indikativ — KEINE Rechts-/Compliance-Beratung (siehe ``REGULATORY_DISCLAIMER``).
"""

from __future__ import annotations

from core.compliance.kmu_priority import (
    ComplianceView,
    build_compliance_view,
    compute_kmu_priority,
)
from core.compliance.regulatory_mapping import (
    REGULATORY_DISCLAIMER,
    REGULATORY_INDICATIVE_PREFIX,
    RegFramework,
    RegReference,
    map_finding_to_regulatory,
    regulatory_framework,
    regulatory_label,
)

__all__ = [
    "REGULATORY_DISCLAIMER",
    "REGULATORY_INDICATIVE_PREFIX",
    "ComplianceView",
    "RegFramework",
    "RegReference",
    "build_compliance_view",
    "compute_kmu_priority",
    "map_finding_to_regulatory",
    "regulatory_framework",
    "regulatory_label",
]
