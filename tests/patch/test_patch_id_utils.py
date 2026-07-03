"""
test_patch_id_utils — Tests fuer die synthetische-Id-Erkennung.

Deckt:func:`core.patch_id_utils.is_synthetic_id`:
* True fuer ``regid:``/``msix:``/``wu:``/``dotnet:``/``drv:``-Praefixe.
* False fuer echte winget-Ids, Store-Ids, leeren String und ``None``.

Sicherheits-Invariante: ``is_synthetic_id`` ist der zentrale Erkennungs-
punkt aller winget-Command-Gates — ein False-Negative wuerde eine
synthetische Id an winget durchlassen.
"""

from __future__ import annotations

import pytest

from core.patch_id_utils import is_synthetic_id


class TestIsSyntheticId:
    @pytest.mark.parametrize(
        "winget_id",
        [
            "regid:mozilla firefox",
            "regid:7-zip",
            "regid:",  # leeres Suffix bleibt synthetisch (Praefix reicht)
            "msix:Microsoft.Photos",
            "msix:",
            "wu:KB5039212",  # ausstehendes Windows-Update
            "wu:",
            "dotnet:.net runtime 8.0",  # installierte.NET-Laufzeit
            "dotnet:",
            "drv:nvidia geforce rtx 4070",  # installierter Geraetetreiber
            "drv:",
        ],
    )
    def test_synthetische_praefixe_sind_true(self, winget_id: str) -> None:
        assert is_synthetic_id(winget_id) is True

    @pytest.mark.parametrize(
        "winget_id",
        [
            "Mozilla.Firefox",
            "7zip.7zip",
            "Microsoft.VCRedist.2013.x86",
            "XP8K2L36VP0QMB",  # Microsoft-Store-Id-Format
            "",
            None,
        ],
    )
    def test_echte_ids_und_leer_sind_false(self, winget_id: str | None) -> None:
        assert is_synthetic_id(winget_id) is False

    def test_praefix_muss_am_anfang_stehen(self) -> None:
        # "regid:" mitten im String macht keine synthetische Id.
        assert is_synthetic_id("Vendor.regid:thing") is False
