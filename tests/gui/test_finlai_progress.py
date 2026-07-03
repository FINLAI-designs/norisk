"""test_finlai_progress Tests fuer FinlaiProgressBar."""

from __future__ import annotations

import pytest

from core.widgets.finlai_progress import FinlaiProgressBar


class TestDefaults:
    """Default-Init: indeterminate, ObjectName, fixe Hoehe."""

    def test_objectname_gesetzt(self, app) -> None:
        bar = FinlaiProgressBar()
        assert bar.objectName() == "FinlaiProgressBar"

    def test_default_indeterminate(self, app) -> None:
        bar = FinlaiProgressBar()
        assert bar.minimum() == 0
        assert bar.maximum() == 0  # Range(0, 0) = indeterminate

    def test_fixe_hoehe_8px(self, app) -> None:
        bar = FinlaiProgressBar()
        assert bar.minimumHeight() == 8
        assert bar.maximumHeight() == 8

    def test_total_bei_init_setzt_determinate(self, app) -> None:
        bar = FinlaiProgressBar(total=42)
        assert bar.minimum() == 0
        assert bar.maximum() == 42
        assert bar.value() == 0


class TestStartIndeterminate:
    """``start_indeterminate`` setzt Range(0, 0) und optional Label."""

    def test_setzt_range_null_null(self, app) -> None:
        bar = FinlaiProgressBar(total=100)  # erst determinate
        bar.start_indeterminate()
        assert bar.maximum() == 0

    def test_label_aktiviert_textvisible(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.start_indeterminate(label="Scan laeuft...")
        assert bar.format() == "Scan laeuft..."
        assert bar.isTextVisible() is True

    def test_ohne_label_kein_text(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.setTextVisible(True)
        bar.start_indeterminate()
        assert bar.isTextVisible() is False


class TestSetDeterminate:
    """``set_determinate`` schaltet auf festes Total um."""

    def test_setzt_total_und_value(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.set_determinate(total=10, current=3)
        assert bar.maximum() == 10
        assert bar.value() == 3

    def test_label_aktiviert_textvisible(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.set_determinate(total=5, label="%v von %m")
        assert bar.format() == "%v von %m"
        assert bar.isTextVisible() is True

    def test_total_kleiner_eins_value_error(self, app) -> None:
        bar = FinlaiProgressBar()
        with pytest.raises(ValueError):
            bar.set_determinate(total=0)


class TestSetStage:
    """``set_stage`` formatiert Multi-Stage-Pattern fuer."""

    def test_setzt_range_und_value(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.set_stage(idx=2, total=3, label="Modell anfragen")
        assert bar.maximum() == 3
        assert bar.value() == 2

    def test_format_string(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.set_stage(idx=1, total=3, label="Daten sammeln")
        assert "1/3" in bar.format()
        assert "Daten sammeln" in bar.format()

    def test_text_immer_sichtbar(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.set_stage(idx=1, total=2, label="Test")
        assert bar.isTextVisible() is True

    def test_idx_zu_klein_value_error(self, app) -> None:
        bar = FinlaiProgressBar()
        with pytest.raises(ValueError):
            bar.set_stage(idx=0, total=3, label="x")

    def test_idx_zu_gross_value_error(self, app) -> None:
        bar = FinlaiProgressBar()
        with pytest.raises(ValueError):
            bar.set_stage(idx=4, total=3, label="x")

    def test_total_null_value_error(self, app) -> None:
        bar = FinlaiProgressBar()
        with pytest.raises(ValueError):
            bar.set_stage(idx=1, total=0, label="x")


class TestHybridLebenszyklus:
    """Typischer Hybrid-Pattern: indeterminate → determinate."""

    def test_indeterminate_dann_determinate(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.start_indeterminate(label="Initialisiere...")
        assert bar.maximum() == 0
        bar.set_determinate(total=42, label="%v von %m")
        assert bar.maximum() == 42
        assert bar.value() == 0


class TestFormatLeak:
    """ Hotfix: ``start_indeterminate`` ohne Label leakt nicht den
    alten Format-String aus einem vorherigen ``set_stage`` / ``set_determinate``.
    """

    def test_set_stage_dann_indeterminate_ohne_label(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.set_stage(idx=2, total=3, label="Modell anfragen")
        assert "Modell anfragen" in bar.format()

        # Ohne Label: Format muss leer sein, sonst wuerde er bei spaeterem
        # setTextVisible(True) wieder auftauchen.
        bar.start_indeterminate()
        assert bar.format() == ""
        assert bar.isTextVisible() is False

    def test_set_stage_dann_indeterminate_mit_label(self, app) -> None:
        bar = FinlaiProgressBar()
        bar.set_stage(idx=2, total=3, label="Modell anfragen")
        bar.start_indeterminate(label="Abbrechen ...")
        # Neuer Label uebernommen, alter weg
        assert bar.format() == "Abbrechen ..."
        assert "Modell anfragen" not in bar.format()


class TestReset:
    """``reset`` bringt die Bar in einen sauberen Default-Zustand."""

    def test_reset_setzt_alles_zurueck(self, app) -> None:
        bar = FinlaiProgressBar(total=100)
        bar.set_stage(idx=2, total=3, label="X")
        # State: range=(0,3), value=2, format="Schritt 2/3 — X", text-visible
        bar.reset()
        assert bar.maximum() == 0  # indeterminate
        assert bar.value() == 0
        assert bar.format() == ""
        assert bar.isTextVisible() is False


class TestBriefingLifecycle:
    """ Lifecycle-Test: set_stage → reset → erneut set_stage funktioniert
    ohne Format-/Wert-Leak (Flicker-Vermeidung).
    """

    def test_lifecycle_drei_runden(self, app) -> None:
        bar = FinlaiProgressBar()
        for _ in range(3):
            bar.set_stage(idx=1, total=3, label="Daten sammeln")
            bar.set_stage(idx=2, total=3, label="Modell anfragen")
            bar.set_stage(idx=3, total=3, label="Antwort verarbeiten")
            bar.reset()
            assert bar.format() == ""
            assert bar.value() == 0


class TestWizardOverride:
    """Wizard-Sonderfall: setFixedHeight(18) ueberschreibt Default 8 px."""

    def test_setfixedheight_ueberschreibt_default(self, app) -> None:
        bar = FinlaiProgressBar(total=4)
        # Default ist 8
        assert bar.minimumHeight() == 8
        # Wizard setzt hoch
        bar.setFixedHeight(18)
        assert bar.minimumHeight() == 18
        assert bar.maximumHeight() == 18


class TestTotalNoneSentinel:
    """ P2: ``total=None`` ist explizites Sentinel fuer indeterminate."""

    def test_total_none_explizit_indeterminate(self, app) -> None:
        bar = FinlaiProgressBar(total=None)
        assert bar.minimum() == 0
        assert bar.maximum() == 0  # Range(0,0) = indeterminate

    def test_default_arg_ist_none(self, app) -> None:
        # Backward-compat: Aufruf ohne Args bleibt indeterminate
        bar = FinlaiProgressBar()
        assert bar.maximum() == 0

    def test_total_zero_bleibt_indeterminate(self, app) -> None:
        # Backward-compat: ``0`` als Magic-Value bleibt erhalten
        bar = FinlaiProgressBar(total=0)
        assert bar.maximum() == 0

    def test_negativer_total_value_error(self, app) -> None:
        import pytest

        with pytest.raises(ValueError):
            FinlaiProgressBar(total=-1)


class TestThemeStylesheetSelectorHook:
    """ P2: ``#FinlaiProgressBar``-Selector im Theme-QSS muss greifen.

    Coupling auf String-ID — wenn jemand ``_OBJECT_NAME`` oder den
    ``QProgressBar#FinlaiProgressBar``-Block in ``core/theme.py`` umbenennt,
    bricht die Vereinheitlichung still. Dieser Test deckt das ab.
    """

    def test_objectname_konstante(self, app) -> None:
        from core.widgets.finlai_progress import _OBJECT_NAME

        assert _OBJECT_NAME == "FinlaiProgressBar"
        bar = FinlaiProgressBar()
        assert bar.objectName() == _OBJECT_NAME

    def test_theme_qss_enthaelt_selector(self) -> None:
        """Smoke-Test: ``QProgressBar#FinlaiProgressBar`` ist im Theme-Stylesheet."""
        from pathlib import Path

        theme_file = Path(__file__).resolve().parent.parent.parent / "core" / "theme.py"
        content = theme_file.read_text(encoding="utf-8")
        assert "QProgressBar#FinlaiProgressBar" in content, (
            "Selector ``QProgressBar#FinlaiProgressBar`` fehlt in core/theme.py — "
            "FinlaiProgressBar verliert seine Vereinheitlichung."
        )
