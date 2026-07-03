"""
test_scan_worker — pytest-Tests fuer core/scan_worker.py.

PM-1.1b. Deckt die 6 Akzeptanzkriterien aus dem Task-Spec:

1. Worker laesst sich ohne laufende Qt-App instanziieren.
2. ``cancel`` setzt ``_cancelled = True``.
3. ``run`` emittiert ``scan_started``.
4. ``run`` emittiert ``batch_ready`` mit den winget-Items.
5. ``run`` emittiert ``scan_complete`` am Ende.
6. ``run`` emittiert ``scan_failed`` bei Exception.
7. Kein ``QApplication``- oder ``MainWindow``-Import (AST-Check).

Zusaetzlich Verhaltens-Tests aus dem User-Hinweis 2026-05-03:
- Wenn ``collect_winget`` leer zurueckkommt, **kein** ``batch_ready``
  fuer leere Liste — direkt zu Welle 2.
- Wenn beide Sammler leer sind, gibt es **keine** ``batch_ready`` und
  trotzdem ``scan_started`` + ``scan_complete``.
- ``cancel`` mid-stream stoppt Welle 3 ohne weitere
  ``scan_progress``-Events nach dem Cancel-Punkt.

Strategie:
- ``collect_winget`` und ``collect_registry`` werden via monkeypatch im
  ``scan_worker``-Modul ersetzt — der Worker importiert sie als Names,
  also ist Modul-Patching der saubere Weg.
- Signals laufen synchron via DirectConnection (Default fuer
  same-thread Signals), daher kommt keine ``QApplication`` ins Spiel.
"""

from __future__ import annotations

import ast
import inspect
from typing import Any

from core.patch_collector import SoftwareItem

# ===========================================================================
# Helfer
# ===========================================================================


class _SignalRecorder:
    """Sammelt alle Signal-Emissionen in der Reihenfolge, in der sie
    eintreffen — als ``list[tuple[name, *args]]``.

    Wird per ``connect`` an die Signal-Slots gehaengt. Die einzelnen
    Methoden duplizieren sich syntaktisch, weil PySide6 Signals mit
    unterschiedlichen Signaturen erwartet.
    """

    def __init__(self) -> None:
        self.events: list[tuple] = []

    def started(self) -> None:
        self.events.append(("started",))

    def batch_ready(self, items: list[SoftwareItem]) -> None:
        self.events.append(("batch_ready", items))

    def item_enriched(self, obj: Any) -> None:
        self.events.append(("item_enriched", obj))

    def progress(self, current: int, total: int) -> None:
        self.events.append(("progress", current, total))

    def complete(self) -> None:
        self.events.append(("complete",))

    def failed(self, msg: str) -> None:
        self.events.append(("failed", msg))


def _attach_all_signals(worker, rec: _SignalRecorder) -> None:
    """Verbindet alle 6 Worker-Signals mit dem Recorder."""
    worker.scan_started.connect(rec.started)
    worker.batch_ready.connect(rec.batch_ready)
    worker.item_enriched.connect(rec.item_enriched)
    worker.scan_progress.connect(rec.progress)
    worker.scan_complete.connect(rec.complete)
    worker.scan_failed.connect(rec.failed)


def _patch_collectors(monkeypatch, *, winget=None, registry=None) -> None:
    """Patcht ``collect_winget``/``collect_registry`` im scan_worker-Modul.

    ``None`` heisst leere Liste, eine Liste wird wie zurueckgegeben,
    eine ``Exception`` wird beim Aufruf gefeuert.

    Zusaetzlich (PM-1.7): die:class:`PatchService`-Klasse im
    ``scan_worker``-Modul wird durch einen Fake ersetzt, der NICHT
    ``collect_all`` (echter Subprocess + Registry + PowerShell)
    erneut aufruft. Welle 3 wird damit zu einem Stub, der nur die
    Lifecycle-Signals erlaubt.
    """
    from core import scan_worker as sw

    def make(value):
        if isinstance(value, Exception):
            err = value

            def _raise():
                raise err

            return _raise
        return lambda: list(value or [])

    monkeypatch.setattr(sw, "collect_winget", make(winget))
    monkeypatch.setattr(sw, "collect_registry", make(registry))

    # Fake-Service ersetzt die Welle-3-Pipeline. Simuliert
    # ``scan_progress`` ueber ``progress_cb`` fuer jedes Item, das in
    # Welle 1+2 gesammelt wurde — exakt wie die alte Per-Item-Loop.
    winget_items = (
        [] if isinstance(winget, Exception)
        else list(winget or [])
    )
    registry_items = (
        [] if isinstance(registry, Exception)
        else list(registry or [])
    )
    winget_names = {i.name.lower() for i in winget_items}
    extra_registry = [
        i for i in registry_items if i.name.lower() not in winget_names
    ]
    all_items = winget_items + extra_registry

    class _FakeService:
        def scan(self, progress_cb=None):
            total = len(all_items)
            for idx in range(1, total + 1):
                if progress_cb is not None:
                    progress_cb(idx, total)
            return []

    monkeypatch.setattr(sw, "PatchService", lambda: _FakeService())


# ===========================================================================
# Akzeptanz 1 — Worker konstruierbar ohne QApplication
# ===========================================================================


class TestInstantiation:
    def test_konstruktor_ohne_qapp(self):
        from core.scan_worker import ScanWorker

        worker = ScanWorker()
        assert worker is not None
        assert worker._cancelled is False

    def test_signals_sind_klassenattribute(self):
        from core.scan_worker import ScanWorker

        # Alle 6 Signals existieren auf der Klasse, nicht erst auf der Instanz
        for name in (
            "scan_started",
            "batch_ready",
            "item_enriched",
            "scan_progress",
            "scan_complete",
            "scan_failed",
        ):
            assert hasattr(ScanWorker, name), f"Signal {name} fehlt"


# ===========================================================================
# Akzeptanz 2 — cancel setzt _cancelled = True
# ===========================================================================


class TestCancel:
    def test_cancel_setzt_flag(self):
        from core.scan_worker import ScanWorker

        worker = ScanWorker()
        assert worker._cancelled is False
        worker.cancel()
        assert worker._cancelled is True

    def test_cancel_idempotent(self):
        from core.scan_worker import ScanWorker

        worker = ScanWorker()
        worker.cancel()
        worker.cancel()
        assert worker._cancelled is True


# ===========================================================================
# Akzeptanz 3+5 — run emittiert scan_started zu Beginn, scan_complete am Ende
# ===========================================================================


class TestLifecycleSignale:
    def test_started_und_complete_bei_leerem_inventar(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[], registry=[])
        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        # Genau zwei Events: started + complete, kein batch_ready, kein progress
        assert rec.events == [("started",), ("complete",)]


# ===========================================================================
# Akzeptanz 4 — batch_ready mit winget-Items
# ===========================================================================


_FIREFOX = SoftwareItem(
    name="Mozilla Firefox",
    version="120.0.1",
    winget_id="Mozilla.Firefox",
    source="winget",
)
_POWERTOYS = SoftwareItem(
    name="PowerToys",
    version="0.75.1",
    winget_id="Microsoft.PowerToys",
    source="winget",
)
_SEVENZIP = SoftwareItem(
    name="7-Zip 23.01",
    version="23.01",
    winget_id=None,
    source="registry",
)


class TestBatchReady:
    def test_winget_items_loesen_batch_ready_aus(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[_FIREFOX, _POWERTOYS], registry=[])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        batches = [e for e in rec.events if e[0] == "batch_ready"]
        assert len(batches) == 1
        assert batches[0][1] == [_FIREFOX, _POWERTOYS]

    def test_registry_extras_loesen_zweites_batch_ready_aus(self, monkeypatch):
        from core.scan_worker import ScanWorker

        # winget: Firefox; registry: Firefox (Doppel) + 7-Zip (neu)
        _patch_collectors(
            monkeypatch,
            winget=[_FIREFOX],
            registry=[
                SoftwareItem(
                    name="Mozilla Firefox",
                    version="120.0.1",
                    winget_id=None,
                    source="registry",
                ),
                _SEVENZIP,
            ],
        )

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        batches = [e for e in rec.events if e[0] == "batch_ready"]
        # Welle 1 (winget) + Welle 2 (Registry-Extras) = 2 Batches
        assert len(batches) == 2
        assert batches[0][1] == [_FIREFOX]
        assert batches[1][1] == [_SEVENZIP]  # Firefox-Doppel raus

    def test_leeres_winget_feuert_kein_batch_ready(self, monkeypatch):
        """User-Hinweis 2026-05-03: bei leerer winget-Liste **kein**
        ``batch_ready([])`` feuern, sondern direkt zu Welle 2."""
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[], registry=[_SEVENZIP])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        batches = [e for e in rec.events if e[0] == "batch_ready"]
        # Nur Welle 2 (Registry), Welle 1 (winget) hat KEIN Signal gefeuert
        assert len(batches) == 1
        assert batches[0][1] == [_SEVENZIP]

    def test_leere_registry_feuert_kein_batch_ready(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[_FIREFOX], registry=[])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        batches = [e for e in rec.events if e[0] == "batch_ready"]
        assert len(batches) == 1
        assert batches[0][1] == [_FIREFOX]

    def test_beide_quellen_leer_keine_batch_ready(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[], registry=[])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        assert not [e for e in rec.events if e[0] == "batch_ready"]
        # Aber Lifecycle-Signale schon
        assert ("started",) in rec.events
        assert ("complete",) in rec.events


# ===========================================================================
# Welle 3 — scan_progress
# ===========================================================================


class TestScanProgress:
    def test_progress_pro_item(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[_FIREFOX, _POWERTOYS], registry=[])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        progress = [e for e in rec.events if e[0] == "progress"]
        assert progress == [("progress", 1, 2), ("progress", 2, 2)]

    def test_kein_progress_bei_leerem_inventar(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[], registry=[])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        assert not [e for e in rec.events if e[0] == "progress"]

    def test_item_enriched_in_pm_1_1b_noch_nicht_gefeuert(self, monkeypatch):
        """``item_enriched`` ist in PM-1.1b reserviert, aber inaktiv —
        kommt erst in PM-1.5/PM-1.6."""
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[_FIREFOX, _POWERTOYS], registry=[])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        assert not [e for e in rec.events if e[0] == "item_enriched"]

    def test_cancel_stoppt_welle_3(self, monkeypatch):
        """Wenn ``cancel`` vor ``run`` aufgerufen wird, bricht die
        Welle 3 nach dem ersten Item-Check ab — kein einziger
        ``scan_progress``-Event."""
        from core.scan_worker import ScanWorker

        _patch_collectors(monkeypatch, winget=[_FIREFOX, _POWERTOYS], registry=[])

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.cancel()  # Vor run — Welle 3 prueft beim ersten Iter
        worker.run()

        assert not [e for e in rec.events if e[0] == "progress"]
        # Lifecycle-Signale dennoch beide gefeuert (sauberer Stop)
        assert ("started",) in rec.events
        assert ("complete",) in rec.events


# ===========================================================================
# Akzeptanz 6 — scan_failed bei Exception
# ===========================================================================


class TestScanFailed:
    def test_exception_in_winget_loest_scan_failed_aus(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(
            monkeypatch,
            winget=RuntimeError("subprocess explodiert"),
            registry=[],
        )

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        failed = [e for e in rec.events if e[0] == "failed"]
        assert len(failed) == 1
        assert "subprocess explodiert" in failed[0][1]

    def test_exception_in_registry_loest_scan_failed_aus(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(
            monkeypatch,
            winget=[_FIREFOX],
            registry=ValueError("registry kaputt"),
        )

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        failed = [e for e in rec.events if e[0] == "failed"]
        assert len(failed) == 1
        assert "registry kaputt" in failed[0][1]

    def test_failed_nimmt_complete_die_stelle_ab(self, monkeypatch):
        """Wenn die Exception durchschlaegt, gibt es kein
        ``scan_complete`` mehr — der Failure-Pfad ist die Alternative
        zum Erfolgs-Lifecycle."""
        from core.scan_worker import ScanWorker

        _patch_collectors(
            monkeypatch, winget=RuntimeError("boom"), registry=[]
        )

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        # scan_started kommt vor dem try-Block, scan_failed im except —
        # scan_complete liegt am Ende des try-Blocks und wird damit
        # uebersprungen.
        names = [e[0] for e in rec.events]
        assert "started" in names
        assert "failed" in names
        assert "complete" not in names


# ===========================================================================
# Akzeptanz 7 — kein QApplication-/MainWindow-Import (AST-Check)
# ===========================================================================


class TestKeineUiKopplung:
    def test_keine_qapplication_oder_mainwindow_imports(self):
        import core.scan_worker as sw

        src = inspect.getsource(sw)
        tree = ast.parse(src)

        verbotene_substrings = ("qapplication", "mainwindow")

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name.lower()
                    for bad in verbotene_substrings:
                        assert bad not in name, (
                            f"Verbotener Import '{alias.name}' im scan_worker"
                        )
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").lower()
                for bad in verbotene_substrings:
                    assert bad not in module, (
                        f"Verbotener Import 'from {node.module}' im scan_worker"
                    )
                for alias in node.names:
                    name = alias.name.lower()
                    for bad in verbotene_substrings:
                        assert bad not in name, (
                            f"Verbotener Import von '{alias.name}' im scan_worker"
                        )

# ===========================================================================
# Reihenfolge-Smoke: Welle 1 -> Welle 2 -> Welle 3
# ===========================================================================


class TestReihenfolge:
    def test_volle_reihenfolge(self, monkeypatch):
        from core.scan_worker import ScanWorker

        _patch_collectors(
            monkeypatch,
            winget=[_FIREFOX, _POWERTOYS],
            registry=[_SEVENZIP],
        )

        worker = ScanWorker()
        rec = _SignalRecorder()
        _attach_all_signals(worker, rec)

        worker.run()

        names = [e[0] for e in rec.events]
        assert names[0] == "started"
        assert names[-1] == "complete"
        # Erst beide batch_ready, dann progress
        first_batch = names.index("batch_ready")
        last_batch = len(names) - 1 - list(reversed(names)).index("batch_ready")
        first_progress = names.index("progress")
        assert first_batch < last_batch < first_progress
