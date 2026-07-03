"""test_subject_cleanup_hook — Nicht-blockierender DSGVO-Cleanup-Hook, Phase 4).

Der Loeschpfad eines Kunden raeumt NACH erfolgreicher Loeschung Betriebs-/UX-Daten
ohne Aufbewahrungspflicht ab (Workflow-Fortschritt + Notizen). Getestet werden der
Adapter (delegiert an das Repo) und der fail-soft Resolver (liefert immer eine
Liste, nie eine Exception).
"""

from __future__ import annotations

from core.security_subject.resolver import (
    _WorkflowProgressCleanupHook,
    create_subject_cleanup_hooks,
)


class _FakeRepo:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete_for_subject(self, subject_id: str) -> int:
        self.deleted.append(subject_id)
        return 2


def test_hook_delegiert_an_repo() -> None:
    repo = _FakeRepo()
    hook = _WorkflowProgressCleanupHook(repo)
    hook.cleanup("subj-1")
    assert repo.deleted == ["subj-1"]


def test_create_hooks_ist_fail_soft_liste() -> None:
    # Baut das echte Repo (oder faellt fail-soft auf []) — nie eine Exception.
    hooks = create_subject_cleanup_hooks()
    assert isinstance(hooks, list)
    # Jeder Hook erfuellt den Vertrag (cleanup callable).
    for hook in hooks:
        assert callable(hook.cleanup)
