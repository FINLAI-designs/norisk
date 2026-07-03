"""
test_ollama_version_check — Tests für den Ollama-Versions-Sicherheits-Check
(Plan P0-1, Testplan T11).

Schwerpunkt: semantischer Versionsvergleich statt String-Vergleich
(klassischer Bug: "0.9.0" > "0.17.1" als String → falsch).

Author: Patrick Riederich
"""

import pytest

from core.ollama_utils import (
    MIN_OLLAMA_VERSION,
    OllamaVersionStatus,
    check_ollama_version,
    is_version_at_least,
)


class TestIsVersionAtLeast:
    def test_equal_is_ok(self):
        assert is_version_at_least("0.17.1", "0.17.1") is True

    def test_newer_patch_ok(self):
        assert is_version_at_least("0.17.2", "0.17.1") is True

    def test_newer_minor_ok(self):
        assert is_version_at_least("0.30.6", "0.17.1") is True

    def test_semver_not_string_compare(self):
        # KERN-Test: "0.9.0" ist KLEINER als "0.17.1" (String-Vergleich
        # würde fälschlich True liefern, weil "9" > "1").
        assert is_version_at_least("0.9.0", "0.17.1") is False

    def test_older_patch_rejected(self):
        assert is_version_at_least("0.17.0", "0.17.1") is False

    def test_leading_v_tolerated(self):
        assert is_version_at_least("v0.30.6", "0.17.1") is True

    def test_release_candidate(self):
        # 0.17.1-rc1 ist eine Vorabversion und damit < 0.17.1
        assert is_version_at_least("0.17.1-rc1", "0.17.1") is False

    def test_unparsable_is_false(self):
        assert is_version_at_least("nightly-build", "0.17.1") is False


class TestCheckOllamaVersion:
    def test_ok_version(self):
        status = check_ollama_version("0.30.6")
        assert isinstance(status, OllamaVersionStatus)
        assert status.state == "ok"
        assert status.is_ok is True
        assert status.current == "0.30.6"

    def test_outdated_version(self):
        status = check_ollama_version("0.9.0")
        assert status.state == "outdated"
        assert status.is_ok is False

    def test_unknown_when_empty(self):
        status = check_ollama_version("")
        assert status.state == "unknown"
        assert status.current is None
        assert status.is_ok is False

    def test_minimum_is_reported(self):
        status = check_ollama_version("0.30.6")
        assert status.minimum == MIN_OLLAMA_VERSION


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
