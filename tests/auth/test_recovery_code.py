"""Tests für:mod:`core.auth.recovery_code`."""

from __future__ import annotations

import re

from core.auth.recovery_code import (
    CODE_LENGTH,
    RECOVERY_ALPHABET,
    generate_recovery_code,
    hash_recovery_code,
    is_valid_format,
    normalize_recovery_code,
    verify_recovery_code,
)


class TestAlphabet:
    def test_no_confusables(self) -> None:
        for ch in "0O1IL8B":
            assert ch not in RECOVERY_ALPHABET

    def test_alphabet_length(self) -> None:
        # Base32 (32) enthält keine 0/1/8 — die werden also nicht wirklich
        # entfernt. Effektiv entfernt werden O, I, L, B (4 Zeichen) → 28.
        assert len(RECOVERY_ALPHABET) == 28


class TestGenerateRecoveryCode:
    def test_format(self) -> None:
        code = generate_recovery_code()
        assert re.match(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", code)

    def test_length(self) -> None:
        code = generate_recovery_code()
        assert len(code) == CODE_LENGTH + 3  # 16 chars + 3 hyphens

    def test_uniqueness(self) -> None:
        codes = {generate_recovery_code() for _ in range(100)}
        assert len(codes) == 100

    def test_uses_only_allowed_chars(self) -> None:
        code = generate_recovery_code().replace("-", "")
        for ch in code:
            assert ch in RECOVERY_ALPHABET


class TestNormalization:
    def test_lowercase_uppercased(self) -> None:
        assert normalize_recovery_code("abcd-efgh-ijkl-mnpq") == "ABCD-EFGH-IJKL-MNPQ"

    def test_no_hyphens_added(self) -> None:
        assert normalize_recovery_code("ABCDEFGHIJKLMNPQ") == "ABCD-EFGH-IJKL-MNPQ"

    def test_spaces_stripped(self) -> None:
        assert (
            normalize_recovery_code("ABCD EFGH IJKL MNPQ") == "ABCD-EFGH-IJKL-MNPQ"
        )

    def test_underscores_stripped(self) -> None:
        assert (
            normalize_recovery_code("ABCD_EFGH_IJKL_MNPQ") == "ABCD-EFGH-IJKL-MNPQ"
        )


class TestIsValidFormat:
    def test_valid(self) -> None:
        assert is_valid_format("ABCD-EFGH-IJKL-MNPQ") is True

    def test_lowercase_invalid(self) -> None:
        assert is_valid_format("abcd-efgh-ijkl-mnpq") is False

    def test_wrong_length_invalid(self) -> None:
        assert is_valid_format("ABC-EFGH-IJKL-MNPQ") is False
        assert is_valid_format("ABCD-EFGH-IJKL-MNPQR") is False


class TestHashAndVerify:
    def test_roundtrip_exact(self) -> None:
        code = generate_recovery_code()
        h = hash_recovery_code(code)
        assert verify_recovery_code(code, h) is True

    def test_roundtrip_with_lowercase(self) -> None:
        code = generate_recovery_code()
        h = hash_recovery_code(code)
        assert verify_recovery_code(code.lower(), h) is True

    def test_roundtrip_with_extra_spaces(self) -> None:
        code = generate_recovery_code()
        h = hash_recovery_code(code)
        spaced = code.replace("-", " ")
        assert verify_recovery_code(spaced, h) is True

    def test_wrong_code_rejected(self) -> None:
        h = hash_recovery_code("ABCD-EFGH-IJKL-MNPQ")
        assert verify_recovery_code("ABCD-EFGH-IJKL-MNPR", h) is False

    def test_empty_hash_rejected(self) -> None:
        assert verify_recovery_code("ABCD-EFGH-IJKL-MNPQ", "") is False

    def test_malformed_hash_rejected(self) -> None:
        assert verify_recovery_code("ABCD-EFGH-IJKL-MNPQ", "not-a-hash") is False

    def test_malformed_code_rejected(self) -> None:
        h = hash_recovery_code("ABCD-EFGH-IJKL-MNPQ")
        assert verify_recovery_code("only-12-chars", h) is False
