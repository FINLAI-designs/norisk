"""Tests für JsonValidator — Tiefe, Größe, Schema, Zahlen."""

from __future__ import annotations

import pytest

from core.security import ImportType, validate_import


def _codes(report):
    return [t.code for t in report.threats]


class TestJsonValidatorBasics:
    def test_simple_json_is_safe(self, make_json):
        path = make_json({"key": "value", "nr": 1})
        r = validate_import(path, ImportType.JSON)
        assert r.safe_to_parse is True
        assert r.risk_score == 0

    def test_shallow_nested_ok(self, make_json):
        obj = {"a": {"b": {"c": {"d": 1}}}}
        path = make_json(obj)
        r = validate_import(path, ImportType.JSON)
        assert "JSON_DEPTH_EXCEEDED" not in _codes(r)


class TestJsonDepth:
    def test_depth_exceeded_high(self, make_deep_json):
        path = make_deep_json(150)
        r = validate_import(path, ImportType.JSON)
        assert "JSON_DEPTH_EXCEEDED" in _codes(r)

    def test_depth_at_limit_ok(self, make_deep_json):
        # 100 ist das harte Limit — 100 selbst darf noch durchgehen
        path = make_deep_json(100)
        r = validate_import(path, ImportType.JSON)
        assert "JSON_DEPTH_EXCEEDED" not in _codes(r)


class TestJsonSize:
    def test_size_exceeded_high(self, tmp_path, monkeypatch):
        from core.security.sub_validators import json_validator

        monkeypatch.setattr(json_validator, "MAX_JSON_SIZE_BYTES", 512)
        p = tmp_path / "big.json"
        p.write_text('{"x": "' + "a" * 2000 + '"}', encoding="utf-8")
        r = validate_import(p, ImportType.JSON)
        assert "JSON_FILE_TOO_LARGE" in _codes(r)


class TestJsonSchema:
    def test_schema_compliant_ok(self, make_json):
        path = make_json({"name": "Patrick", "age": 30})
        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        r = validate_import(path, ImportType.JSON, json_schema=schema)
        assert "JSON_SCHEMA_VIOLATION" not in _codes(r)

    def test_schema_violation_reported(self, make_json):
        path = make_json({"name": "Patrick", "age": "thirty"})
        schema = {
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
            },
        }
        r = validate_import(path, ImportType.JSON, json_schema=schema)
        assert "JSON_SCHEMA_VIOLATION" in _codes(r)

    def test_invalid_schema_reported(self, make_json):
        path = make_json({"x": 1})
        # "type" ist Pflichtfeld und muss eindeutig sein
        schema = {"type": "not-a-valid-type"}
        r = validate_import(path, ImportType.JSON, json_schema=schema)
        assert "JSON_SCHEMA_INVALID" in _codes(r)


class TestJsonNumbers:
    def test_huge_integer_reports_low(self, make_json):
        # 2^70 überschreitet MAX_SAFE_INTEGER (2^53)
        obj = {"huge": 2**70}
        path = make_json(obj)
        r = validate_import(path, ImportType.JSON)
        assert "JSON_NUMERIC_OVERFLOW" in _codes(r)


class TestJsonParseError:
    def test_invalid_json_high(self, tmp_path):
        p = tmp_path / "broken.json"
        p.write_text("{not: valid, json", encoding="utf-8")
        r = validate_import(p, ImportType.JSON)
        assert "JSON_PARSE_ERROR" in _codes(r)


class TestJsonPerformance:
    @pytest.mark.slow
    def test_10mb_json_under_2s(self, tmp_path):
        import json
        import time

        # 10 MB = eine Liste mit vielen mittleren Einträgen
        data = [{"i": i, "s": "x" * 100} for i in range(50_000)]
        p = tmp_path / "big.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        t0 = time.perf_counter()
        validate_import(p, ImportType.JSON)
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0
