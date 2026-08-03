"""Tests para load_signatures — que cargue los JSON reales de
inyector/data/ usados por WAFDetector/ORMDetector, que cachee por
filename (lru_cache), y que un archivo ausente o corrupto falle de
forma explícita en vez de devolver silenciosamente un dict vacío.
"""

import json

import pytest

import inyector.utils.signatures as signatures_module
from inyector.utils.signatures import load_signatures


def test_loads_real_waf_signatures_file():
    data = load_signatures("waf_signatures.json")
    assert isinstance(data, dict)
    assert "cloudflare" in data


def test_loads_real_orm_signatures_file():
    data = load_signatures("orm_signatures.json")
    assert isinstance(data, dict)
    assert len(data) > 0


def test_load_signatures_is_cached_returns_same_object():
    first = load_signatures("waf_signatures.json")
    second = load_signatures("waf_signatures.json")
    assert first is second


def test_missing_file_raises_file_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr(signatures_module, "DATA_DIR", str(tmp_path))

    with pytest.raises(FileNotFoundError):
        load_signatures("no_existe_este_archivo.json")


def test_corrupt_json_raises_decode_error(tmp_path, monkeypatch):
    monkeypatch.setattr(signatures_module, "DATA_DIR", str(tmp_path))
    corrupt_file = tmp_path / "corrupto.json"
    corrupt_file.write_text("{ esto no es json valido ]", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        load_signatures("corrupto.json")


def test_valid_custom_signatures_file_loads_correctly(tmp_path, monkeypatch):
    monkeypatch.setattr(signatures_module, "DATA_DIR", str(tmp_path))
    custom_file = tmp_path / "custom_signatures.json"
    custom_file.write_text(json.dumps({"foo": {"bar": 1}}), encoding="utf-8")

    data = load_signatures("custom_signatures.json")
    assert data == {"foo": {"bar": 1}}
