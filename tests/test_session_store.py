"""Tests para SessionStore — el mecanismo detrás de --resume. Cubre
el roundtrip de guardar/recuperar recon_data, que targets distintos
(url/param/method) no se pisen entre sí, y que una sesión ausente o
corrupta se trate como "no hay sesión" en vez de reventar el CLI.
"""

import json
import os

from inyector.utils.session_store import SessionStore


RECON_DATA = {
    "waf": {"waf": "cloudflare", "confidence": 0.9},
    "stack": {"stack": "php"},
    "orm": {"orm": "none"},
    "graphql": {"graphql": False},
}


def test_save_then_load_roundtrip(tmp_path):
    store = SessionStore()
    path = store.save(str(tmp_path), "http://x.com/?id=1", "id", "GET", RECON_DATA)

    assert os.path.exists(path)

    loaded = store.load(str(tmp_path), "http://x.com/?id=1", "id", "GET")
    assert loaded == RECON_DATA


def test_save_creates_sessions_subdir(tmp_path):
    store = SessionStore()
    store.save(str(tmp_path), "http://x.com/?id=1", "id", "GET", RECON_DATA)

    assert os.path.isdir(tmp_path / ".inyector_sessions")


def test_load_returns_none_when_nothing_saved(tmp_path):
    store = SessionStore()
    result = store.load(str(tmp_path), "http://x.com/?id=1", "id", "GET")
    assert result is None


def test_load_returns_none_for_corrupt_session_file(tmp_path):
    store = SessionStore()
    path = store.save(str(tmp_path), "http://x.com/?id=1", "id", "GET", RECON_DATA)

    with open(path, "w", encoding="utf-8") as f:
        f.write("{ esto no es json valido ]")

    result = store.load(str(tmp_path), "http://x.com/?id=1", "id", "GET")
    assert result is None


def test_different_params_produce_independent_sessions(tmp_path):
    store = SessionStore()
    data_id = {"param": "id"}
    data_cat = {"param": "cat"}

    store.save(str(tmp_path), "http://x.com/?id=1&cat=2", "id", "GET", data_id)
    store.save(str(tmp_path), "http://x.com/?id=1&cat=2", "cat", "GET", data_cat)

    assert store.load(str(tmp_path), "http://x.com/?id=1&cat=2", "id", "GET") == data_id
    assert store.load(str(tmp_path), "http://x.com/?id=1&cat=2", "cat", "GET") == data_cat


def test_different_methods_produce_independent_sessions(tmp_path):
    store = SessionStore()
    data_get = {"method": "GET"}
    data_post = {"method": "POST"}

    store.save(str(tmp_path), "http://x.com/login", "user", "GET", data_get)
    store.save(str(tmp_path), "http://x.com/login", "user", "POST", data_post)

    assert store.load(str(tmp_path), "http://x.com/login", "user", "GET") == data_get
    assert store.load(str(tmp_path), "http://x.com/login", "user", "POST") == data_post


def test_method_is_case_insensitive_for_session_key(tmp_path):
    store = SessionStore()
    store.save(str(tmp_path), "http://x.com/login", "user", "get", RECON_DATA)

    assert store.load(str(tmp_path), "http://x.com/login", "user", "GET") == RECON_DATA


def test_param_none_is_a_valid_stable_key(tmp_path):
    store = SessionStore()
    store.save(str(tmp_path), "http://x.com/", None, "GET", RECON_DATA)

    assert store.load(str(tmp_path), "http://x.com/", None, "GET") == RECON_DATA
    # Distinto de un param vacío explícito solo si se pasa algo distinto de None.
    assert store.load(str(tmp_path), "http://x.com/", "otro", "GET") is None


def test_save_survives_oserror_and_returns_path_without_raising(tmp_path, monkeypatch):
    store = SessionStore()
    real_open = open

    def failing_open(path, mode="r", *args, **kwargs):
        if "w" in mode:
            raise OSError("disco lleno")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", failing_open)

    path = store.save(str(tmp_path), "http://x.com/", "id", "GET", RECON_DATA)
    assert isinstance(path, str)


def test_saved_file_content_is_valid_json_on_disk(tmp_path):
    store = SessionStore()
    path = store.save(str(tmp_path), "http://x.com/?id=1", "id", "GET", RECON_DATA)

    with open(path, "r", encoding="utf-8") as f:
        on_disk = json.load(f)

    assert on_disk == RECON_DATA
