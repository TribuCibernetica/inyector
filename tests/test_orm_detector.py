"""Tests para ORMDetector.

Cubre la distinción entre "orm: none" (se probó y no hay firma) y el
caso donde TODOS los payloads fallan por red — reportar 'none' ahí
sería engañoso, porque no es que no haya ORM, es que no se pudo ni
preguntar.
"""

from unittest.mock import MagicMock

import requests

from inyector.recon.orm_detector import ORMDetector


def _response(text=""):
    resp = MagicMock()
    resp.text = text
    return resp


def test_detects_orm_by_error_signature():
    detector = ORMDetector()
    orm_name = next(iter(detector.ORM_SIGNATURES))
    error_sig = detector.ORM_SIGNATURES[orm_name]["errors"][0]

    session = MagicMock()
    session.get.return_value = _response(text=f"algo salio mal: {error_sig}")

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["orm"] == orm_name
    assert resultado["confidence"] >= 0.7
    assert resultado["error"] is None


def test_no_signature_match_returns_none():
    detector = ORMDetector()
    session = MagicMock()
    session.get.return_value = _response(text="respuesta normal sin errores")

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["orm"] == "none"
    assert resultado["confidence"] == 0.0


def test_all_payloads_failing_sets_connection_error_instead_of_none():
    detector = ORMDetector()
    session = MagicMock()
    session.get.side_effect = requests.exceptions.ConnectionError()

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["orm"] == "none"
    assert resultado["error"] == "connection_error"


def test_multiple_signature_matches_raise_confidence():
    detector = ORMDetector()
    orm_name = next(
        name for name, data in detector.ORM_SIGNATURES.items()
        if len(data.get("errors", [])) >= 2
    )
    sigs = detector.ORM_SIGNATURES[orm_name]["errors"]

    session = MagicMock()
    session.get.return_value = _response(text=" ".join(sigs[:2]))

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["orm"] == orm_name
    assert resultado["confidence"] >= 0.85


def test_raw_queries_likely_reflects_escape_hatches_presence():
    detector = ORMDetector()
    orm_name = next(
        name for name, data in detector.ORM_SIGNATURES.items()
        if data.get("escape_hatches")
    )
    error_sig = detector.ORM_SIGNATURES[orm_name]["errors"][0]

    session = MagicMock()
    session.get.return_value = _response(text=error_sig)

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["raw_queries_likely"] is True
    assert resultado["escape_hatches"] == detector.ORM_SIGNATURES[orm_name]["escape_hatches"]
