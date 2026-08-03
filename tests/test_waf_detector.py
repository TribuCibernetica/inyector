"""Tests para WAFDetector.

Cubre las tres fuentes de evidencia (headers/cookies, body, probing
activo) y la distinción entre "sin WAF" y "no se pudo verificar" —
un timeout/connection-error nunca debe reportarse como waf=none con
confianza 0, porque en un reporte de seguridad eso se lee como "no
hay WAF" cuando en realidad no se pudo comprobar nada.
"""

from unittest.mock import MagicMock

import requests

from inyector.recon.waf_detector import WAFDetector


def _response(status_code=200, headers=None, text="", cookies=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    resp.cookies = cookies or []
    return resp


def test_detects_waf_by_header_signature():
    detector = WAFDetector()
    waf_name = next(iter(detector.WAF_SIGNATURES))
    header_name, expected = next(
        iter(detector.WAF_SIGNATURES[waf_name].get("headers", {}).items())
    )
    header_value = expected[0] if isinstance(expected, list) else (
        "anything" if expected is None else expected
    )

    session = MagicMock()
    session.get.return_value = _response(headers={header_name: header_value})

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["waf"] == waf_name
    assert resultado["confidence"] > 0
    assert resultado["error"] is None


def test_no_signature_match_returns_none_with_zero_confidence():
    detector = WAFDetector()
    session = MagicMock()
    session.get.return_value = _response(headers={}, text="pagina normal sin nada raro")

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["waf"] == "none"
    assert resultado["confidence"] == 0.0
    assert resultado["error"] is None


def test_timeout_is_reported_as_error_not_as_no_waf():
    # Un timeout NO es lo mismo que "no hay WAF" — puede ser justo lo
    # contrario (un WAF agresivo cortando la conexión). El resultado
    # debe distinguir explícitamente este caso via 'error'.
    detector = WAFDetector()
    session = MagicMock()
    session.get.side_effect = requests.exceptions.Timeout()

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["error"] == "timeout"
    assert resultado["waf"] == "none"
    assert any("timeout" in e.lower() or "agresivo" in e.lower() for e in resultado["evidence"])


def test_connection_error_is_reported_as_error():
    detector = WAFDetector()
    session = MagicMock()
    session.get.side_effect = requests.exceptions.ConnectionError()

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["error"] == "connection_error"


def test_probing_detects_block_page_when_header_match_is_weak():
    # Con confianza de headers baja (<0.7), se dispara el probing
    # activo — un 403 con firma de block-page conocida debe subir
    # la confianza y reemplazar el resultado débil de headers.
    detector = WAFDetector()
    waf_name = next(
        name for name, sig in detector.WAF_SIGNATURES.items()
        if sig.get("block_page_signatures")
    )
    block_sig = detector.WAF_SIGNATURES[waf_name]["block_page_signatures"][0]

    session = MagicMock()
    session.get.side_effect = [
        _response(headers={}, text="pagina normal"),
        _response(status_code=403, text=f"acceso bloqueado {block_sig}"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["waf"] == waf_name
    assert resultado["confidence"] >= 0.85


def test_probing_unknown_waf_on_generic_block_status():
    detector = WAFDetector()
    session = MagicMock()
    session.get.side_effect = [
        _response(headers={}, text="pagina normal"),
        _response(status_code=406, text="bloqueado sin firma reconocible"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["waf"] == "unknown"
    assert resultado["confidence"] == 0.5
