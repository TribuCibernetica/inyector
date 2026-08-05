"""Tests para StackDetector.

Cubre el scoring por headers/cookies/errores para identificar
framework+lenguaje, la detección de DB por firma de error, y que un
score débil (< 2) no fuerce un match espurio.
"""

from unittest.mock import MagicMock

from inyector.recon.stack_detector import StackDetector


def _response(headers=None, text="", cookies=None):
    resp = MagicMock()
    resp.headers = headers or {}
    resp.text = text
    resp.cookies = cookies or []
    return resp


def test_detects_php_by_header_and_cookie():
    detector = StackDetector()
    session = MagicMock()
    session.get.side_effect = [
        _response(headers={"X-Powered-By": "PHP/8.1"}),
        _response(text="sin errores de db"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["language"] == "php"
    assert resultado["confidence"] > 0


def test_weak_score_stays_unknown():
    detector = StackDetector()
    session = MagicMock()
    session.get.side_effect = [
        _response(headers={}, text="pagina sin ninguna firma reconocible"),
        _response(text="sin errores de db"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["language"] == "desconocido"
    assert resultado["framework"] == "desconocido"


def test_detects_database_from_error_signature():
    detector = StackDetector()
    session = MagicMock()
    session.get.side_effect = [
        _response(headers={}, text="sin firmas de stack"),
        _response(text="You have an error in your SQL syntax near '1'"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert "mysql" in resultado["database_hints"]


def test_database_hints_merge_signature_and_error_detection_without_duplicates():
    detector = StackDetector()
    session = MagicMock()
    session.get.side_effect = [
        _response(headers={"X-Powered-By": "PHP/8.1"}),
        _response(text="You have an error in your SQL syntax"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["database_hints"].count("mysql") == 1


def test_generic_security_header_alone_does_not_imply_django():
    """Regresión real (www.uat.edu.mx en SharePoint/.NET, y
    repository.uaeh.edu.mx en OJS/PHP): ambos ocultaban sus headers
    reveladores del stack real pero mandaban 'X-Frame-Options:
    SAMEORIGIN' (hardening genérico, no algo específico de Django), y
    los dos se detectaban como 'Django' solo por eso."""
    detector = StackDetector()
    session = MagicMock()
    session.get.side_effect = [
        _response(headers={"X-Frame-Options": "SAMEORIGIN"},
                   text="pagina sin ninguna firma reconocible"),
        _response(text="sin errores de db"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["framework"] != "Django"
    assert resultado["language"] == "desconocido"


def test_detects_django_by_cookies_without_header_signature():
    """Las cookies csrftoken+sessionid siguen siendo suficientes para
    detectar Django, incluso sin ninguna firma de headers."""
    detector = StackDetector()
    session = MagicMock()
    cookie_csrf = MagicMock(name="csrftoken", value="abc")
    cookie_csrf.name = "csrftoken"
    cookie_session = MagicMock(name="sessionid", value="xyz")
    cookie_session.name = "sessionid"
    session.get.side_effect = [
        _response(headers={}, text="", cookies=[cookie_csrf, cookie_session]),
        _response(text="sin errores de db"),
    ]

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["framework"] == "Django"


def test_timeout_sets_error_field():
    import requests
    detector = StackDetector()
    session = MagicMock()
    session.get.side_effect = requests.exceptions.Timeout()

    resultado = detector.detect("http://x.com/?id=1", session)

    assert resultado["error"] == "timeout"
    assert resultado["language"] == "desconocido"
