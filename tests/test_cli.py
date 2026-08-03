"""Tests para helpers de cli.py.

Cubre create_session(): que la sesión reintenta ante errores
transitorios (502/503/504) pero NUNCA ante 403/406/429 (esos son la
señal misma que waf_detector usa para fingerprinting -- reintentarlos
la enmascararía como error de red en vez de bloqueo real), y que los
headers explícitos del usuario tienen prioridad sobre los generados
por HeaderRotator (comportamiento verificado al escribir tests de
HeaderRotator, que no vive ahí sino en create_session).
"""

from inyector.cli import create_session


def test_session_retries_on_transient_server_errors():
    session = create_session()
    adapter = session.get_adapter("https://x.com")

    assert adapter.max_retries.total == 3
    assert 503 in adapter.max_retries.status_forcelist
    assert 502 in adapter.max_retries.status_forcelist
    assert 504 in adapter.max_retries.status_forcelist


def test_session_does_not_retry_waf_signal_status_codes():
    # 403/406/429 son evidencia de WAF, no errores transitorios --
    # reintentarlos rompería el fingerprinting por comportamiento.
    session = create_session()
    adapter = session.get_adapter("https://x.com")

    for status in (403, 406, 429):
        assert status not in adapter.max_retries.status_forcelist


def test_explicit_header_overrides_generated_header():
    session = create_session(headers=["User-Agent: mi-agente-custom"])
    assert session.headers["User-Agent"] == "mi-agente-custom"


def test_cookie_sets_cookie_header():
    session = create_session(cookie="session=abc123")
    assert session.headers["Cookie"] == "session=abc123"


def test_proxy_applies_to_http_and_https():
    session = create_session(proxy="http://127.0.0.1:8080")
    assert session.proxies == {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080",
    }


def test_no_proxy_by_default():
    session = create_session()
    assert session.proxies == {}
