"""Tests para HeaderRotator — que los headers generados sean
consistentes/realistas y que la rotación efectivamente varíe el
User-Agent y el Accept-Language entre llamadas (no siempre lo mismo).

Nota: la prioridad de headers explícitos del usuario sobre los
generados NO vive en este módulo — HeaderRotator.get_realistic_headers
no acepta overrides; ese merge ocurre en cli.create_session(), que
aplica los headers del usuario después de los generados.
"""

from inyector.utils.headers import HeaderRotator


def test_get_realistic_headers_contains_expected_keys():
    rotator = HeaderRotator()
    headers = rotator.get_realistic_headers()

    for key in (
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Connection",
        "Upgrade-Insecure-Requests",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Site",
        "Sec-Fetch-User",
        "Cache-Control",
    ):
        assert key in headers


def test_get_realistic_headers_user_agent_and_language_from_known_lists():
    rotator = HeaderRotator()
    headers = rotator.get_realistic_headers()

    assert headers["User-Agent"] in HeaderRotator.REAL_USER_AGENTS
    assert headers["Accept-Language"] in HeaderRotator.ACCEPT_LANGUAGES


def test_get_random_user_agent_returns_known_value():
    rotator = HeaderRotator()
    assert rotator.get_random_user_agent() in HeaderRotator.REAL_USER_AGENTS


def test_realistic_headers_rotate_user_agent_across_calls():
    rotator = HeaderRotator()
    seen = {
        rotator.get_realistic_headers()["User-Agent"] for _ in range(100)
    }
    # Con 8 user-agents disponibles, 100 llamadas casi seguro producen
    # más de uno distinto si realmente hay rotación aleatoria.
    assert len(seen) > 1


def test_realistic_headers_rotate_accept_language_across_calls():
    rotator = HeaderRotator()
    seen = {
        rotator.get_realistic_headers()["Accept-Language"] for _ in range(100)
    }
    assert len(seen) > 1


def test_get_random_user_agent_also_rotates():
    rotator = HeaderRotator()
    seen = {rotator.get_random_user_agent() for _ in range(100)}
    assert len(seen) > 1
