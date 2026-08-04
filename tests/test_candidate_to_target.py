"""Tests para _candidate_to_target — conversión de un candidato del
crawler a un target (url, method, data, param) listo para sqlmap.

El punto central: un candidato de tipo 'html_link' ya trae su query
string completa en 'url' (params es solo ese mismo query ya parseado,
no algo nuevo por agregar). Apendear "?k=v" a ciegas ahí produce una
URL con dos '?', que sqlmap termina probando tal cual.
"""

from inyector.commands.scan import _candidate_to_target


def test_html_link_candidate_does_not_duplicate_existing_query_string():
    """Regresión real (www.uat.edu.mx, SharePoint): el crawler
    encontró 'https://x.com/Authenticate.aspx?Source=%2F' como link
    con query propia. Antes del fix, el resultado era
    '...Authenticate.aspx?Source=%2F?Source=/' -- una URL con dos '?'
    que se mandaba tal cual a sqlmap como target real."""
    candidate = {
        "url": "https://x.com/_layouts/15/Authenticate.aspx?Source=%2F",
        "method": "GET",
        "params": {"Source": "/"},
        "json_body": None,
        "source": "html_link",
    }

    url, method, data, param = _candidate_to_target(candidate, None)

    assert url.count("?") == 1
    assert url == "https://x.com/_layouts/15/Authenticate.aspx?Source=%2F"
    assert method == "GET"
    assert data is None
    assert param == "Source"


def test_form_candidate_without_query_string_gets_params_appended():
    """Un candidato de <form action="/search"> no trae query propia --
    acá sí hay que agregar los params del form como query string."""
    candidate = {
        "url": "https://x.com/search",
        "method": "GET",
        "params": {"q": "test"},
        "json_body": None,
        "source": "html_form",
    }

    url, method, data, param = _candidate_to_target(candidate, None)

    assert url == "https://x.com/search?q=test"
    assert param == "q"


def test_html_link_candidate_merges_extra_params_without_losing_existing_query():
    """Si además de la query propia hubiera un param nuevo (no viene
    hoy del crawler, pero la función debe seguir soportándolo), se
    mergea sin perder lo que ya traía la URL."""
    candidate = {
        "url": "https://x.com/page?existing=1",
        "method": "GET",
        "params": {"existing": "1", "extra": "2"},
        "json_body": None,
        "source": "html_link",
    }

    url, method, data, param = _candidate_to_target(candidate, None)

    assert "existing=1" in url
    assert "extra=2" in url
    assert url.count("?") == 1


def test_post_form_candidate_uses_data_body_not_query_string():
    candidate = {
        "url": "https://x.com/login",
        "method": "POST",
        "params": {"user": "admin", "pass": "x"},
        "json_body": None,
        "source": "html_form",
    }

    url, method, data, param = _candidate_to_target(candidate, None)

    assert url == "https://x.com/login"
    assert data == "user=admin&pass=x"
    assert param == "user"


def test_json_body_candidate_untouched():
    candidate = {
        "url": "https://x.com/api/users",
        "method": "POST",
        "params": None,
        "json_body": {"id": 1},
        "source": "js_api_path",
    }

    url, method, data, param = _candidate_to_target(candidate, None)

    assert url == "https://x.com/api/users"
    assert data == '{"id": 1}'
    assert param == "id"


def test_cli_param_takes_priority_over_crawler_detected_param():
    candidate = {
        "url": "https://x.com/search",
        "method": "GET",
        "params": {"q": "test"},
        "json_body": None,
        "source": "html_form",
    }

    _, _, _, param = _candidate_to_target(candidate, "forced_param")

    assert param == "forced_param"
