"""Tests para Crawler.

Cubre la extracción de rutas de API desde JS (el vector que hace
falta para SPAs como OWASP Juice Shop, donde el HTML inicial no tiene
ningún link ni form real) y la regresión de priorización: truncar la
lista de rutas a probar ordenada alfabéticamente descartaba rutas
reales importantes como '/rest/user/login' solo porque '/api/...'
viene antes en el alfabeto.
"""

from inyector.recon.crawler import Crawler

JUICE_SHOP_LIKE_JS = '''
var routes = {
  login: "/rest/user/login",
  search: "/rest/products/search",
  users: "/api/Users",
  addresses: "/api/Addresss",
  basket: "/api/BasketItems",
};
fetch("/rest/user/whoami");
fetch("/graphql/v1");
'''


def test_extracts_api_paths_from_js():
    crawler = Crawler()
    matches = {m.group(1) for m in crawler.API_PATH_PATTERN.finditer(JUICE_SHOP_LIKE_JS)}

    assert "/rest/user/login" in matches
    assert "/rest/products/search" in matches
    assert "/api/Users" in matches


def test_high_value_paths_survive_truncation_despite_alphabetical_order():
    # Regresión: con muchos '/api/...' (alfabéticamente primero) y
    # pocos '/rest/...' importantes, un corte alfabético simple
    # descartaba '/rest/user/login' antes de siquiera probarlo.
    crawler = Crawler()
    api_paths = {f"/api/Entity{i}" for i in range(20)}
    api_paths.add("/rest/user/login")
    api_paths.add("/rest/products/search")

    prioritized = sorted(
        api_paths,
        key=lambda p: (
            0 if any(hint in p.lower() for hint in crawler.HIGH_VALUE_HINTS) else 1,
            p,
        ),
    )
    top_10 = prioritized[:10]

    assert "/rest/user/login" in top_10
    assert "/rest/products/search" in top_10


def test_score_prioritizes_login_over_generic_entity():
    crawler = Crawler()
    login_candidate = {
        "url": "http://x.com/rest/user/login", "method": "POST",
        "params": None, "json_body": {"email": "a", "password": "b"},
        "source": "js_api_path",
    }
    generic_candidate = {
        "url": "http://x.com/api/Recycles", "method": "POST",
        "params": None, "json_body": {"email": "a", "password": "b"},
        "source": "js_api_path",
    }

    assert crawler._score(login_candidate) > crawler._score(generic_candidate)


def test_score_does_not_confuse_substring_match_with_real_login_path():
    # Regresión: '/rest/saveLoginIp' contiene "login" como substring
    # pero NO es un endpoint de login real — empataba con
    # '/rest/user/login' y a veces ganaba por orden de inserción.
    crawler = Crawler()
    real_login = {
        "url": "http://x.com/rest/user/login", "method": "POST",
        "params": None, "json_body": {"email": "a", "password": "b"},
        "source": "js_api_path",
    }
    fake_login_substring = {
        "url": "http://x.com/rest/saveLoginIp", "method": "POST",
        "params": None, "json_body": {"email": "a", "password": "b"},
        "source": "js_api_path",
    }

    assert crawler._score(real_login) > crawler._score(fake_login_substring)


def test_dedupe_removes_identical_candidates():
    crawler = Crawler()
    candidates = [
        {"url": "http://x.com/a", "method": "GET", "params": {"q": "1"}, "json_body": None},
        {"url": "http://x.com/a", "method": "GET", "params": {"q": "2"}, "json_body": None},
    ]
    deduped = crawler._dedupe(candidates)
    assert len(deduped) == 1
