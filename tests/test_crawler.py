"""Tests para Crawler.

Cubre la extracción de rutas de API desde JS (el vector que hace
falta para SPAs como OWASP Juice Shop, donde el HTML inicial no tiene
ningún link ni form real) y la regresión de priorización: truncar la
lista de rutas a probar ordenada alfabéticamente descartaba rutas
reales importantes como '/rest/user/login' solo porque '/api/...'
viene antes en el alfabeto.
"""

from unittest.mock import MagicMock

from bs4 import BeautifulSoup

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


def test_probe_api_paths_only_tries_auth_bodies_against_auth_looking_paths():
    """Regresión real (Juice Shop): un endpoint sin ninguna relación con
    login (ej. '/api/Products') protegido por auth responde 401/403 --
    no 404/405 -- así que el probe viejo lo aceptaba con el PRIMER body
    de la lista (email/password) sin verificar que tuviera sentido.
    Resultado: sqlmap terminaba escaneando 'email' contra el endpoint
    de productos, que no lo procesa, y el scan volvía limpio contra un
    target realmente vulnerable en otro lado."""
    crawler = Crawler()

    session = MagicMock()
    session.get.return_value = MagicMock(status_code=401)  # nunca 404/405
    session.post.return_value = MagicMock(status_code=401)  # nunca 404/405

    found = crawler._probe_api_paths(
        "http://x.com", ["/api/Products", "/rest/user/login"], session,
    )

    products = [
        c for c in found
        if c["url"].endswith("/api/Products") and c["method"] == "POST"
    ]
    login = [
        c for c in found
        if c["url"].endswith("/rest/user/login") and c["method"] == "POST"
    ]

    assert products, "no se encontró candidato para /api/Products"
    assert "email" not in (products[0]["json_body"] or {})
    assert "id" in (products[0]["json_body"] or {})

    assert login, "no se encontró candidato para /rest/user/login"
    assert "email" in (login[0]["json_body"] or {})


def test_post_form_yields_urlencoded_params_not_json_body():
    # Regresión real (UAEH): un <form method="post"> HTML manda
    # application/x-www-form-urlencoded, no JSON. Marcarlo como
    # json_body hacía que sqlmap probara un body JSON contra un
    # backend PHP que nunca poblaba $_POST con eso -- falso negativo
    # total en un login con SQLi confirmada por SAST y manualmente.
    html = '''
    <form method="post" action="/sape/index.php">
      <input name="txtUsuario" value="">
      <input name="txtContrasenya" value="">
      <input type="hidden" name="hdnRol" value="1">
    </form>
    '''
    soup = BeautifulSoup(html, "html.parser")
    crawler = Crawler()

    candidates = crawler._extract_forms(
        "http://x.com/sape/index.php", "http://x.com", soup,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["method"] == "POST"
    assert candidate["json_body"] is None
    assert candidate["params"] == {
        "txtUsuario": "test", "txtContrasenya": "test", "hdnRol": "1",
    }
    # "hdnRol" no es un nombre de campo CSRF conocido -- no-op explícito
    # para el caso default (la gran mayoría de forms reales).
    assert "csrf" not in candidate


def test_detects_moodle_logintoken_as_csrf_field():
    # Regresión real (tie.teziutlan.tecnm.mx): el 'logintoken' de
    # Moodle es de un solo uso -- reusar el mismo valor en un segundo
    # POST simplemente re-renderiza el form vacío sin procesar el
    # login. sqlmap necesita --csrf-token/--csrf-url para refrescarlo
    # antes de cada request.
    html = '''
    <form method="post" action="/m24/login/index.php">
      <input type="hidden" name="anchor" value="">
      <input type="hidden" name="logintoken" value="PECvIlw5H94akhqYpGX9uy8QDNjmLCSs">
      <input type="text" name="username" value="">
      <input type="password" name="password" value="">
    </form>
    '''
    soup = BeautifulSoup(html, "html.parser")
    crawler = Crawler()

    candidates = crawler._extract_forms(
        "https://tie.teziutlan.tecnm.mx/m24/login/index.php",
        "https://tie.teziutlan.tecnm.mx", soup,
    )

    assert len(candidates) == 1
    assert candidates[0]["csrf"] == {
        "field": "logintoken",
        "url": "https://tie.teziutlan.tecnm.mx/m24/login/index.php",
        "method": "GET",
    }


def test_prioritizes_viewstate_over_other_aspnet_webforms_fields():
    # Regresión real (cloud.teziutlan.tecnm.mx): un form ASP.NET
    # WebForms trae 3 campos dinámicos (__VIEWSTATE, __EVENTVALIDATION,
    # __VIEWSTATEGENERATOR) pero sqlmap solo refresca UNO por corrida
    # -- CSRF_FIELD_PRIORITY debe elegir siempre el mismo de forma
    # determinística.
    html = '''
    <form method="post" action="./frmLogin.aspx">
      <input type="hidden" name="__VIEWSTATE" value="abc123==">
      <input type="hidden" name="__VIEWSTATEGENERATOR" value="44CFBAFC">
      <input type="hidden" name="__EVENTVALIDATION" value="xyz789=">
      <input name="ctl00$cphContenido$txtNoControl" value="">
      <input type="password" name="ctl00$cphContenido$txtPassword" value="">
    </form>
    '''
    soup = BeautifulSoup(html, "html.parser")
    crawler = Crawler()

    candidates = crawler._extract_forms(
        "https://cloud.teziutlan.tecnm.mx/PrecargaWeb/webForms/frmLogin.aspx",
        "https://cloud.teziutlan.tecnm.mx", soup,
    )

    assert candidates[0]["csrf"]["field"] == "__VIEWSTATE"


def test_dedupe_removes_identical_candidates():
    crawler = Crawler()
    candidates = [
        {"url": "http://x.com/a", "method": "GET", "params": {"q": "1"}, "json_body": None},
        {"url": "http://x.com/a", "method": "GET", "params": {"q": "2"}, "json_body": None},
    ]
    deduped = crawler._dedupe(candidates)
    assert len(deduped) == 1
