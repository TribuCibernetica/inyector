"""Tests para payload_verifier — la confirmación con evidencia real.

El punto central: una sugerencia (de IA o de KnowledgeBase) solo cuenta
como "confirmada" si hay evidencia HTTP concreta (firma de error real,
delay de tiempo significativo, o cambio de comportamiento) — nunca
solo porque "suena razonable".
"""

import json
from types import SimpleNamespace
from unittest.mock import patch

from inyector.intelligence.payload_verifier import verify_payload


class FakeSession:
    """Sesión HTTP falsa: devuelve respuestas pre-programadas según
    si la URL contiene el payload probado o no."""

    def __init__(self, baseline_text="normal", payload_response_text="normal",
                 status_code=200, baseline_status_code=None):
        self.baseline_text = baseline_text
        self.payload_response_text = payload_response_text
        self.status_code = status_code
        self.baseline_status_code = (
            baseline_status_code if baseline_status_code is not None else status_code
        )
        self.calls = []
        self.post_calls = []

    def get(self, url, timeout=None):
        self.calls.append(url)
        # Primera llamada = baseline (verify_payload la pide primero
        # si no se le pasó una ya calculada); la segunda = la URL con
        # el payload de test.
        is_baseline = len(self.calls) == 1
        text = self.baseline_text if is_baseline else self.payload_response_text
        status = self.baseline_status_code if is_baseline else self.status_code
        return SimpleNamespace(status_code=status, text=text)

    def post(self, url, json=None, data=None, timeout=None):
        self.post_calls.append({"url": url, "json": json, "data": data})
        is_baseline = len(self.post_calls) == 1
        text = self.baseline_text if is_baseline else self.payload_response_text
        status = self.baseline_status_code if is_baseline else self.status_code
        return SimpleNamespace(status_code=status, text=text)


def test_error_based_payload_is_confirmed_by_db_error_signature():
    session = FakeSession(
        baseline_text="<html>ok</html>",
        payload_response_text="You have an error in your SQL syntax near '1'",
    )
    result = verify_payload(
        "http://example.com/page?id=1", session, "id", "1' AND 1=CONVERT(int,'x')--",
    )
    assert result["confirmed"] is True
    assert result["signal"] == "error_based"


def test_boolean_based_payload_confirmed_by_different_response():
    session = FakeSession(
        baseline_text="a" * 500,
        payload_response_text="b" * 50,  # muy distinto en longitud
    )
    result = verify_payload(
        "http://example.com/page?id=1", session, "id", "1' AND '1'='2",
    )
    assert result["confirmed"] is True
    assert result["signal"] == "boolean_based"


def test_similar_responses_are_not_confirmed():
    session = FakeSession(
        baseline_text="a" * 500,
        payload_response_text="a" * 498,  # prácticamente igual
    )
    result = verify_payload(
        "http://example.com/page?id=1", session, "id", "1' AND '1'='1",
    )
    assert result["confirmed"] is False
    assert result["signal"] == "none"


def test_time_based_payload_confirmed_by_real_delay():
    session = FakeSession(baseline_text="ok", payload_response_text="ok")

    # baseline: t=0 -> t=0.2 (elapsed 0.2s); test: t=0.2 -> t=6.5 (elapsed 6.3s)
    with patch(
        "inyector.intelligence.payload_verifier.time.time",
        side_effect=[0, 0.2, 0.2, 6.5],
    ):
        result = verify_payload(
            "http://example.com/page?id=1", session, "id",
            "1' AND SLEEP(5)-- -",
        )

    assert result["confirmed"] is True
    assert result["signal"] == "time_based"


def test_time_based_payload_not_confirmed_without_real_delay():
    session = FakeSession(baseline_text="ok", payload_response_text="ok")

    with patch(
        "inyector.intelligence.payload_verifier.time.time",
        side_effect=[0, 0.2, 0.2, 0.4],
    ):
        result = verify_payload(
            "http://example.com/page?id=1", session, "id",
            "1' AND SLEEP(5)-- -",
        )

    assert result["confirmed"] is False


def test_post_method_mutates_json_body_instead_of_query_string():
    """Regresión real (Juice Shop): antes SIEMPRE se probaba el
    parámetro como query string GET, aunque el punto de inyección real
    fuera un campo de un body POST/JSON (ej. 'email' en un login) --
    nunca se tocaba el código que de verdad procesa ese campo."""
    session = FakeSession(
        baseline_text="a" * 500,
        payload_response_text="b" * 50,
    )
    result = verify_payload(
        "http://example.com/rest/user", session, "email", "' OR 1=1--",
        method="POST", data=json.dumps({"email": "x@x.com", "password": "y"}),
    )

    assert session.calls == []  # nunca se usó GET/query string
    assert len(session.post_calls) == 2  # baseline + test, ambos POST
    assert session.post_calls[1]["json"]["email"] == "' OR 1=1--"
    assert session.post_calls[1]["json"]["password"] == "y"  # resto del body intacto
    assert result["confirmed"] is True


def test_post_form_urlencoded_data_mutates_form_field_not_sent_as_json():
    """Regresión real (UAEH): un <form> HTML manda
    application/x-www-form-urlencoded ('txtUsuario=x&txtContrasenya=y'),
    no JSON. Tratarlo como JSON (json.loads sobre ese string) fallaba
    silenciosamente y el payload nunca llegaba al campo real del
    login -- falso negativo total en un target con SQLi confirmada."""
    session = FakeSession(
        baseline_text="a" * 500,
        payload_response_text="b" * 50,
    )
    result = verify_payload(
        "http://example.com/sape/index.php", session, "txtUsuario",
        "' OR 1=1--",
        method="POST",
        data="txtUsuario=admin&txtContrasenya=admin&hdnRol=1",
    )

    assert session.calls == []  # nunca se usó GET/query string
    assert len(session.post_calls) == 2  # baseline + test, ambos POST
    assert session.post_calls[1]["json"] is None  # no se mandó como JSON
    assert session.post_calls[1]["data"]["txtUsuario"] == "' OR 1=1--"
    assert session.post_calls[1]["data"]["hdnRol"] == "1"  # resto del body intacto
    assert result["confirmed"] is True


def test_server_error_on_payload_is_not_confirmed_even_if_different():
    """Regresión real (Juice Shop contra un dyno gratuito de Heroku
    inestable): un 5xx en la respuesta del payload no distingue 'la
    query SQL se rompió' de 'el servidor se cayó por carga/flakiness'.
    Sin una firma de error de BD o un delay real, no debe confirmarse
    solo porque el status code o el body difieran del baseline."""
    session = FakeSession(
        baseline_text="<html>ok</html>", status_code=503,
        baseline_status_code=200,
    )
    result = verify_payload(
        "http://example.com/rest/user", session, "email", "' OR 1=1--",
    )

    assert result["confirmed"] is False
    assert result["signal"] == "unstable_target"


def test_waf_block_page_on_payload_is_not_confirmed_as_boolean_based():
    """Regresión real (BUAP, Imperva/Incapsula delante de Drupal): el
    payload volvía 403 (bloqueado por el WAF) mientras el baseline
    volvía 200 normal. responses_similar() correctamente decía
    'distintas' (el status code no coincide), y eso se confirmaba como
    boolean_based -- comparar una página de bloqueo del WAF contra una
    normal nunca es evidencia de comportamiento SQL, sin importar cuán
    distinto se vea el body."""
    session = FakeSession(
        baseline_text="<html>resultados de busqueda normales...</html>" * 50,
        status_code=403,
        baseline_status_code=200,
    )
    result = verify_payload(
        "http://example.com/search/node", session, "keys",
        "1' UNION ALL SELECT NULL,VERSION(),NULL,NULL-- -",
    )

    assert result["confirmed"] is False
    assert result["signal"] == "unstable_target"


def test_error_signature_already_in_baseline_is_not_confirmed():
    """Regresión real (sitio con extensión mysql_* deprecada): el body
    normal ya trae 'Deprecated: mysql_fetch()...' en TODA respuesta,
    con o sin payload. 5 payloads de técnicas distintas (error/time/
    boolean/union-probe) se confirmaban todos como "error_based" solo
    porque esa firma siempre estaba presente -- una firma de error solo
    cuenta como evidencia si es nueva respecto al baseline."""
    session = FakeSession(
        baseline_text="<b>Deprecated</b>: mysql_fetch() is deprecated",
        payload_response_text="<b>Deprecated</b>: mysql_fetch() is deprecated",
    )
    result = verify_payload(
        "http://example.com/page?id=1", session, "id",
        "1 AND EXTRACTVALUE(1,CONCAT(0x5c,DATABASE()))",
    )

    assert result["confirmed"] is False
    assert result["signal"] == "none"


def test_error_signature_new_in_payload_response_is_still_confirmed():
    """La firma sigue siendo evidencia válida si NO estaba en el
    baseline -- el fix no debe volverse ciego a errores reales."""
    session = FakeSession(
        baseline_text="<b>Deprecated</b>: mysql_fetch() is deprecated",
        payload_response_text=(
            "<b>Deprecated</b>: mysql_fetch() is deprecated"
            " You have an error in your SQL syntax near '1'"
        ),
    )
    result = verify_payload(
        "http://example.com/page?id=1", session, "id",
        "1' AND 1=CONVERT(int,'x')--",
    )

    assert result["confirmed"] is True
    assert result["signal"] == "error_based"


def test_broken_baseline_is_not_used_as_reference():
    """Si el baseline mismo ya viene con error de servidor, no hay
    contra qué comparar de forma confiable."""
    session = FakeSession(baseline_status_code=503, status_code=503)
    result = verify_payload(
        "http://example.com/rest/user", session, "email", "' OR 1=1--",
    )

    assert result["confirmed"] is False
    assert result["signal"] == "unstable_target"
