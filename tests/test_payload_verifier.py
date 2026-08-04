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
    si la URL contiene el payload probado o no.

    Orden de llamadas que hace verify_payload cuando no se le pasa un
    baseline ya calculado: 1) baseline (valor original), 2) payload de
    test, 3) valor de control/ruido -- solo si (2) resultó "distinto"
    al baseline. Por defecto el control se ve como el baseline (mismo
    texto) para que los tests existentes, que no ejercitan el control
    de ruido, sigan confirmando boolean-based como antes."""

    def __init__(self, baseline_text="normal", payload_response_text="normal",
                 status_code=200, baseline_status_code=None,
                 noise_response_text=None, noise_status_code=None):
        self.baseline_text = baseline_text
        self.payload_response_text = payload_response_text
        self.status_code = status_code
        self.baseline_status_code = (
            baseline_status_code if baseline_status_code is not None else status_code
        )
        self.noise_response_text = (
            noise_response_text if noise_response_text is not None else baseline_text
        )
        self.noise_status_code = (
            noise_status_code if noise_status_code is not None
            else self.baseline_status_code
        )
        self.calls = []
        self.post_calls = []

    def _response_for(self, index):
        if index == 1:
            return self.baseline_status_code, self.baseline_text
        if index == 2:
            return self.status_code, self.payload_response_text
        return self.noise_status_code, self.noise_response_text

    def get(self, url, timeout=None):
        self.calls.append(url)
        status, text = self._response_for(len(self.calls))
        return SimpleNamespace(status_code=status, text=text)

    def post(self, url, json=None, data=None, timeout=None):
        self.post_calls.append({"url": url, "json": json, "data": data})
        status, text = self._response_for(len(self.post_calls))
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
    # baseline + payload + control de ruido, los 3 POST
    assert len(session.post_calls) == 3
    assert session.post_calls[0]["json"]["email"] == "x@x.com"  # baseline = valor real
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
    # baseline + payload + control de ruido, los 3 POST
    assert len(session.post_calls) == 3
    assert session.post_calls[0]["data"]["txtUsuario"] == "admin"  # baseline = valor real
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


def test_baseline_uses_real_original_value_not_synthetic_probe():
    """El baseline debe representar una request legítima -- mandar un
    valor sintético ('baseline_probe') como email/id de prueba puede
    disparar el mismo camino de "input inválido" que un payload SQL en
    un endpoint con validación de formato, haciendo el baseline tan
    poco representativo como lo que se está probando."""
    session = FakeSession(baseline_text="ok", payload_response_text="ok")
    verify_payload(
        "http://example.com/page?id=1&other=x", session, "id", "1' OR '1'='1",
    )
    assert "id=1" in session.calls[0]
    assert "baseline_probe" not in session.calls[0]


def test_boolean_based_not_confirmed_when_noise_control_also_differs():
    """Regresión real (www.uag.mx, endpoint de validación de email):
    payloads de técnica error/union-probe que nunca dispararon una
    firma de error de BD real se confirmaban como "boolean_based" solo
    porque CUALQUIER valor con forma distinta al original (sea o no
    SQL) hace que el validador de email responda distinto. Si un
    control sin semántica SQL reproduce la misma diferencia que el
    payload, no hay evidencia de que la condición SQL en sí haya hecho
    algo -- no debe confirmarse."""
    session = FakeSession(
        baseline_text="<html>email valido, procesando...</html>" * 10,
        payload_response_text="<html>formato de email invalido</html>",
        noise_response_text="<html>formato de email invalido</html>",
    )
    result = verify_payload(
        "http://example.com/api/emailValidacion.php?email=test@test.com",
        session, "email", "1 ORDER BY 9999 -- -",
    )

    assert result["confirmed"] is False
    assert result["signal"] == "inconclusive"


def test_broken_baseline_is_not_used_as_reference():
    """Si el baseline mismo ya viene con error de servidor, no hay
    contra qué comparar de forma confiable."""
    session = FakeSession(baseline_status_code=503, status_code=503)
    result = verify_payload(
        "http://example.com/rest/user", session, "email", "' OR 1=1--",
    )

    assert result["confirmed"] is False
    assert result["signal"] == "unstable_target"
