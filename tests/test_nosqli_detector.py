"""Tests para NoSQLiDetector — lógica pura (sin red).

Regresión del bug encontrado probando contra un lab real: mandar
'param[$ne]=x' SIN remover el 'param=valor_original' de la query
dejaba ambos presentes a la vez, produciendo una query ambigua que
Express/qs parseaba de forma impredecible y hacía fallar la
detección incluso contra un target genuinamente vulnerable.
"""

from types import SimpleNamespace

from inyector.recon.nosqli_detector import NoSQLiDetector


def _resp(status=200, text=""):
    return SimpleNamespace(status_code=status, text=text)


def test_replace_param_with_operator_removes_original_value():
    d = NoSQLiDetector()
    url = "http://example.com/login?username=admin&password=wrong"
    result = d._replace_param_with_operator(url, "password", "$ne", "x")

    assert "password=wrong" not in result
    assert "password[$ne]=x" in result
    assert "username=admin" in result


def test_replace_param_with_operator_appends_if_param_missing():
    d = NoSQLiDetector()
    url = "http://example.com/login?username=admin"
    result = d._replace_param_with_operator(url, "password", "$ne", "x")
    assert result == "http://example.com/login?username=admin&password[$ne]=x"


def test_responses_similar_by_status_and_length():
    d = NoSQLiDetector()
    a = _resp(200, "x" * 100)
    b = _resp(200, "x" * 101)
    c = _resp(401, "x" * 100)

    assert d._responses_similar(a, b) is True
    assert d._responses_similar(a, c) is False


def test_responses_similar_handles_none():
    d = NoSQLiDetector()
    assert d._responses_similar(None, _resp()) is False
    assert d._responses_similar(_resp(), None) is False


def test_where_busy_loop_payload_has_no_native_sleep():
    # $where no tiene sleep() nativo — el payload debe ser un busy-loop
    # real, no una llamada a una función que Mongo no provee.
    payload = NoSQLiDetector._where_busy_loop(3)
    assert "sleep(" not in payload.lower()
    assert "do {" in payload or "do{" in payload
