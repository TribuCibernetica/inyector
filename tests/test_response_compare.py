"""Tests para responses_similar — la comparación tolerante de
respuestas HTTP que decide si dos respuestas se consideran "iguales"
para boolean-blind. Cubre el umbral (max(5, 2% de la longitud mayor))
y los casos límite: respuestas ausentes (None) y bodies vacíos.
"""

from types import SimpleNamespace

from inyector.utils.response_compare import responses_similar


def _resp(status_code=200, text=""):
    return SimpleNamespace(status_code=status_code, text=text)


def test_identical_responses_are_similar():
    a = _resp(200, "hola mundo")
    b = _resp(200, "hola mundo")
    assert responses_similar(a, b) is True


def test_none_response_is_never_similar():
    a = _resp(200, "hola")
    assert responses_similar(None, a) is False
    assert responses_similar(a, None) is False
    assert responses_similar(None, None) is False


def test_different_status_codes_are_not_similar_even_with_same_body():
    a = _resp(200, "misma pagina")
    b = _resp(500, "misma pagina")
    assert responses_similar(a, b) is False


def test_both_empty_bodies_are_similar():
    a = _resp(200, "")
    b = _resp(200, "")
    assert responses_similar(a, b) is True


def test_small_absolute_difference_within_min_threshold_is_similar():
    # Bodies cortos: el umbral mínimo es 5 caracteres de diferencia.
    a = _resp(200, "x" * 10)
    b = _resp(200, "x" * 14)  # diff = 4 <= 5
    assert responses_similar(a, b) is True


def test_absolute_difference_just_over_min_threshold_is_not_similar():
    a = _resp(200, "x" * 10)
    b = _resp(200, "x" * 16)  # diff = 6 > 5
    assert responses_similar(a, b) is False


def test_percentage_threshold_applies_to_long_bodies():
    # len_a=1000, umbral = max(5, 0.02*1000) = 20.
    a = _resp(200, "x" * 1000)
    b = _resp(200, "x" * 1020)  # diff = 20, justo en el límite (<=)
    assert responses_similar(a, b) is True


def test_percentage_threshold_exceeded_on_long_bodies_is_not_similar():
    a = _resp(200, "x" * 1000)
    b = _resp(200, "x" * 1021)  # diff = 21 > 20
    assert responses_similar(a, b) is False
