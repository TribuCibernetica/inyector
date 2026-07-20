"""Tests para payload_verifier — la confirmación con evidencia real.

El punto central: una sugerencia (de IA o de KnowledgeBase) solo cuenta
como "confirmada" si hay evidencia HTTP concreta (firma de error real,
delay de tiempo significativo, o cambio de comportamiento) — nunca
solo porque "suena razonable".
"""

from types import SimpleNamespace
from unittest.mock import patch

from inyector.intelligence.payload_verifier import verify_payload


class FakeSession:
    """Sesión HTTP falsa: devuelve respuestas pre-programadas según
    si la URL contiene el payload probado o no."""

    def __init__(self, baseline_text="normal", payload_response_text="normal",
                 status_code=200):
        self.baseline_text = baseline_text
        self.payload_response_text = payload_response_text
        self.status_code = status_code
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(url)
        # Primera llamada = baseline (verify_payload la pide primero
        # si no se le pasó una ya calculada); la segunda = la URL con
        # el payload de test.
        text = self.baseline_text if len(self.calls) == 1 else self.payload_response_text
        return SimpleNamespace(status_code=self.status_code, text=text)


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
