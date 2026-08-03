"""Tests para AIAssistant — sin llamadas reales a la API de Gemini.

Cubre: que falta sin API key es un error claro (no un crash raro más
adelante), y que si la API falla por cualquier motivo -- incluyendo
que devuelva algo que no valida contra el schema pedido, algo que
pasó de verdad en producción con el endpoint experimental viejo -- el
resto del pipeline sigue funcionando (lista vacía, no una excepción
que tumbe el scan completo, esto es una sugerencia best-effort).

Usa la API estable client.models.generate_content() con
response_schema (no el endpoint "interactions", todavía experimental
en el SDK y que en producción llegó a envolver el JSON en un code
fence de markdown y, otra vez, a usar una clave top-level distinta a
la pedida por el schema -- generate_content()+response_schema es la
vía oficialmente soportada por Google para JSON garantizado).
"""

from unittest.mock import MagicMock, patch

import pytest

from inyector.intelligence.ai_assistant import (
    AICallBudget,
    AIAssistant,
    PayloadSuggestion,
    PayloadSuggestions,
    SqlmapRecovery,
)


def test_missing_api_key_raises_clear_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        AIAssistant()


def test_explicit_api_key_is_used_over_env(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with patch("google.genai.Client") as mock_client_cls:
        AIAssistant(api_key="explicit-key-123")
        mock_client_cls.assert_called_once_with(api_key="explicit-key-123")


def test_suggest_advanced_payloads_parses_structured_response(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    parsed = PayloadSuggestions(
        suggestions=[
            PayloadSuggestion(
                payload="1' AND updatexml(1,concat(0x7e,version()),1)-- -",
                technique="E",
                injection_point="param",
                reasoning="Error-based especifico de MySQL via updatexml",
            )
        ]
    )

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.return_value = MagicMock(
            parsed=parsed, text=parsed.model_dump_json(),
        )

        assistant = AIAssistant()
        result = assistant.suggest_advanced_payloads(
            stack={"framework": "PHP nativo", "language": "php"},
            orm={"orm": "none"},
            waf={"waf": "none"},
            param_name="id",
            sample_response="<html>...</html>",
        )

    assert len(result) == 1
    assert result[0]["technique"] == "E"
    assert "updatexml" in result[0]["payload"]


def test_suggest_advanced_payloads_handles_unparseable_response(monkeypatch):
    """Regresión real: el endpoint experimental viejo (interactions.create)
    llegó a devolver 200 OK con JSON que no validaba contra el schema
    pedido (una vez envuelto en markdown, otra vez con una clave
    top-level distinta a 'suggestions'). generate_content() con
    response_schema evita eso, pero igual nos defendemos: si por lo
    que sea `parsed` viene None, se trata como fallo -- lista vacía,
    no una excepción que tumbe el scan."""
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.return_value = MagicMock(
            parsed=None, text='{"sql_injection_payloads": []}',
        )

        assistant = AIAssistant()
        result = assistant.suggest_advanced_payloads(
            stack={}, orm={}, waf={}, param_name="id", sample_response="",
        )

    assert result == []


def test_api_failure_returns_empty_list_not_exception(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.side_effect = RuntimeError("API caida")

        assistant = AIAssistant()
        result = assistant.suggest_advanced_payloads(
            stack={}, orm={}, waf={}, param_name="id", sample_response="",
        )

    assert result == []  # nunca lanza, el scan sigue su curso


def test_sqlmap_recovery_parses_structured_response(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    parsed = SqlmapRecovery(
        suggested_flags=["--string=OK"],
        reasoning="La respuesta varía por un timestamp dinámico",
    )

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.return_value = MagicMock(
            parsed=parsed, text=parsed.model_dump_json(),
        )

        assistant = AIAssistant()
        result = assistant.suggest_sqlmap_recovery(
            "target url content is not stable", "output...", {},
        )

    assert result["suggested_flags"] == ["--string=OK"]


def test_sqlmap_recovery_failure_returns_safe_default(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.models.generate_content.side_effect = RuntimeError("timeout")

        assistant = AIAssistant()
        result = assistant.suggest_sqlmap_recovery(
            "target url content is not stable", "output...", {},
        )

    assert result == {"suggested_flags": [], "reasoning": ""}


def test_ai_call_budget_unlimited_by_default():
    budget = AICallBudget()
    assert not budget.exhausted
    for _ in range(50):
        budget.consume()
    assert not budget.exhausted  # max_calls=None nunca se agota


def test_ai_call_budget_exhausts_at_limit():
    budget = AICallBudget(max_calls=2)
    assert not budget.exhausted
    budget.consume()
    assert not budget.exhausted
    budget.consume()
    assert budget.exhausted


def test_suggest_advanced_payloads_skips_api_call_when_budget_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    budget = AICallBudget(max_calls=1)
    budget.consume()  # ya gastado por otro target en el mismo --crawl-all

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        assistant = AIAssistant(budget=budget)
        result = assistant.suggest_advanced_payloads(
            stack={}, orm={}, waf={}, param_name="id", sample_response="",
        )

        mock_client.models.generate_content.assert_not_called()

    assert result == []


def test_suggest_sqlmap_recovery_skips_api_call_when_budget_exhausted(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    budget = AICallBudget(max_calls=0)

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        assistant = AIAssistant(budget=budget)
        result = assistant.suggest_sqlmap_recovery("motivo", "output", {})

        mock_client.models.generate_content.assert_not_called()

    assert result == {"suggested_flags": [], "reasoning": ""}


def test_budget_is_shared_across_multiple_assistant_instances(monkeypatch):
    # El caso real: --crawl-all crea un AIAssistant nuevo por target,
    # pero todos comparten la MISMA instancia de AICallBudget.
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    budget = AICallBudget(max_calls=1)

    with patch("google.genai.Client"):
        first = AIAssistant(budget=budget)
        first._budget.consume()

        second = AIAssistant(budget=budget)
        assert second._budget.exhausted
