"""Tests para AIAssistant — sin llamadas reales a la API de Gemini.

Cubre: que falta sin API key es un error claro (no un crash raro más
adelante), y que si la API falla por cualquier motivo, el resto del
pipeline sigue funcionando (lista vacía, no una excepción que tumbe
el scan completo — esto es una sugerencia best-effort).
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from inyector.intelligence.ai_assistant import AIAssistant


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

    fake_payload = {
        "suggestions": [
            {
                "payload": "1' AND updatexml(1,concat(0x7e,version()),1)-- -",
                "technique": "E",
                "injection_point": "param",
                "reasoning": "Error-based especifico de MySQL via updatexml",
            }
        ]
    }

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.interactions.create.return_value = MagicMock(
            output_text=json.dumps(fake_payload)
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


def test_api_failure_returns_empty_list_not_exception(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.interactions.create.side_effect = RuntimeError("API caida")

        assistant = AIAssistant()
        result = assistant.suggest_advanced_payloads(
            stack={}, orm={}, waf={}, param_name="id", sample_response="",
        )

    assert result == []  # nunca lanza, el scan sigue su curso


def test_sqlmap_recovery_failure_returns_safe_default(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")

    with patch("google.genai.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.interactions.create.side_effect = RuntimeError("timeout")

        assistant = AIAssistant()
        result = assistant.suggest_sqlmap_recovery(
            "target url content is not stable", "output...", {},
        )

    assert result == {"suggested_flags": [], "reasoning": ""}
