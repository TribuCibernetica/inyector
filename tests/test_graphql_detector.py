"""Tests para GraphQLDetector.

Cubre descubrimiento de endpoints (POST y fallback GET), fingerprint
de motor por firma de error, e introspección (habilitada/deshabilitada
y extracción de queries/mutations), además de la selección de
argumentos inyectables por tipo escalar.
"""

from unittest.mock import MagicMock

from inyector.recon.graphql_detector import GraphQLDetector


def _response(status_code=200, json_data=None, text="", headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text if text else (str(json_data) if json_data else "")
    resp.headers = headers or {}
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        import json as _json
        resp.json.side_effect = _json.JSONDecodeError("no json", "", 0)
    return resp


def test_detect_endpoints_finds_post_endpoint():
    detector = GraphQLDetector()
    session = MagicMock()

    def get_post_response(url, **kwargs):
        if url.endswith("/graphql"):
            return _response(json_data={"data": {"__typename": "Query"}})
        return _response(status_code=404)

    session.post.side_effect = get_post_response

    found = detector.detect_endpoints("https://x.com", session)

    assert "https://x.com/graphql" in found


def test_detect_endpoints_falls_back_to_get_on_405():
    detector = GraphQLDetector()
    session = MagicMock()

    def post_side_effect(url, **kwargs):
        if url.endswith("/query"):
            return _response(status_code=405)
        return _response(status_code=404)

    def get_side_effect(url, **kwargs):
        if "/query" in url:
            return _response(json_data={"data": {"__typename": "Query"}})
        return _response(status_code=404)

    session.post.side_effect = post_side_effect
    session.get.side_effect = get_side_effect

    found = detector.detect_endpoints("https://x.com", session)

    assert "https://x.com/query" in found


def test_detect_endpoints_returns_empty_when_nothing_found():
    detector = GraphQLDetector()
    session = MagicMock()
    session.post.return_value = _response(status_code=404)

    found = detector.detect_endpoints("https://x.com", session)

    assert found == []


def test_fingerprint_engine_detects_hasura_by_header():
    detector = GraphQLDetector()
    session = MagicMock()
    session.post.return_value = _response(
        headers={"x-hasura-request-id": "abc123"}, text="error",
    )

    resultado = detector.fingerprint_engine("https://x.com/graphql", session)

    assert resultado["engine"] == "hasura"
    assert resultado["confidence"] >= 0.9


def test_fingerprint_engine_detects_apollo_by_extension_code():
    detector = GraphQLDetector()
    session = MagicMock()
    session.post.return_value = _response(
        text='{"errors":[{"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}',
    )

    resultado = detector.fingerprint_engine("https://x.com/graphql", session)

    assert resultado["engine"] == "apollo_server"


def test_fingerprint_engine_unknown_without_signature():
    detector = GraphQLDetector()
    session = MagicMock()
    session.post.return_value = _response(text="respuesta rara sin firma")

    resultado = detector.fingerprint_engine("https://x.com/graphql", session)

    assert resultado["engine"] == "unknown"
    assert resultado["confidence"] == 0.0


def test_check_introspection_enabled_extracts_queries_and_mutations():
    detector = GraphQLDetector()
    session = MagicMock()
    schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "Query", "kind": "OBJECT",
                "fields": [
                    {"name": "user", "args": [
                        {"name": "id", "type": {"name": "ID", "kind": "SCALAR"}},
                    ]},
                ],
            },
            {
                "name": "Mutation", "kind": "OBJECT",
                "fields": [
                    {"name": "deleteUser", "args": [
                        {"name": "id", "type": {"name": "ID", "kind": "SCALAR"}},
                    ]},
                ],
            },
        ],
    }
    session.post.return_value = _response(json_data={"data": {"__schema": schema}})

    resultado = detector.check_introspection("https://x.com/graphql", session)

    assert resultado["enabled"] is True
    assert any(f["name"] == "user" for f in resultado["queries"])
    assert any(f["name"] == "deleteUser" for f in resultado["mutations"])


def test_check_introspection_disabled_when_no_schema_in_response():
    detector = GraphQLDetector()
    session = MagicMock()
    session.post.return_value = _response(json_data={"errors": [{"message": "introspection disabled"}]})

    resultado = detector.check_introspection("https://x.com/graphql", session)

    assert resultado["enabled"] is False


def test_find_injectable_args_only_returns_scalar_types():
    detector = GraphQLDetector()
    schema = {
        "queries": [{
            "name": "search",
            "args": [
                {"name": "term", "type": "String"},
                {"name": "filter", "type": "FilterInput"},
            ],
        }],
        "mutations": [],
    }

    injectable = detector.find_injectable_args(schema)

    assert len(injectable) == 1
    assert injectable[0]["arg_name"] == "term"
    assert injectable[0]["operation"] == "query"
