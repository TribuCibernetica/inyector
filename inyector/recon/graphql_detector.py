"""Módulo de detección de endpoints GraphQL.

Descubre endpoints GraphQL, verifica si la introspección está habilitada
y encuentra argumentos potencialmente inyectables.
"""

import json
import requests
from urllib.parse import urlparse
from typing import Optional
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class GraphQLDetector:
    """Detecta endpoints GraphQL y analiza su superficie de ataque."""

    COMMON_GRAPHQL_ENDPOINTS = [
        "/graphql", "/api/graphql", "/v1/graphql",
        "/query", "/gql", "/graphql/v1",
        "/api/v1/graphql", "/graphiql",
        "/playground", "/api/query",
    ]

    # Query de introspección completa
    INTROSPECTION_QUERY = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            args {
              name
              type {
                name
                kind
                ofType {
                  name
                  kind
                }
              }
            }
          }
        }
      }
    }
    """

    def detect_endpoints(self, base_url: str,
                         session: requests.Session) -> list[str]:
        """Prueba endpoints comunes de GraphQL.

        Args:
            base_url: URL base del sitio.
            session: Sesión HTTP configurada.

        Returns:
            Lista de endpoints GraphQL válidos encontrados.
        """
        logger.info("Buscando endpoints GraphQL...")
        found_endpoints = []

        # Limpiar URL base
        base = base_url.rstrip("/")
        if "://" not in base:
            base = f"https://{base}"

        parsed = urlparse(base)
        base_clean = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in self.COMMON_GRAPHQL_ENDPOINTS:
            full_url = f"{base_clean}{endpoint}"
            try:
                # Query mínima para verificar si es GraphQL
                test_payload = {"query": "{ __typename }"}
                response = session.post(
                    full_url, json=test_payload, timeout=15,
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "data" in data:
                            found_endpoints.append(full_url)
                            logger.info(f"Endpoint GraphQL encontrado: {endpoint}")
                    except json.JSONDecodeError:
                        pass

                elif response.status_code in [400, 405]:
                    response_get = session.get(
                        f"{full_url}?query={{__typename}}", timeout=15,
                    )
                    if response_get.status_code == 200:
                        try:
                            data = response_get.json()
                            if "data" in data:
                                found_endpoints.append(full_url)
                                logger.info(
                                    f"Endpoint GraphQL (GET) encontrado: {endpoint}"
                                )
                        except json.JSONDecodeError:
                            pass

            except requests.exceptions.Timeout:
                logger.debug(f"Timeout en {endpoint}")
            except requests.exceptions.ConnectionError:
                logger.debug(f"Error de conexión en {endpoint}")
            except Exception as e:
                logger.debug(f"Error en {endpoint}: {e}")

        if not found_endpoints:
            logger.info("No se encontraron endpoints GraphQL")

        return found_endpoints

    def fingerprint_engine(self, endpoint: str,
                           session: requests.Session) -> dict:
        """Identifica el motor GraphQL detrás del endpoint.

        Envía queries deliberadamente inválidas y compara la forma
        exacta del error devuelto — cada motor (Apollo, Hasura, AWS
        AppSync, etc.) tiene un formato de error distinto y bien
        documentado. Enfoque inspirado en graphw00f, pero limitado a
        las firmas que se pueden verificar con confianza (evitamos
        adivinar formatos de motores menos documentados).

        Args:
            endpoint: URL del endpoint GraphQL.
            session: Sesión HTTP configurada.

        Returns:
            Diccionario con engine, confidence y evidence.
        """
        resultado = {"engine": "unknown", "confidence": 0.0, "evidence": []}

        try:
            # Query con un campo que no existe en ningún schema real —
            # fuerza un error de validación en cualquier motor.
            response = session.post(
                endpoint,
                json={"query": "{ __inyectorNonExistentField__ }"},
                timeout=15,
            )
            body = response.text
            body_lower = body.lower()
            headers_lower = {
                k.lower(): v for k, v in response.headers.items()
            }

            # Hasura: siempre agrega este header, incluso en errores,
            # y su extensión de error trae "code": "validation-failed".
            if "x-hasura-request-id" in headers_lower:
                resultado.update({
                    "engine": "hasura", "confidence": 0.95,
                    "evidence": ["Header 'x-hasura-request-id' presente"],
                })
                return resultado
            if "validation-failed" in body_lower and "hasura" in body_lower:
                resultado.update({
                    "engine": "hasura", "confidence": 0.8,
                    "evidence": ["Código de error 'validation-failed' (Hasura)"],
                })
                return resultado

            # Apollo Server: código de extensión documentado oficialmente.
            if "graphql_validation_failed" in body_lower:
                resultado.update({
                    "engine": "apollo_server", "confidence": 0.85,
                    "evidence": [
                        "Extensión de error 'GRAPHQL_VALIDATION_FAILED' (Apollo)"
                    ],
                })
                return resultado

            # AWS AppSync: formato de error propio con "errorType",
            # ausente en implementaciones basadas en graphql-js.
            if '"errortype"' in body_lower:
                resultado.update({
                    "engine": "aws_appsync", "confidence": 0.8,
                    "evidence": ["Campo 'errorType' en respuesta (AWS AppSync)"],
                })
                return resultado

            # Sin firma reconocida, pero sí es GraphQL válido
            if "errors" in body_lower or "data" in body_lower:
                resultado.update({
                    "engine": "generic_graphql_js", "confidence": 0.3,
                    "evidence": [
                        "Responde como GraphQL pero sin firma de motor conocida"
                    ],
                })

        except requests.exceptions.Timeout:
            logger.debug("Timeout al fingerprintear motor GraphQL")
        except Exception as e:
            logger.debug(f"Error al fingerprintear motor GraphQL: {e}")

        return resultado

    def check_introspection(self, endpoint: str,
                            session: requests.Session) -> dict:
        """Verifica si la introspección está habilitada.

        Args:
            endpoint: URL del endpoint GraphQL.
            session: Sesión HTTP configurada.

        Returns:
            Diccionario con enabled, queries, mutations y types.
        """
        logger.info(f"Verificando introspección en {endpoint}...")

        resultado = {
            "enabled": False,
            "queries": [],
            "mutations": [],
            "types": [],
            "raw_schema": None,
        }

        try:
            response = session.post(
                endpoint,
                json={"query": self.INTROSPECTION_QUERY},
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    resultado["enabled"] = True
                    schema = data["data"]["__schema"]
                    resultado["raw_schema"] = schema

                    for type_info in schema.get("types", []):
                        if type_info["name"].startswith("__"):
                            continue

                        type_data = {
                            "name": type_info["name"],
                            "kind": type_info["kind"],
                            "fields": [],
                        }

                        for field in type_info.get("fields", []) or []:
                            field_data = {"name": field["name"], "args": []}
                            for arg in field.get("args", []) or []:
                                arg_type = arg.get("type", {})
                                type_name = (
                                    arg_type.get("name")
                                    or (arg_type.get("ofType", {}) or {}).get("name")
                                    or "Unknown"
                                )
                                field_data["args"].append({
                                    "name": arg["name"],
                                    "type": type_name,
                                    "kind": arg_type.get("kind", "UNKNOWN"),
                                })
                            type_data["fields"].append(field_data)

                        resultado["types"].append(type_data)

                    query_type_name = (
                        schema.get("queryType", {}) or {}
                    ).get("name", "Query")
                    mutation_type_name = (
                        schema.get("mutationType", {}) or {}
                    ).get("name", "Mutation")

                    for t in resultado["types"]:
                        if t["name"] == query_type_name:
                            resultado["queries"] = t["fields"]
                        elif t["name"] == mutation_type_name:
                            resultado["mutations"] = t["fields"]

                    logger.info("Introspección habilitada — schema extraído")
                else:
                    logger.info("Introspección deshabilitada")

        except Exception as e:
            logger.error(f"Error al verificar introspección: {e}")

        return resultado

    def find_injectable_args(self, schema: dict) -> list[dict]:
        """Analiza el schema para encontrar argumentos inyectables.

        Args:
            schema: Schema de introspección parseado.

        Returns:
            Lista de diccionarios con query_name, arg_name y arg_type.
        """
        injectable = []
        injectable_types = ["String", "Int", "ID", "Float"]

        for field in schema.get("queries", []):
            for arg in field.get("args", []):
                if arg.get("type") in injectable_types:
                    injectable.append({
                        "query_name": field["name"],
                        "arg_name": arg["name"],
                        "arg_type": arg["type"],
                        "operation": "query",
                    })

        for field in schema.get("mutations", []):
            for arg in field.get("args", []):
                if arg.get("type") in injectable_types:
                    injectable.append({
                        "query_name": field["name"],
                        "arg_name": arg["name"],
                        "arg_type": arg["type"],
                        "operation": "mutation",
                    })

        if injectable:
            logger.info(
                f"Encontrados {len(injectable)} argumentos potencialmente inyectables"
            )
        else:
            logger.info("No se encontraron argumentos inyectables en el schema")

        return injectable
