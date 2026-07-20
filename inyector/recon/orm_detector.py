"""Módulo de detección de ORM (Object-Relational Mapping).

Identifica qué ORM utiliza la aplicación objetivo analizando
mensajes de error provocados por payloads de sintaxis SQL inválida.
"""

import requests
from typing import Optional
from inyector.utils.logger import get_logger
from inyector.utils.url_probe import build_probe_url
from inyector.utils.signatures import load_signatures

logger = get_logger(__name__)


class ORMDetector:
    """Detecta el ORM utilizado por la aplicación web objetivo.

    Las firmas de error y escape hatches por ORM viven en
    inyector/data/orm_signatures.json.
    """

    ORM_SIGNATURES = load_signatures("orm_signatures.json")

    def detect(self, url: str, session: requests.Session,
               param: Optional[str] = None) -> dict:
        """Detecta el ORM utilizado por la aplicación.

        Envía un payload que genera un error de sintaxis SQL y analiza
        el mensaje de error para identificar el ORM.

        Args:
            url: URL objetivo.
            session: Sesión HTTP configurada.
            param: Parámetro específico a testear (opcional).

        Returns:
            Diccionario con orm, escape_hatches, raw_queries_likely y confidence.
        """
        logger.info("Iniciando detección de ORM...")

        resultado = {
            "orm": "none",
            "escape_hatches": [],
            "raw_queries_likely": False,
            "confidence": 0.0,
            "evidence": [],
            "error": None,
        }

        # Payloads diseñados para provocar errores del ORM
        payloads = [
            "'",           # Comilla simple — error de sintaxis SQL
            "1'",          # Número seguido de comilla
            "1 OR 1=1",    # Inyección clásica
            "' OR '1'='1", # Inyección con strings
            "1; --",       # Stacked query
        ]

        failed_payloads = 0

        for payload in payloads:
            try:
                test_url = build_probe_url(
                    url, param, payload, fallback_name="orm_test",
                )

                response = session.get(test_url, timeout=30)
                body = response.text

                # Buscar firmas de ORM en la respuesta
                for orm_name, orm_data in self.ORM_SIGNATURES.items():
                    signatures = orm_data.get("errors", [])
                    for sig in signatures:
                        if sig.lower() in body.lower():
                            confidence = 0.7
                            match_count = sum(
                                1 for s in signatures
                                if s.lower() in body.lower()
                            )
                            if match_count >= 2:
                                confidence = 0.85
                            if match_count >= 3:
                                confidence = 0.95

                            if confidence > resultado["confidence"]:
                                resultado["orm"] = orm_name
                                resultado["confidence"] = confidence
                                resultado["escape_hatches"] = (
                                    orm_data.get("escape_hatches", [])
                                )
                                resultado["raw_queries_likely"] = len(
                                    resultado["escape_hatches"]
                                ) > 0
                                resultado["evidence"].append(
                                    f"Firma '{sig}' detectada con payload '{payload}'"
                                )

                            if resultado["confidence"] >= 0.85:
                                break
                    if resultado["confidence"] >= 0.85:
                        break

                if resultado["confidence"] >= 0.85:
                    break

            except requests.exceptions.Timeout:
                logger.debug(f"Timeout con payload: {payload}")
                failed_payloads += 1
            except requests.exceptions.ConnectionError:
                logger.debug(f"Error de conexión con payload: {payload}")
                failed_payloads += 1
            except Exception as e:
                logger.debug(f"Error con payload '{payload}': {e}")
                failed_payloads += 1

        # Si NINGÚN payload pudo enviarse, "orm: none" sería engañoso
        # (no es que no haya ORM, es que no pudimos ni preguntar).
        if failed_payloads == len(payloads):
            resultado["error"] = "connection_error"
            logger.warning(
                "No se pudo verificar ORM — todos los intentos fallaron"
            )

        if resultado["orm"] != "none":
            logger.info(
                f"ORM detectado: {resultado['orm']} "
                f"(confianza: {resultado['confidence']:.0%})"
            )
        else:
            logger.info("No se detectó ORM específico")

        return resultado
