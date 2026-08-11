"""Módulo de detección de Web Application Firewalls (WAF).

Analiza headers HTTP, cookies y comportamiento de respuestas
para identificar el WAF que protege al objetivo.
"""

import requests
import time
from typing import Any, Optional
from urllib.parse import urlparse
from inyector.utils.logger import get_logger
from inyector.utils.signatures import load_signatures

logger = get_logger(__name__)


class WAFDetector:
    """Detecta y fingerprinta el WAF que protege una aplicación web.

    Las firmas (headers/cookies/body) viven en
    inyector/data/waf_signatures.json — cubren ~28 vendors basados en
    los mismos indicadores públicos que usa wafw00f.
    """

    WAF_SIGNATURES = load_signatures("waf_signatures.json")


    def detect(self, url: str, session: requests.Session) -> dict:
        """Detecta el WAF que protege la URL objetivo.

        Args:
            url: URL objetivo a analizar.
            session: Sesión HTTP configurada.

        Returns:
            Diccionario con waf, confidence y evidence.
        """
        logger.info("Iniciando detección de WAF...")

        resultado: dict[str, Any] = {
            "waf": "none",
            "confidence": 0.0,
            "evidence": [],
            # None = se pudo verificar. Si no, dice POR QUÉ no se pudo
            # verificar, para no confundir "sin WAF" con "no logramos
            # comprobarlo" (que son estados muy distintos en un reporte
            # de seguridad).
            "error": None,
        }

        try:
            # Hacer request inicial
            response = session.get(url, timeout=30, allow_redirects=True)

            # Fase 1: Analizar headers y cookies
            waf, confidence, evidence = self._check_headers(response)
            if confidence > resultado["confidence"]:
                resultado["waf"] = waf
                resultado["confidence"] = confidence
                resultado["evidence"] = evidence

            # Fase 2: Probing activo con payloads de prueba
            if resultado["confidence"] < 0.7:
                probe_waf, probe_confidence = self._probe_waf_behavior(url, session)
                if probe_confidence > resultado["confidence"]:
                    resultado["waf"] = probe_waf
                    resultado["confidence"] = probe_confidence
                    resultado["evidence"].append(
                        "Detección por comportamiento ante payload malicioso"
                    )

        except requests.exceptions.Timeout:
            logger.warning("Timeout al intentar detectar WAF")
            resultado["error"] = "timeout"
            resultado["evidence"].append("Timeout durante detección — posible WAF agresivo")
        except requests.exceptions.ConnectionError:
            logger.warning("Error de conexión al intentar detectar WAF")
            resultado["error"] = "connection_error"
            resultado["evidence"].append("Error de conexión — posible bloqueo de IP")
        except Exception as e:
            logger.error(f"Error inesperado en detección de WAF: {e}")
            resultado["error"] = str(e)

        logger.info(
            f"WAF detectado: {resultado['waf']} "
            f"(confianza: {resultado['confidence']:.0%})"
        )
        return resultado

    def _check_headers(self, response: requests.Response) -> tuple[str, float, list]:
        """Analiza headers HTTP y cookies para fingerprinting de WAF.

        Args:
            response: Respuesta HTTP a analizar.

        Returns:
            Tupla con (nombre_waf, confianza, lista_evidencias).
        """
        best_match: tuple[str, float, list[str]] = ("none", 0.0, [])

        for waf_name, signatures in self.WAF_SIGNATURES.items():
            confidence = 0.0
            evidence = []
            matches = 0
            total_checks = 0

            # Verificar headers
            for header_name, expected_value in signatures.get("headers", {}).items():
                total_checks += 1
                header_val = response.headers.get(header_name, "")

                if expected_value is None and header_name in response.headers:
                    # Solo verificar presencia del header
                    matches += 1
                    evidence.append(f"Header '{header_name}' presente: {header_val}")
                elif isinstance(expected_value, list):
                    for ev in expected_value:
                        if ev.lower() in header_val.lower():
                            matches += 1
                            evidence.append(f"Header '{header_name}' contiene '{ev}'")
                            break
                elif isinstance(expected_value, str):
                    if expected_value.lower() in header_val.lower():
                        matches += 1
                        evidence.append(f"Header '{header_name}' = '{expected_value}'")

            # Verificar cookies
            for cookie_name in signatures.get("cookies", []):
                total_checks += 1
                cookies_dict = {c.name: c.value for c in response.cookies}
                cookie_header = response.headers.get("Set-Cookie", "")
                if cookie_name in cookies_dict or cookie_name in cookie_header:
                    matches += 1
                    evidence.append(f"Cookie '{cookie_name}' detectada")

            # Verificar firmas en el body
            for body_sig in signatures.get("body_signatures", []):
                total_checks += 1
                if body_sig.lower() in response.text.lower():
                    matches += 1
                    evidence.append(f"Firma en body: '{body_sig}'")

            # Calcular confianza
            if total_checks > 0 and matches > 0:
                confidence = min(1.0, matches / total_checks)
                if matches >= 2:
                    confidence = min(1.0, confidence + 0.15)
                if matches >= 3:
                    confidence = min(1.0, confidence + 0.10)

            if confidence > best_match[1]:
                best_match = (waf_name, confidence, evidence)

        return best_match

    def _probe_waf_behavior(self, url: str,
                            session: requests.Session) -> tuple[str, float]:
        """Envía payloads de prueba y analiza comportamiento del WAF.

        Args:
            url: URL objetivo.
            session: Sesión HTTP configurada.

        Returns:
            Tupla con (nombre_waf, confianza).
        """
        separator = "&" if "?" in url else "?"

        # Sondeo de sinkhole-redirect: algunos WAFs institucionales
        # (sin firma de vendor conocida -- confirmado manualmente
        # contra itescam.edu.mx) no devuelven 403 ante una keyword SQL
        # bloqueada, sino un 3xx hacia un dominio completamente ajeno
        # al target. Los status codes de abajo (403/406/...) no lo
        # detectan porque una redirección es 3xx, no un bloqueo
        # directo -- por eso es un chequeo aparte, sin seguir el
        # redirect (allow_redirects=False) para no depender de que ese
        # dominio ajeno resuelva.
        sinkhole_test_url = f"{url}{separator}waf_test_sqli=1 AND 1=1"
        try:
            redirect_resp = session.get(
                sinkhole_test_url, timeout=30, allow_redirects=False,
            )
            location = redirect_resp.headers.get("Location", "")
            if redirect_resp.status_code in (301, 302, 303, 307, 308) and location:
                redirect_host = urlparse(location).netloc
                target_host = urlparse(url).netloc
                if redirect_host and redirect_host != target_host:
                    return ("keyword_sinkhole", 0.8)
        except requests.exceptions.RequestException:
            pass

        test_url = f"{url}{separator}waf_test=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

        try:
            response = session.get(test_url, timeout=30, allow_redirects=True)

            blocked = self._classify_block_response(response)
            if blocked:
                return blocked

            # Medir timing con payload de SLEEP -- además de medir el
            # delay, hay que revisar el status code de ESTA respuesta
            # en particular: algunos WAFs (confirmado contra
            # uttecam.edu.mx) dejan pasar 'AND 1=1' e incluso el
            # payload XSS de arriba sin filtrar, pero bloquean la
            # keyword 'SLEEP(' específicamente con un 403 instantáneo
            # (challenge JS anti-bot, sin firma de vendor conocida).
            # Sin este chequeo el bloqueo pasaba desapercibido: al ser
            # una respuesta rápida (no hay delay real que medir), el
            # código nunca miraba más allá del tiempo transcurrido.
            separator2 = "&" if "?" in url else "?"
            timing_url = f"{url}{separator2}timing_test=1%20AND%20SLEEP%280%29"

            start = time.time()
            timing_resp = session.get(timing_url, timeout=30)
            elapsed = time.time() - start

            blocked = self._classify_block_response(timing_resp)
            if blocked:
                return blocked

            normal_start = time.time()
            session.get(url, timeout=30)
            normal_elapsed = time.time() - normal_start

            if elapsed > normal_elapsed * 3:
                return ("unknown", 0.4)

        except requests.exceptions.Timeout:
            return ("unknown", 0.3)
        except Exception:
            pass

        return ("none", 0.0)

    def _classify_block_response(
        self, response: requests.Response,
    ) -> Optional[tuple[str, float]]:
        """Si la respuesta tiene status code de bloqueo (403/406/...),
        intenta identificar el WAF por firma de body; si no matchea
        ninguna firma conocida, igual reporta 'unknown'. Devuelve None
        si la respuesta no parece un bloqueo.
        """
        if response.status_code not in (403, 406, 501, 418, 429):
            return None

        body_lower = response.text.lower()

        # Fingerprinting por body de la página de bloqueo, usando la
        # misma base de firmas que _check_headers (campo
        # block_page_signatures — términos más genéricos que solo son
        # fiables cuando ya sabemos que estamos ante una página de
        # bloqueo real).
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures.get("block_page_signatures", []):
                if sig in body_lower:
                    return (waf_name, 0.85)

        return ("unknown", 0.5)
