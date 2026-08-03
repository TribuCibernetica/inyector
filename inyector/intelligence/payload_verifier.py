"""Verificación real de payloads sugeridos (por IA o por KnowledgeBase).

Una sugerencia — nuestra o de Gemini — nunca se reporta como
vulnerabilidad confirmada solo porque "suena razonable". Siempre se
prueba contra el target real y se exige evidencia HTTP concreta
(firma de error de BD, delay de tiempo, o diferencia de
comportamiento tipo boolean-blind) antes de contarla como hallazgo.
Esto es lo que separa "el LLM dijo que probablemente funcione" de
"confirmamos que funciona".
"""

import json
import time
from typing import Optional
from urllib.parse import parse_qsl

import requests

from inyector.recon.stack_detector import StackDetector
from inyector.utils.logger import get_logger
from inyector.utils.response_compare import responses_similar
from inyector.utils.url_probe import build_probe_url

logger = get_logger(__name__)

# Si el payload sugerido incluye alguna de estas, es una técnica
# time-based — el criterio de confirmación es el delay, no el body.
TIME_BASED_MARKERS = ["sleep(", "waitfor delay", "pg_sleep(", "benchmark("]

# Margen sobre el baseline para considerar un delay significativo
# (evita falsos positivos por jitter normal de red).
TIME_BASED_THRESHOLD_SECONDS = 4.0


def _send(session: requests.Session, url: str, method: str,
          param: str, value, data: Optional[str], timeout: int):
    """Manda la request con el parámetro mutado, respetando el
    método/injection point real -- bug real encontrado: esto antes
    SIEMPRE hacía un GET con `param` como query string, aunque el
    parámetro bajo prueba fuera en realidad un campo de un body
    POST/JSON (ej. 'email' en un login). Como nunca se tocaba el
    código que de verdad procesa ese campo, cualquier diferencia de
    respuesta era ruido -- no evidencia de inyección."""
    if method.upper() == "POST" and data:
        try:
            body = json.loads(data)
            body[param] = value
            return session.post(url, json=body, timeout=timeout)
        except (TypeError, ValueError):
            pass
        # No es JSON -- es el caso normal de un <form> HTML, que manda
        # application/x-www-form-urlencoded (ej. 'txtUsuario=x&...').
        # Mandarlo como json=... nunca tocaría el $_POST real del
        # backend (bug real: causaba falso negativo total en un login
        # con SQLi confirmada por SAST y manualmente).
        body = dict(parse_qsl(data))
        body[param] = value
        return session.post(url, data=body, timeout=timeout)

    test_url = build_probe_url(url, param, value, fallback_name="ai_test")
    return session.get(test_url, timeout=timeout)


def verify_payload(
    url: str, session: requests.Session, param: str, payload: str,
    method: str = "GET", data: Optional[str] = None,
    baseline_response=None, baseline_elapsed: Optional[float] = None,
) -> dict:
    """Prueba un payload puntual contra el target real y busca evidencia.

    Args:
        url: URL objetivo.
        session: sesión HTTP configurada.
        param: parámetro a mutar con el payload.
        payload: el payload SQL sugerido a probar.
        method: 'GET' o 'POST' -- determina si `param` se manda como
            query string o como campo de un body JSON.
        data: body original (JSON string) cuando method='POST', para
            mutar solo `param` y dejar el resto de los campos intactos.
        baseline_response: respuesta normal ya capturada, para
            comparar (se pide una nueva si se omite).
        baseline_elapsed: tiempo de la request baseline, necesario
            para confirmar payloads time-based.

    Returns:
        {"confirmed": bool, "signal": str, "evidence": str}
    """
    if baseline_response is None or baseline_elapsed is None:
        try:
            start = time.time()
            baseline_response = _send(
                session, url, method, param, "baseline_probe", data, 20,
            )
            baseline_elapsed = time.time() - start
        except requests.exceptions.RequestException as e:
            return {
                "confirmed": False, "signal": "error",
                "evidence": f"No se pudo obtener baseline: {e}",
            }

    # Un baseline que ya viene roto (error de servidor) no sirve de
    # referencia -- cualquier diferencia contra él sería ruido, no
    # evidencia (bug real: un target inestable bajo carga, ej. un
    # dyno gratuito de Heroku, devolvía 503 de forma intermitente y
    # eso se reportaba como "boolean-based confirmado" solo porque el
    # status code cambiaba entre baseline y test).
    if baseline_response.status_code >= 500:
        return {
            "confirmed": False, "signal": "unstable_target",
            "evidence": (
                f"Baseline devolvió {baseline_response.status_code} -- "
                f"el target parece inestable, no se puede confirmar de "
                f"forma confiable contra este baseline"
            ),
        }

    is_time_based = any(marker in payload.lower() for marker in TIME_BASED_MARKERS)

    try:
        start = time.time()
        response = _send(session, url, method, param, payload, data, 30)
        elapsed = time.time() - start
    except requests.exceptions.RequestException as e:
        return {"confirmed": False, "signal": "error", "evidence": str(e)}

    # 1. Error-based: la firma de un motor de BD real es la evidencia
    # más fuerte posible — casi cero falsos positivos. Pero solo si la
    # firma es NUEVA respecto al baseline: apps que usan extensiones
    # deprecadas (ej. mysql_*) imprimen warnings con nombres de
    # funciones tipo 'mysql_fetch' en CADA respuesta, con o sin
    # payload -- bug real encontrado en producción, donde 5 payloads
    # de técnicas distintas (error/time/boolean/union-probe) se
    # confirmaban todos como "error_based" solo porque el body
    # siempre traía ese warning.
    body_lower = response.text.lower()
    baseline_lower = baseline_response.text.lower()
    for db_name, signatures in StackDetector.DB_ERROR_SIGNATURES.items():
        for sig in signatures:
            sig_lower = sig.lower()
            if sig_lower in body_lower and sig_lower not in baseline_lower:
                return {
                    "confirmed": True, "signal": "error_based",
                    "evidence": f"Firma de error de {db_name}: '{sig}'",
                }

    # 2. Time-based: solo aplica si el payload realmente pide un delay.
    if is_time_based:
        if elapsed > baseline_elapsed + TIME_BASED_THRESHOLD_SECONDS:
            return {
                "confirmed": True, "signal": "time_based",
                "evidence": (
                    f"Delay de {elapsed:.1f}s vs baseline "
                    f"{baseline_elapsed:.1f}s"
                ),
            }
        return {"confirmed": False, "signal": "none", "evidence": ""}

    # 3. Boolean-based: la respuesta cambió de forma significativa
    # frente al comportamiento normal del target -- pero solo cuenta
    # si la respuesta del payload también es "sana" (no un error de
    # servidor, y no un bloqueo del WAF/IPS). Un status >= 400 puntual
    # en el payload no distingue "esto rompió la query SQL" de "el
    # target se cayó por carga/flakiness" o "el WAF bloqueó este
    # request pero no el baseline" -- bug real encontrado contra un
    # target con Imperva: el payload volvía 403 (bloqueado) mientras
    # el baseline volvía 200, responses_similar() correctamente decía
    # "distintas" (status code no coincide), y eso se confirmaba como
    # "boolean_based" -- comparar una página de bloqueo contra una
    # normal nunca es evidencia de SQLi. Sin evidencia más fuerte
    # (error-based o time-based arriba), no se confirma solo por eso.
    if response.status_code >= 400:
        return {
            "confirmed": False, "signal": "unstable_target",
            "evidence": (
                f"El payload devolvió {response.status_code} -- podría "
                f"ser real, pero también un bloqueo de WAF/IPS o "
                f"inestabilidad del servidor; no se confirma sin una "
                f"firma de error de BD o time-based"
            ),
        }

    if not responses_similar(baseline_response, response):
        return {
            "confirmed": True, "signal": "boolean_based",
            "evidence": "Respuesta significativamente distinta al baseline",
        }

    return {"confirmed": False, "signal": "none", "evidence": ""}
