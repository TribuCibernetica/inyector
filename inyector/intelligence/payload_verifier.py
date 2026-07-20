"""Verificación real de payloads sugeridos (por IA o por KnowledgeBase).

Una sugerencia — nuestra o de Gemini — nunca se reporta como
vulnerabilidad confirmada solo porque "suena razonable". Siempre se
prueba contra el target real y se exige evidencia HTTP concreta
(firma de error de BD, delay de tiempo, o diferencia de
comportamiento tipo boolean-blind) antes de contarla como hallazgo.
Esto es lo que separa "el LLM dijo que probablemente funcione" de
"confirmamos que funciona".
"""

import time
from typing import Optional

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


def verify_payload(
    url: str, session: requests.Session, param: str, payload: str,
    baseline_response=None, baseline_elapsed: Optional[float] = None,
) -> dict:
    """Prueba un payload puntual contra el target real y busca evidencia.

    Args:
        url: URL objetivo.
        session: sesión HTTP configurada.
        param: parámetro a mutar con el payload.
        payload: el payload SQL sugerido a probar.
        baseline_response: respuesta normal ya capturada, para
            comparar (se pide una nueva si se omite).
        baseline_elapsed: tiempo de la request baseline, necesario
            para confirmar payloads time-based.

    Returns:
        {"confirmed": bool, "signal": str, "evidence": str}
    """
    test_url = build_probe_url(url, param, payload, fallback_name="ai_test")

    if baseline_response is None or baseline_elapsed is None:
        try:
            start = time.time()
            baseline_response = session.get(url, timeout=20)
            baseline_elapsed = time.time() - start
        except requests.exceptions.RequestException as e:
            return {
                "confirmed": False, "signal": "error",
                "evidence": f"No se pudo obtener baseline: {e}",
            }

    is_time_based = any(marker in payload.lower() for marker in TIME_BASED_MARKERS)

    try:
        start = time.time()
        response = session.get(test_url, timeout=30)
        elapsed = time.time() - start
    except requests.exceptions.RequestException as e:
        return {"confirmed": False, "signal": "error", "evidence": str(e)}

    # 1. Error-based: la firma de un motor de BD real es la evidencia
    # más fuerte posible — casi cero falsos positivos.
    body_lower = response.text.lower()
    for db_name, signatures in StackDetector.DB_ERROR_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in body_lower:
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
    # frente al comportamiento normal del target.
    if not responses_similar(baseline_response, response):
        return {
            "confirmed": True, "signal": "boolean_based",
            "evidence": "Respuesta significativamente distinta al baseline",
        }

    return {"confirmed": False, "signal": "none", "evidence": ""}
