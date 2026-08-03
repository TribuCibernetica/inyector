"""Módulo de cálculo de timing para evasión.

Calcula los parámetros óptimos de delay y timeout
para sqlmap basándose en el tiempo de respuesta base
del servidor y el WAF detectado.
"""

import time
import statistics
import requests
from typing import Any
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class TimingCalculator:
    """Calcula parámetros de timing óptimos para la evasión."""

    WAF_RATE_LIMITS = {
        "cloudflare": {"requests_before_pause": 20, "pause_min": 10, "pause_max": 30},
        "aws_waf": {"requests_before_pause": 30, "pause_min": 5, "pause_max": 15},
        "imperva": {"requests_before_pause": 15, "pause_min": 15, "pause_max": 40},
        "akamai": {"requests_before_pause": 25, "pause_min": 8, "pause_max": 20},
        "modsecurity": {"requests_before_pause": 25, "pause_min": 5, "pause_max": 15},
        "wordfence": {"requests_before_pause": 10, "pause_min": 20, "pause_max": 45},
        "sucuri": {"requests_before_pause": 20, "pause_min": 10, "pause_max": 25},
        "f5": {"requests_before_pause": 20, "pause_min": 10, "pause_max": 25},
        "barracuda": {"requests_before_pause": 25, "pause_min": 5, "pause_max": 15},
        "none": {"requests_before_pause": 0, "pause_min": 0, "pause_max": 0},
        "unknown": {"requests_before_pause": 20, "pause_min": 10, "pause_max": 20},
    }

    def __init__(self, stealth_mode: bool = True):
        """Inicializa el calculador de timing.

        Args:
            stealth_mode: Si es True, usa delays más conservadores.
        """
        self.stealth_mode = stealth_mode

    def measure_baseline(self, url: str, session: requests.Session,
                         samples: int = 5) -> float:
        """Mide el tiempo de respuesta base del servidor.

        Args:
            url: URL objetivo.
            session: Sesión HTTP configurada.
            samples: Número de muestras (default: 5).

        Returns:
            Tiempo de respuesta promedio en milisegundos.
        """
        logger.info(f"Midiendo baseline de respuesta ({samples} muestras)...")
        response_times = []

        for i in range(samples):
            try:
                start = time.time()
                session.get(url, timeout=30)
                elapsed = (time.time() - start) * 1000
                response_times.append(elapsed)
                logger.debug(f"Muestra {i+1}: {elapsed:.0f}ms")
            except Exception as e:
                logger.debug(f"Error en muestra {i+1}: {e}")

        if not response_times:
            logger.warning("No se pudo medir baseline, usando default de 500ms")
            return 500.0

        if len(response_times) >= 3:
            sorted_times = sorted(response_times)
            trimmed = sorted_times[1:-1]
            baseline = statistics.mean(trimmed)
        else:
            baseline = statistics.mean(response_times)

        logger.info(f"Baseline de respuesta: {baseline:.0f}ms")
        return baseline

    def calculate_delay(self, baseline_ms: float, waf: str) -> dict:
        """Calcula los parámetros de timing para sqlmap.

        Args:
            baseline_ms: Tiempo de respuesta base en ms.
            waf: WAF detectado.

        Returns:
            Diccionario con delay, timeout, retries y safe_freq.
        """
        if self.stealth_mode:
            delay = max(1, int((baseline_ms * 1.5) / 1000))
            timeout = max(30, int((baseline_ms * 10) / 1000))
            retries = 5

            waf_config = self.WAF_RATE_LIMITS.get(waf, self.WAF_RATE_LIMITS["none"])
            safe_freq = (
                waf_config["requests_before_pause"] // 2
                if waf_config["requests_before_pause"] > 0 else 0
            )

            if waf != "none":
                delay = max(delay, 2)
                retries = 5
        else:
            delay = 0
            timeout = 30
            retries = 3
            safe_freq = 0

        resultado: dict[str, Any] = {
            "delay": delay,
            "timeout": timeout,
            "retries": retries,
            "safe_freq": safe_freq,
        }

        logger.info(
            f"Timing calculado: delay={delay}s, timeout={timeout}s, "
            f"retries={retries}, safe_freq={safe_freq}"
        )
        return resultado
