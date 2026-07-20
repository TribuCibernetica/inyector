"""Módulo de evasión y comportamiento sigiloso.

Implementa delays con distribución gaussiana, detección
de throttling y pausas automáticas para simular tráfico humano.
"""

import time
import random
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class StealthEngine:
    """Motor de evasión que simula comportamiento humano."""

    # Configuración de pausas automáticas por WAF
    WAF_PAUSE_CONFIG = {
        "cloudflare": {"interval": 20, "min_pause": 10, "max_pause": 30},
        "aws_waf": {"interval": 30, "min_pause": 5, "max_pause": 15},
        "imperva": {"interval": 15, "min_pause": 15, "max_pause": 40},
        "akamai": {"interval": 25, "min_pause": 8, "max_pause": 20},
        "modsecurity": {"interval": 25, "min_pause": 5, "max_pause": 15},
        "wordfence": {"interval": 10, "min_pause": 20, "max_pause": 45},
        "sucuri": {"interval": 20, "min_pause": 10, "max_pause": 25},
        "f5": {"interval": 20, "min_pause": 10, "max_pause": 25},
        "barracuda": {"interval": 25, "min_pause": 5, "max_pause": 15},
        "none": {"interval": 0, "min_pause": 0, "max_pause": 0},
        "unknown": {"interval": 20, "min_pause": 10, "max_pause": 20},
    }

    def human_delay(self, min_ms: int = 800, max_ms: int = 3000) -> None:
        """Pausa con distribución gaussiana para simular tráfico humano.

        Args:
            min_ms: Delay mínimo en milisegundos.
            max_ms: Delay máximo en milisegundos.
        """
        mean = (min_ms + max_ms) / 2
        std = (max_ms - min_ms) / 6  # 99.7% dentro del rango
        delay = random.gauss(mean, std)
        delay = max(min_ms, min(max_ms, delay))  # Clamp al rango

        logger.debug(f"Human delay: {delay:.0f}ms")
        time.sleep(delay / 1000)

    def detect_throttling(self, response_times: list[float]) -> bool:
        """Detecta si el servidor está aplicando throttling.

        Args:
            response_times: Lista de tiempos de respuesta en ms.

        Returns:
            True si se detecta throttling.
        """
        if len(response_times) < 3:
            return False

        # Tomar los últimos 3 tiempos de respuesta
        last_three = response_times[-3:]

        # Verificar si son progresivamente más lentos
        is_increasing = (
            last_three[1] > last_three[0] * 1.5
            and last_three[2] > last_three[1] * 1.5
        )

        if is_increasing:
            logger.warning(
                f"Throttling detectado: tiempos {last_three[0]:.0f}ms → "
                f"{last_three[1]:.0f}ms → {last_three[2]:.0f}ms"
            )
            return True

        return False

    def should_pause(self, request_count: int,
                     waf: str) -> tuple[bool, float]:
        """Decide si hacer una pausa larga basada en el contexto.

        Args:
            request_count: Número de requests realizados.
            waf: WAF detectado.

        Returns:
            Tupla con (debe_pausar, duración_pausa_segundos).
        """
        config = self.WAF_PAUSE_CONFIG.get(waf, self.WAF_PAUSE_CONFIG["none"])

        if config["interval"] == 0:
            return (False, 0.0)

        if request_count > 0 and request_count % config["interval"] == 0:
            pause_duration = random.uniform(
                config["min_pause"], config["max_pause"]
            )
            logger.info(
                f"Pausa automática: {pause_duration:.1f}s "
                f"(cada {config['interval']} requests para {waf})"
            )
            return (True, pause_duration)

        return (False, 0.0)

    def adaptive_delay(self, response_times: list[float],
                       base_delay_ms: int = 800) -> None:
        """Aplica delay adaptativo basado en tiempos de respuesta.

        Args:
            response_times: Lista de tiempos de respuesta.
            base_delay_ms: Delay base en milisegundos.
        """
        if self.detect_throttling(response_times):
            adjusted_delay = base_delay_ms * 2
            logger.warning(f"Delay ajustado a {adjusted_delay}ms por throttling")
            self.human_delay(adjusted_delay, adjusted_delay * 2)
        else:
            self.human_delay(base_delay_ms, base_delay_ms * 2)
