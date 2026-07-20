"""Módulo de rotación de headers HTTP.

Genera headers HTTP realistas que simulan navegadores
reales para evitar detección de tráfico automatizado.
"""

import random
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class HeaderRotator:
    """Genera headers HTTP realistas para evasión de detección."""

    # User-Agents de navegadores reales (actualizados)
    REAL_USER_AGENTS = [
        # Chrome Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        # Chrome macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        # Firefox Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) "
        "Gecko/20100101 Firefox/122.0",
        # Firefox macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:122.0) "
        "Gecko/20100101 Firefox/122.0",
        # Safari macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Edge Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        # Chrome Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        # Firefox Linux
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) "
        "Gecko/20100101 Firefox/122.0",
    ]

    # Idiomas para Accept-Language (variados)
    ACCEPT_LANGUAGES = [
        "es-MX,es;q=0.9,en;q=0.8",
        "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
        "en-US,en;q=0.9,es;q=0.8",
        "en-GB,en;q=0.9,es-MX;q=0.8,es;q=0.7",
        "es-CO,es;q=0.9,en;q=0.8",
    ]

    def get_realistic_headers(self) -> dict:
        """Genera un conjunto completo de headers HTTP realistas.

        Returns:
            Diccionario con headers HTTP realistas.
        """
        headers = {
            "User-Agent": random.choice(self.REAL_USER_AGENTS),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        logger.debug(f"Headers generados con UA: {headers['User-Agent'][:50]}...")
        return headers

    def get_random_user_agent(self) -> str:
        """Retorna un User-Agent aleatorio."""
        return random.choice(self.REAL_USER_AGENTS)
