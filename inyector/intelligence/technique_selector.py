"""Módulo de selección de técnicas de SQL Injection.

Selecciona las técnicas óptimas de SQLi basándose en
el WAF detectado, el modo de operación y las preferencias del usuario.
"""

from typing import Optional
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class TechniqueSelector:
    """Selecciona técnicas de SQLi óptimas según el contexto.

    Técnicas disponibles en sqlmap:
        B = Boolean-based blind
        E = Error-based
        U = Union query
        S = Stacked queries
        T = Time-based blind
        Q = Inline queries
    """

    TECHNIQUE_PROFILES = {
        "stealth": "BT",
        "normal": "BEUT",
        "aggressive": "BEUSTQ",
    }

    WAF_TECHNIQUE_MAP = {
        "cloudflare": "BT",
        "aws_waf": "BET",
        "modsecurity": "BT",
        "imperva": "BT",
        "akamai": "BT",
        "wordfence": "BET",
        "sucuri": "BET",
        "f5": "BT",
        "barracuda": "BEUT",
        "none": "BEUSTQ",
        "unknown": "BT",
    }

    def select(self, waf: str, stealth: bool = True,
               user_technique: Optional[str] = None) -> str:
        """Selecciona las técnicas de SQLi a utilizar.

        Args:
            waf: WAF detectado.
            stealth: Si es True, usa técnicas silenciosas.
            user_technique: Técnica forzada por el usuario (opcional).

        Returns:
            String con las técnicas a usar (ej: 'BT', 'BEUSTQ').
        """
        if user_technique:
            logger.info(f"Técnica forzada por usuario: {user_technique}")
            return user_technique.upper()

        if stealth:
            technique = self.WAF_TECHNIQUE_MAP.get(waf, "BT")
            logger.info(f"Modo stealth + WAF={waf}: técnica={technique}")
        elif waf == "none":
            technique = self.TECHNIQUE_PROFILES["aggressive"]
            logger.info(f"Sin WAF + modo rápido: técnica={technique}")
        else:
            technique = self.WAF_TECHNIQUE_MAP.get(waf, "BEUT")
            logger.info(f"WAF={waf}: técnica={technique}")

        return technique
