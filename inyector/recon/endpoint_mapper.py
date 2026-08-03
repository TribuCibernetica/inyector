"""Módulo de mapeo de endpoints y parámetros.

Analiza la URL objetivo para extraer parámetros GET/POST
y mapear la superficie de ataque.
"""

from urllib.parse import urlparse, parse_qs, unquote_plus
from typing import Any, Optional
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class EndpointMapper:
    """Mapea endpoints y parámetros de la URL objetivo."""

    def map_parameters(self, url: str, method: str = "GET",
                       data: Optional[str] = None) -> dict:
        """Extrae y mapea todos los parámetros de la URL.

        Args:
            url: URL objetivo con parámetros.
            method: Método HTTP (GET o POST).
            data: Datos del body para POST.

        Returns:
            Diccionario con endpoint base, parámetros y método.
        """
        logger.info("Mapeando parámetros del endpoint...")

        parsed = urlparse(url)
        params_get = parse_qs(parsed.query, keep_blank_values=True)
        params_post = {}

        # Parsear datos POST si los hay
        if data:
            try:
                for pair in data.split("&"):
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        params_post[unquote_plus(key)] = [unquote_plus(value)]
            except Exception:
                pass

        # Aplanar valores de parámetros
        flat_get = {k: v[0] if v else "" for k, v in params_get.items()}
        flat_post = {k: v[0] if v else "" for k, v in params_post.items()}

        resultado: dict[str, Any] = {
            "base_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "full_url": url,
            "method": method.upper(),
            "params_get": flat_get,
            "params_post": flat_post,
            "total_params": len(flat_get) + len(flat_post),
            "injectable_params": self._identify_injectable(flat_get, flat_post),
        }

        logger.info(
            f"Endpoint mapeado: {resultado['total_params']} parámetros encontrados"
        )
        return resultado

    def _identify_injectable(self, params_get: dict,
                              params_post: dict) -> list[dict]:
        """Identifica parámetros potencialmente inyectables.

        Args:
            params_get: Parámetros GET.
            params_post: Parámetros POST.

        Returns:
            Lista de parámetros con su prioridad de inyección.
        """
        high_priority_keywords = [
            "id", "uid", "user_id", "item_id", "product_id",
            "category", "cat", "page", "search", "query",
            "q", "sort", "order", "filter", "name",
            "username", "email", "login", "password",
        ]

        injectable = []

        for param, value in params_get.items():
            priority = (
                "alta" if param.lower() in high_priority_keywords else "media"
            )
            if value.isdigit():
                priority = "alta"
            injectable.append({
                "name": param,
                "value": value,
                "method": "GET",
                "priority": priority,
            })

        for param, value in params_post.items():
            priority = (
                "alta" if param.lower() in high_priority_keywords else "media"
            )
            if value.isdigit():
                priority = "alta"
            injectable.append({
                "name": param,
                "value": value,
                "method": "POST",
                "priority": priority,
            })

        injectable.sort(key=lambda x: 0 if x["priority"] == "alta" else 1)
        return injectable
