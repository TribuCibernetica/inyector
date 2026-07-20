"""Persistencia de sesiones de reconocimiento.

Si un scan se corta a la mitad (o simplemente se quiere reintentar
sqlmap con otra configuración sin repetir todo el recon), esto
permite guardar el resultado de la fase de reconocimiento y
recuperarlo después con --resume, en vez de tener que repetir todas
las peticiones de WAF/Stack/ORM/GraphQL contra el target.
"""

import hashlib
import json
import os
from typing import Optional

from inyector.utils.logger import get_logger

logger = get_logger(__name__)

SESSIONS_SUBDIR = ".inyector_sessions"


def _session_key(url: str, param: Optional[str], method: str) -> str:
    """Genera una clave estable para identificar la sesión de un target."""
    raw = f"{url}|{param or ''}|{method.upper()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class SessionStore:
    """Guarda y recupera el resultado del recon para un target."""

    def _session_path(self, output_dir: str, url: str,
                       param: Optional[str], method: str) -> str:
        sessions_dir = os.path.join(output_dir, SESSIONS_SUBDIR)
        os.makedirs(sessions_dir, exist_ok=True)
        key = _session_key(url, param, method)
        return os.path.join(sessions_dir, f"{key}.json")

    def save(self, output_dir: str, url: str, param: Optional[str],
              method: str, recon_data: dict) -> str:
        """Guarda el recon_data de un target. Devuelve la ruta usada."""
        path = self._session_path(output_dir, url, param, method)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(recon_data, f, ensure_ascii=False)
            logger.debug(f"Sesión de recon guardada: {path}")
        except OSError as e:
            logger.warning(f"No se pudo guardar la sesión: {e}")
        return path

    def load(self, output_dir: str, url: str, param: Optional[str],
             method: str) -> Optional[dict]:
        """Recupera el recon_data guardado para un target, si existe."""
        path = self._session_path(output_dir, url, param, method)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Sesión de recon corrupta, se ignora: {e}")
            return None
