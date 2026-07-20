"""Módulo de construcción del comando sqlmap.

Construye el comando sqlmap completo basándose en todos
los resultados del reconocimiento e inteligencia.
"""

import os
import shlex
from typing import Optional
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class CommandBuilder:
    """Construye el comando sqlmap optimizado según el reconocimiento."""

    def build(self, scan_config: dict) -> str:
        """Construye el comando completo de sqlmap.

        Args:
            scan_config: Configuración completa del scan.

        Returns:
            Comando sqlmap completo como string.
        """
        parts = ["sqlmap"]

        url = scan_config["url"]
        method = scan_config.get("method", "GET")
        data = scan_config.get("data")
        param = scan_config.get("param")
        cookie = scan_config.get("cookie")
        headers = scan_config.get("headers", [])
        waf = scan_config.get("waf", {}).get("waf", "none")
        orm = scan_config.get("orm", {}).get("orm", "none")
        timing = scan_config.get("timing", {})
        tampers = scan_config.get("tampers", [])
        technique = scan_config.get("technique")
        level = scan_config.get("level", 2)
        risk = scan_config.get("risk", 1)
        threads = scan_config.get("threads", 3)
        proxy = scan_config.get("proxy")
        output_dir = scan_config.get("output_dir", "/app/reports")
        stealth = scan_config.get("stealth", True)

        # 1. URL base
        parts.append(f"-u {shlex.quote(url)}")

        # 2. Modo batch (no interactivo)
        parts.append("--batch")
        parts.append("--no-cast")

        # 3. Método y datos POST
        # shlex.quote (no comillas dobles a mano): un body JSON trae
        # sus propias comillas dobles, que rompían el armado del
        # comando cuando se lo pasa al shell (bug real encontrado al
        # agregar soporte de --crawl para candidatos JSON tipo login).
        if method.upper() == "POST" and data:
            parts.append(f"--data={shlex.quote(data)}")

        # 4. Parámetro objetivo
        if param:
            parts.append(f"-p {param}")

        # 5. Técnica SQLi
        selected_technique = self._select_technique(waf, stealth, technique)
        parts.append(f"--technique={selected_technique}")

        # 6. Tamper scripts
        if tampers:
            tamper_str = ",".join(tampers)
            parts.append(f"--tamper={tamper_str}")

        # 7. Timing (modo stealth)
        if timing:
            delay = timing.get("delay", 0)
            timeout = timing.get("timeout", 30)
            retries = timing.get("retries", 3)
            safe_freq = timing.get("safe_freq", 0)

            if delay > 0:
                parts.append(f"--delay={delay}")
            parts.append(f"--timeout={timeout}")
            parts.append(f"--retries={retries}")
            if safe_freq > 0:
                parts.append(f"--safe-freq={safe_freq}")

        # 8. User-Agent realista
        parts.append("--random-agent")

        # 9. Cookie de sesión
        if cookie:
            parts.append(f"--cookie={shlex.quote(cookie)}")

        # 10. Headers adicionales
        for header in headers:
            parts.append(f"--header={shlex.quote(header)}")

        # 11. Level y Risk
        parts.append(f"--level={level}")
        parts.append(f"--risk={risk}")

        # 12. Threads
        parts.append(f"--threads={threads}")

        # 13. Output
        parts.append(f"--output-dir={output_dir}")

        # 14. Proxy
        if proxy:
            parts.append(f"--proxy={shlex.quote(proxy)}")

        # 15. Flags de evasión adicionales según WAF
        if waf == "cloudflare":
            parts.append("--hpp")
        elif waf == "modsecurity":
            parts.append("--hex")

        # 16. Si ORM detectado con raw queries
        orm_data = scan_config.get("orm", {})
        if orm_data.get("raw_queries_likely"):
            orm_name = orm_data.get("orm", "")
            orm_strings = {
                "django_orm": "OperationalError",
                "sqlalchemy": "sqlalchemy.exc",
                "hibernate": "HibernateException",
                "eloquent": "QueryException",
            }
            if orm_name in orm_strings:
                parts.append(f"--string={shlex.quote(orm_strings[orm_name])}")

        # 17. Flush session
        parts.append("--flush-session")

        comando = " ".join(parts)
        logger.info(f"Comando sqlmap construido ({len(parts)} flags)")
        logger.debug(f"Comando: {comando}")

        return comando

    def _select_technique(self, waf: str, stealth: bool,
                          user_technique: Optional[str]) -> str:
        """Selecciona la técnica de SQLi basándose en el contexto.

        Args:
            waf: WAF detectado.
            stealth: Si es True, usar técnicas silenciosas.
            user_technique: Técnica forzada por el usuario.

        Returns:
            String con técnicas (ej: 'BT', 'BEUSTQ').
        """
        if user_technique:
            return user_technique.upper()

        if stealth and waf != "none":
            return "BT"

        if waf == "none" and not stealth:
            return "BEUSTQ"

        return "BEUT"
