"""Módulo de parsing del output de sqlmap.

Extrae información estructurada del output de texto
de sqlmap: vulnerabilidades, DBMS, payloads, etc.
"""

import re
import os
from typing import Any
from urllib.parse import urlparse
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class SqlmapOutputParser:
    """Parsea el output de sqlmap y extrae información estructurada."""

    def parse(self, stdout: str, output_dir: str, target_url: str = "") -> dict:
        """Parsea el output completo de sqlmap.

        Args:
            stdout: Output de texto de sqlmap.
            output_dir: Directorio de output de sqlmap (compartido
                entre TODOS los targets escaneados alguna vez --
                sqlmap crea un subdirectorio propio por hostname
                debajo de este).
            target_url: URL del target de ESTE scan. Se usa para
                acotar `_merge_file_results` al subdirectorio de este
                target -- sin esto, se mezclan hallazgos de scans
                viejos contra sitios totalmente distintos (ver
                docstring de `_merge_file_results`).

        Returns:
            Diccionario estructurado con todos los resultados.
        """
        logger.info("Parseando resultados de sqlmap...")

        resultado: dict[str, Any] = {
            "vulnerable": False,
            "vulnerabilities": [],
            "databases": [],
            "tables": {},
            "users": [],
            "target_url": "",
            "injection_point": "",
            "dbms": {},
            "raw_output": stdout,
        }

        # Extraer URL objetivo. sqlmap imprime "URL:" en una línea y
        # "GET http://..." en la siguiente, por eso hay que saltar el
        # método HTTP y no solo el espacio en blanco.
        url_match = re.search(r"URL:\s*(?:\S+\s+)?(\w+://\S+)", stdout)
        if url_match:
            resultado["target_url"] = url_match.group(1)

        # Extraer vulnerabilidades
        vulns = self._extract_vulnerability_blocks(stdout)
        resultado["vulnerabilities"] = vulns
        resultado["vulnerable"] = len(vulns) > 0

        # Extraer información del DBMS
        resultado["dbms"] = self._parse_dbms_info(stdout)

        # Extraer bases de datos
        db_match = re.findall(
            r"\[\*\]\s+available databases.*?:\n(.*?)(?=\n\n|$)",
            stdout, re.DOTALL,
        )
        if db_match:
            for block in db_match:
                dbs = re.findall(r"\[\*\]\s+(\S+)", block)
                resultado["databases"].extend(dbs)

        # Extraer punto de inyección
        injection_match = re.search(
            r"Parameter:\s+(\S+.*?)(?:\n|$)", stdout,
        )
        if injection_match:
            resultado["injection_point"] = injection_match.group(1).strip()

        # Intentar leer resultados desde archivo de sqlmap
        self._merge_file_results(resultado, output_dir, target_url)

        if resultado["vulnerable"]:
            logger.info(
                f"Resultados: {len(resultado['vulnerabilities'])} "
                f"vulnerabilidades encontradas"
            )
        else:
            logger.info("No se encontraron vulnerabilidades")

        return resultado

    def _extract_vulnerability_blocks(self, text: str) -> list[dict]:
        """Extrae bloques de vulnerabilidades del output de sqlmap.

        Args:
            text: Output de texto de sqlmap.

        Returns:
            Lista de diccionarios con información de cada vulnerabilidad.
        """
        vulnerabilities = []
        blocks = re.findall(r"---\n(.*?)---", text, re.DOTALL)

        for block in blocks:
            vuln = {
                "parameter": "",
                "type": "",
                "title": "",
                "payload": "",
                "dbms": "",
                "dbms_version": "",
                "os": "",
                "technique": "",
            }

            param_match = re.search(r"Parameter:\s+(.+)", block)
            if param_match:
                vuln["parameter"] = param_match.group(1).strip()

            type_match = re.search(r"Type:\s+(.+)", block)
            if type_match:
                vuln["type"] = type_match.group(1).strip()
                type_lower = vuln["type"].lower()
                if "boolean" in type_lower:
                    vuln["technique"] = "B"
                elif "error" in type_lower:
                    vuln["technique"] = "E"
                elif "union" in type_lower:
                    vuln["technique"] = "U"
                elif "stacked" in type_lower:
                    vuln["technique"] = "S"
                elif "time" in type_lower:
                    vuln["technique"] = "T"
                elif "inline" in type_lower:
                    vuln["technique"] = "Q"

            title_match = re.search(r"Title:\s+(.+)", block)
            if title_match:
                vuln["title"] = title_match.group(1).strip()

            payload_match = re.search(r"Payload:\s+(.+)", block)
            if payload_match:
                vuln["payload"] = payload_match.group(1).strip()

            if vuln["parameter"] or vuln["type"] or vuln["title"]:
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _parse_dbms_info(self, text: str) -> dict:
        """Extrae información del DBMS del output de sqlmap.

        Args:
            text: Output de texto de sqlmap.

        Returns:
            Diccionario con name, version, os y web_tech.
        """
        dbms_info = {
            "name": "",
            "version": "",
            "os": "",
            "web_tech": "",
        }

        # sqlmap suele imprimir primero una suposición heurística
        # ("it looks like the back-end DBMS is 'MySQL'. Do you want...")
        # y solo al final la línea autoritativa ("[INFO] the back-end
        # DBMS is MySQL"). Nos quedamos con el ÚLTIMO match y limitamos
        # la clase de caracteres para no arrastrar texto del prompt.
        dbms_matches = re.findall(
            r"(?:the back-end DBMS is|back-end DBMS:)\s+'?([A-Za-z0-9_.\-<>= ]+?)'?(?:\s*\(|\n|$)",
            text, re.IGNORECASE,
        )
        if dbms_matches:
            dbms_str = dbms_matches[-1].strip()
            version_match = re.search(r"([><=]+\s*[\d.]+)", dbms_str)
            if version_match:
                dbms_info["version"] = version_match.group(1).strip()
                dbms_str = dbms_str[:version_match.start()].strip()
            dbms_info["name"] = dbms_str.split()[0] if dbms_str else ""

        tech_match = re.search(
            r"web (?:server|application) technology:\s+(.+?)(?:\n|$)",
            text, re.IGNORECASE,
        )
        if tech_match:
            dbms_info["web_tech"] = tech_match.group(1).strip()

        os_match = re.search(
            r"operating system:\s+(.+?)(?:\n|$)",
            text, re.IGNORECASE,
        )
        if os_match:
            dbms_info["os"] = os_match.group(1).strip()

        return dbms_info

    def _merge_file_results(self, resultado: dict, output_dir: str,
                             target_url: str = "") -> None:
        """Intenta leer y mergear resultados desde archivos de sqlmap.

        `output_dir` es compartido entre TODOS los targets escaneados
        alguna vez (por defecto `/app/reports`) -- sqlmap crea su
        propio subdirectorio por hostname debajo de él (ej.
        `reports/<hostname>/log`). Sin acotar la búsqueda a ese
        subdirectorio, un `os.walk` sobre todo `output_dir` mezcla
        hallazgos de scans anteriores contra sitios totalmente
        distintos en el reporte de ESTE scan -- bug real encontrado:
        un log viejo de un scan contra 'localhost' contaminó el
        reporte de un scan posterior contra Juice Shop, reportando
        una vulnerabilidad de MySQL que nunca existió ahí.

        Args:
            resultado: Diccionario de resultados actual.
            output_dir: Directorio de output de sqlmap.
            target_url: URL del target de este scan -- si se pasa, la
                búsqueda se acota a `output_dir/<hostname>/`. Sin
                hostname disponible, se cae de vuelta al
                comportamiento viejo (menos preciso, pero no rompe
                nada) como último recurso.
        """
        if not os.path.isdir(output_dir):
            return

        search_root = output_dir
        if target_url:
            hostname = urlparse(target_url).hostname
            if hostname:
                candidate = os.path.join(output_dir, hostname)
                if os.path.isdir(candidate):
                    search_root = candidate

        for root, dirs, files in os.walk(search_root):
            for filename in files:
                filepath = os.path.join(root, filename)

                if filename == "log":
                    try:
                        with open(filepath, "r") as f:
                            log_content = f.read()
                            extra_vulns = self._extract_vulnerability_blocks(
                                log_content
                            )
                            for vuln in extra_vulns:
                                if vuln not in resultado["vulnerabilities"]:
                                    resultado["vulnerabilities"].append(vuln)
                    except Exception:
                        pass
