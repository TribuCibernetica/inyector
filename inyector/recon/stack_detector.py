"""Módulo de detección del stack tecnológico del objetivo.

Analiza headers, cookies, mensajes de error y comportamiento
para identificar el lenguaje, framework y base de datos.
"""

import requests
from typing import Any, Optional
from inyector.utils.logger import get_logger
from inyector.utils.url_probe import build_probe_url

logger = get_logger(__name__)


class StackDetector:
    """Detecta el stack tecnológico de la aplicación web objetivo."""

    STACK_SIGNATURES: dict[str, dict[str, Any]] = {
        "php": {
            "language": "php",
            "framework": "PHP nativo",
            "headers": {"X-Powered-By": ["PHP"]},
            "cookies": ["PHPSESSID"],
            "errors": ["Fatal error", "Parse error", "Warning:",
                       "mysql_", "mysqli_", "pg_query"],
            "db_hints": ["mysql", "mariadb"],
        },
        "java_spring": {
            "language": "java",
            "framework": "Spring Boot",
            "headers": {"X-Application-Context": ["*"]},
            "cookies": ["JSESSIONID"],
            "errors": ["WhitelabelError", "Spring Boot",
                       "java.sql.SQLException"],
            "db_hints": ["postgresql", "mysql", "oracle"],
        },
        "django": {
            "language": "python",
            "framework": "Django",
            "headers": {"X-Frame-Options": ["SAMEORIGIN"]},
            "cookies": ["csrftoken", "sessionid"],
            "errors": ["DoesNotExist", "IntegrityError",
                       "django.db", "OperationalError",
                       "DisallowedHost"],
            "db_hints": ["postgresql", "sqlite"],
        },
        "laravel": {
            "language": "php",
            "framework": "Laravel",
            "headers": {},
            "cookies": ["laravel_session", "XSRF-TOKEN"],
            "errors": ["Illuminate\\Database", "QueryException",
                       "Whoops!"],
            "db_hints": ["mysql", "mariadb"],
        },
        "rails": {
            "language": "ruby",
            "framework": "Ruby on Rails",
            "headers": {"X-Runtime": ["*"]},
            "cookies": ["_session_id"],
            "errors": ["ActiveRecord::", "PG::Error",
                       "ActionController"],
            "db_hints": ["postgresql"],
        },
        "express_node": {
            "language": "node",
            "framework": "Express.js",
            "headers": {"X-Powered-By": ["Express"]},
            "cookies": [],
            "errors": ["Cannot GET", "SyntaxError",
                       "ReferenceError"],
            "db_hints": ["mongodb", "mysql", "postgresql"],
        },
        "fastapi": {
            "language": "python",
            "framework": "FastAPI",
            "headers": {"server": ["uvicorn"]},
            "cookies": [],
            "errors": ["422 Unprocessable Entity", "pydantic",
                       "RequestValidationError"],
            "db_hints": ["postgresql"],
        },
        "asp_net": {
            "language": "csharp",
            "framework": "ASP.NET",
            "headers": {
                "X-AspNet-Version": ["*"],
                "X-Powered-By": ["ASP.NET"],
            },
            "cookies": ["ASP.NET_SessionId", ".AspNetCore.Session"],
            "errors": ["Server Error in '/' Application",
                       "System.Data.SqlClient",
                       "Microsoft.Data.SqlClient"],
            "db_hints": ["mssql", "sqlserver"],
        },
    }

    # Firmas de base de datos en mensajes de error
    DB_ERROR_SIGNATURES = {
        "mysql": [
            "You have an error in your SQL syntax",
            "mysql_fetch", "mysqli_",
            "MySQL server version",
            "SQLSTATE[HY000]",
        ],
        "postgresql": [
            "PSQLException", "pg_query",
            "PG::SyntaxError", "psycopg2",
            "ERROR:  syntax error at or near",
        ],
        "mssql": [
            "Microsoft SQL Server",
            "Unclosed quotation mark",
            "Microsoft OLE DB",
            "SqlClient",
        ],
        "oracle": [
            "ORA-", "Oracle error",
            "oracle.jdbc",
        ],
        "sqlite": [
            "SQLite3::", "sqlite3.OperationalError",
            "SQLITE_ERROR",
        ],
    }

    def detect(self, url: str, session: requests.Session,
               param: Optional[str] = None) -> dict:
        """Detecta el stack tecnológico de la aplicación web.

        Args:
            url: URL objetivo.
            session: Sesión HTTP configurada.
            param: Parámetro real a mutar para provocar el error de
                DB (si se omite, se agrega uno sintético que muchas
                apps reales simplemente ignoran).

        Returns:
            Diccionario con language, framework, database_hints,
            confidence y evidence.
        """
        logger.info("Iniciando detección de stack tecnológico...")

        resultado: dict[str, Any] = {
            "language": "desconocido",
            "framework": "desconocido",
            "database_hints": [],
            "confidence": 0.0,
            "evidence": [],
            "error": None,
        }

        try:
            # Request normal para analizar headers y cookies
            response = session.get(url, timeout=30, allow_redirects=True)

            best_match = None
            best_score = 0

            for stack_name, signatures in self.STACK_SIGNATURES.items():
                score = 0
                evidence = []

                # Verificar headers
                for header_name, expected_values in signatures.get("headers", {}).items():
                    header_val = response.headers.get(header_name, "")
                    if header_val:
                        if expected_values == ["*"]:
                            score += 2
                            evidence.append(
                                f"Header '{header_name}' presente: {header_val}"
                            )
                        else:
                            for ev in expected_values:
                                if ev.lower() in header_val.lower():
                                    score += 3
                                    evidence.append(
                                        f"Header '{header_name}' contiene '{ev}'"
                                    )
                                    break

                # Verificar cookies
                cookies_dict = {c.name: c.value for c in response.cookies}
                cookie_header = response.headers.get("Set-Cookie", "")
                for cookie_name in signatures.get("cookies", []):
                    if (cookie_name in cookies_dict
                            or cookie_name.lower() in cookie_header.lower()):
                        score += 3
                        evidence.append(f"Cookie '{cookie_name}' detectada")

                # Verificar errores en el body
                for error_sig in signatures.get("errors", []):
                    if error_sig.lower() in response.text.lower():
                        score += 2
                        evidence.append(f"Firma de error '{error_sig}' en body")

                if score > best_score:
                    best_score = score
                    best_match = (stack_name, signatures, evidence)

            # Aplicar resultado del mejor match
            if best_match and best_score >= 2:
                stack_name, signatures, evidence = best_match
                resultado["language"] = signatures.get("language", "desconocido")
                resultado["framework"] = signatures.get("framework", stack_name)
                resultado["database_hints"] = signatures.get("db_hints", [])
                resultado["confidence"] = min(1.0, best_score / 8.0)
                resultado["evidence"] = evidence

            # Intentar detectar base de datos con error provocado
            db_hints = self._detect_database(url, session, param=param)
            if db_hints:
                resultado["database_hints"] = list(set(
                    resultado["database_hints"] + db_hints
                ))
                resultado["evidence"].append(
                    f"Bases de datos detectadas por error: {db_hints}"
                )

        except requests.exceptions.Timeout:
            logger.warning("Timeout al detectar stack tecnológico")
            resultado["error"] = "timeout"
        except requests.exceptions.ConnectionError:
            logger.warning("Error de conexión al detectar stack")
            resultado["error"] = "connection_error"
        except Exception as e:
            logger.error(f"Error inesperado en detección de stack: {e}")
            resultado["error"] = str(e)

        logger.info(
            f"Stack detectado: {resultado['framework']} ({resultado['language']})"
        )
        return resultado

    def _detect_database(self, url: str, session: requests.Session,
                         param: Optional[str] = None) -> list[str]:
        """Intenta detectar la base de datos provocando errores SQL.

        Args:
            url: URL objetivo.
            session: Sesión HTTP.
            param: Parámetro real a mutar. Si se omite, el payload se
                agrega como parámetro sintético nuevo (menos fiable,
                porque la app puede simplemente ignorarlo).

        Returns:
            Lista de bases de datos detectadas.
        """
        detected = []
        error_url = build_probe_url(url, param, "1'", fallback_name="db_test")

        try:
            response = session.get(error_url, timeout=30)
            body = response.text

            for db_name, signatures in self.DB_ERROR_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in body.lower():
                        detected.append(db_name)
                        break

        except Exception:
            pass

        return detected
