"""Módulo de enriquecimiento de resultados.

Añade contexto, recomendaciones de remediación y
niveles de severidad a los resultados del scan.
"""

from typing import Optional
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class ResultEnricher:
    """Enriquece los resultados del scan con contexto adicional."""

    SEVERITY_MAP = {
        "B": {"level": "ALTO", "score": 8.0},
        "E": {"level": "CRÍTICO", "score": 9.5},
        "U": {"level": "CRÍTICO", "score": 9.8},
        "S": {"level": "CRÍTICO", "score": 10.0},
        "T": {"level": "ALTO", "score": 7.5},
        "Q": {"level": "CRÍTICO", "score": 9.0},
    }

    REMEDIATION_MAP = {
        "django_orm": [
            "Usar .filter() y .exclude() en lugar de .raw() o .extra()",
            "Si necesitas queries crudas, usar parametrized queries con params=[]",
            "Ejemplo seguro: MyModel.objects.raw('SELECT * FROM app_model WHERE id = %s', [user_id])",
            "Nunca usar f-strings o .format() para construir queries SQL",
            "Activar django.middleware.security.SecurityMiddleware",
        ],
        "sqlalchemy": [
            "Usar bindparams en lugar de text() con f-strings",
            "Ejemplo seguro: session.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id})",
            "Nunca concatenar strings en queries SQL",
            "Usar el ORM de SQLAlchemy en lugar de queries SQL crudas",
        ],
        "hibernate": [
            "Usar Criteria API o JPQL con parámetros nombrados",
            "Ejemplo seguro: query.setParameter('id', userId)",
            "Evitar createNativeQuery() con strings concatenados",
            "Usar PreparedStatement para queries nativas",
        ],
        "prisma": [
            "Evitar $queryRawUnsafe a toda costa",
            "Usar $queryRaw con template literals de Prisma",
            "Ejemplo seguro: prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`",
            "Usar el query builder de Prisma en lugar de SQL crudo",
        ],
        "sequelize": [
            "Evitar sequelize.query() con strings concatenados",
            "Usar replacements o bind parameters",
            "Ejemplo seguro: sequelize.query('SELECT * FROM users WHERE id = ?', { replacements: [userId] })",
            "Preferir el query builder de Sequelize",
        ],
        "active_record": [
            "Evitar find_by_sql() con interpolación de strings",
            "Usar placeholders con ?",
            "Ejemplo seguro: User.where('id = ?', params[:id])",
            "Nunca usar #{} dentro de queries SQL",
        ],
        "eloquent": [
            "Evitar DB::raw() y whereRaw() con variables sin sanitizar",
            "Usar bindings en queries crudas",
            "Ejemplo seguro: DB::select('SELECT * FROM users WHERE id = ?', [$id])",
            "Preferir el query builder de Eloquent con where()",
        ],
        "none": [
            "Usar Prepared Statements / Parametrized Queries",
            "Nunca concatenar input del usuario en queries SQL",
            "Implementar validación de input (whitelist, no blacklist)",
            "Aplicar principio de menor privilegio en la base de datos",
            "Implementar un WAF como capa adicional de defensa",
        ],
    }

    GENERAL_REMEDIATION = [
        "Implementar Prepared Statements / Parametrized Queries en todos los accesos a BD",
        "Configurar un WAF (Web Application Firewall) como defensa en profundidad",
        "Aplicar principio de menor privilegio: el usuario de BD no debe tener permisos de DBA",
        "Implementar logging y alertas para queries SQL anómalas",
        "Realizar auditorías de código regulares enfocadas en acceso a BD",
        "Mantener actualizado el DBMS y el framework de la aplicación",
    ]

    def enrich(self, scan_results: dict, recon_data: dict) -> dict:
        """Enriquece los resultados del scan con contexto adicional.

        Args:
            scan_results: Resultados del parser de sqlmap.
            recon_data: Datos del reconocimiento.

        Returns:
            Resultados enriquecidos con contexto adicional.
        """
        logger.info("Enriqueciendo resultados...")

        enriched = {
            **scan_results,
            "severity": "LIMPIO",
            "severity_score": 0.0,
            "remediation": [],
            "general_remediation": self.GENERAL_REMEDIATION,
            "recon": recon_data,
        }

        if scan_results.get("vulnerable"):
            max_severity = {"level": "BAJO", "score": 0.0}

            for vuln in scan_results.get("vulnerabilities", []):
                technique = vuln.get("technique", "")
                sev = self.SEVERITY_MAP.get(
                    technique, {"level": "MEDIO", "score": 5.0}
                )

                if sev["score"] > max_severity["score"]:
                    max_severity = sev

                vuln["severity"] = sev["level"]
                vuln["severity_score"] = sev["score"]

            enriched["severity"] = max_severity["level"]
            enriched["severity_score"] = max_severity["score"]

        orm = recon_data.get("orm", {}).get("orm", "none")
        orm_remediation = self.REMEDIATION_MAP.get(
            orm, self.REMEDIATION_MAP["none"]
        )
        enriched["remediation"] = orm_remediation

        # NoSQLi confirmado es una vulnerabilidad real aunque sqlmap
        # (que no soporta NoSQL) haya reportado el lado SQL como
        # limpio — no debe quedar oculto detrás de un severity LIMPIO.
        nosqli = recon_data.get("nosqli", {})
        nosqli_vulnerable = (
            nosqli.get("operator_injection", {}).get("vulnerable")
            or nosqli.get("where_injection", {}).get("vulnerable")
        )
        if nosqli_vulnerable:
            if enriched["severity_score"] < 8.0:
                enriched["severity"] = "ALTO"
                enriched["severity_score"] = 8.0
            enriched["remediation"] = enriched["remediation"] + [
                "NoSQLi (MongoDB): nunca pasar req.query/req.body directamente "
                "a filtros de MongoDB — castear explícitamente a String/Number "
                "antes de usarlos en find()/findOne()",
                "Deshabilitar operadores en input de usuario con una librería "
                "como mongo-sanitize o express-mongo-sanitize",
                "Evitar $where con JavaScript generado a partir de input del "
                "usuario — usar operadores nativos ($eq, $in, etc.) en su lugar",
            ]

        logger.info(
            f"Severidad: {enriched['severity']} (score: {enriched['severity_score']})"
        )
        return enriched
