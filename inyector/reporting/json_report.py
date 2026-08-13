"""Módulo de generación de reportes JSON.

Genera reportes estructurados en formato JSON con todos
los resultados del scan y reconocimiento.
"""

import json
import os
from datetime import datetime
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class JSONReportGenerator:
    """Genera reportes en formato JSON."""

    def generate(self, enriched_results: dict, output_path: str) -> str:
        """Genera un reporte JSON completo.

        Args:
            enriched_results: Resultados enriquecidos del scan.
            output_path: Ruta del archivo de salida.

        Returns:
            Ruta del archivo generado.
        """
        logger.info(f"Generando reporte JSON: {output_path}")

        report = {
            "meta": {
                "tool": "inyector",
                "version": "1.0.0",
                "author": "TribuCibernetica",
                "generated_at": datetime.now().isoformat(),
                "disclaimer": (
                    "Este reporte es confidencial. Solo para uso "
                    "en entornos autorizados."
                ),
            },
            "target": {
                "url": enriched_results.get("target_url", ""),
                "injection_point": enriched_results.get("injection_point", ""),
            },
            "severity": {
                "level": enriched_results.get("severity", "LIMPIO"),
                "score": enriched_results.get("severity_score", 0.0),
            },
            "scan_meta": {
                "auto_escalated": enriched_results.get("auto_escalated", False),
            },
            "reconnaissance": {
                "waf": enriched_results.get("recon", {}).get("waf", {}),
                "stack": enriched_results.get("recon", {}).get("stack", {}),
                "orm": enriched_results.get("recon", {}).get("orm", {}),
                "graphql": enriched_results.get("recon", {}).get("graphql", {}),
                "nosqli": enriched_results.get("recon", {}).get("nosqli", {}),
                "csrf": enriched_results.get("recon", {}).get("csrf", {}),
                "injectable_params": enriched_results.get("recon", {})
                    .get("endpoints", {}).get("injectable_params", []),
                "consistency_notes": enriched_results.get("recon", {})
                    .get("consistency_notes", []),
            },
            "vulnerabilities": [
                {k: v for k, v in vuln.items() if k != "raw_output"}
                for vuln in enriched_results.get("vulnerabilities", [])
            ],
            "dbms": enriched_results.get("dbms", {}),
            "databases": enriched_results.get("databases", []),
            "ai_assist": enriched_results.get("ai_assist", {}),
            "remediation": {
                "specific": enriched_results.get("remediation", []),
                "general": enriched_results.get("general_remediation", []),
            },
        }

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"Reporte JSON generado: {output_path}")
        return output_path
