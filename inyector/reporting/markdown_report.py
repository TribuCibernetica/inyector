"""Módulo de generación de reportes Markdown.

Genera un reporte en texto plano (Markdown) con la misma
información que el reporte HTML, pensado para pegarse en
tickets, PRs o wikis internas.
"""

import os
from datetime import datetime
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class MarkdownReportGenerator:
    """Genera reportes en formato Markdown."""

    SEVERITY_EMOJI = {
        "CRÍTICO": "🔴",
        "ALTO": "🟠",
        "MEDIO": "🟡",
        "BAJO": "🔵",
        "LIMPIO": "🟢",
    }

    def generate(self, enriched_results: dict, output_path: str) -> str:
        """Genera un reporte Markdown completo.

        Args:
            enriched_results: Resultados enriquecidos del scan.
            output_path: Ruta del archivo de salida.

        Returns:
            Ruta del archivo generado.
        """
        logger.info(f"Generando reporte Markdown: {output_path}")

        recon = enriched_results.get("recon", {})
        waf_data = recon.get("waf", {})
        stack_data = recon.get("stack", {})
        orm_data = recon.get("orm", {})
        graphql_data = recon.get("graphql", {})

        severity = enriched_results.get("severity", "LIMPIO")
        emoji = self.SEVERITY_EMOJI.get(severity, "🟢")
        vulnerable = enriched_results.get("vulnerable", False)
        vulnerabilities = enriched_results.get("vulnerabilities", [])
        dbms = enriched_results.get("dbms", {})

        lines = []
        lines.append("# 🛡️ Reporte de SQL Injection — inyector v1.0")
        lines.append("")
        lines.append(f"**Fecha:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}  ")
        lines.append(f"**Objetivo:** `{enriched_results.get('target_url', 'N/A')}`  ")
        lines.append(f"**Severidad:** {emoji} **{severity}**")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Resumen ejecutivo
        lines.append("## 📊 Resumen Ejecutivo")
        lines.append("")
        lines.append("| Campo | Valor |")
        lines.append("|---|---|")
        lines.append(f"| URL objetivo | {enriched_results.get('target_url', 'N/A')} |")
        waf_name = waf_data.get("waf", "none")
        waf_confidence = int(waf_data.get("confidence", 0) * 100)
        lines.append(f"| WAF detectado | {waf_name} ({waf_confidence}%) |")
        lines.append(
            f"| Stack tecnológico | {stack_data.get('framework', 'desconocido')} "
            f"({stack_data.get('language', 'desconocido')}) |"
        )
        lines.append(f"| ORM detectado | {orm_data.get('orm', 'none')} |")
        lines.append(f"| Vulnerabilidades encontradas | {len(vulnerabilities)} |")
        dbms_str = f"{dbms.get('name', 'N/A')} {dbms.get('version', '')}".strip()
        lines.append(f"| DBMS | {dbms_str or 'N/A'} |")
        lines.append("")

        # Vulnerabilidades
        if vulnerable and vulnerabilities:
            lines.append("## 🔴 Vulnerabilidades Encontradas")
            lines.append("")
            for vuln in vulnerabilities:
                lines.append(
                    f"### Parámetro: `{vuln.get('parameter', 'N/A')}`"
                )
                lines.append("")
                lines.append(f"- **Tipo:** {vuln.get('type', 'N/A')}")
                lines.append(f"- **Título:** {vuln.get('title', 'N/A')}")
                if vuln.get("dbms"):
                    lines.append(f"- **DBMS:** {vuln.get('dbms')}")
                if vuln.get("technique"):
                    lines.append(f"- **Técnica sqlmap:** {vuln.get('technique')}")
                if vuln.get("payload"):
                    lines.append("- **Payload:**")
                    lines.append("")
                    lines.append("  ```")
                    lines.append(f"  {vuln.get('payload')}")
                    lines.append("  ```")
                lines.append("")
        else:
            lines.append("## ✅ Sin vulnerabilidades detectadas")
            lines.append("")

        # Reconocimiento
        lines.append("## 🔍 Reconocimiento")
        lines.append("")
        lines.append("### WAF Fingerprinting")
        lines.append("")
        lines.append(f"- **WAF:** {waf_name}")
        lines.append(f"- **Confianza:** {waf_confidence}%")
        evidence = waf_data.get("evidence", [])
        if evidence:
            lines.append("- **Evidencias:**")
            for ev in evidence:
                lines.append(f"  - {ev}")
        tampers = recon.get("tampers_used", [])
        if tampers:
            lines.append(f"- **Tampers usados:** {', '.join(tampers)}")
        lines.append("")

        lines.append("### Stack Detection")
        lines.append("")
        lines.append(f"- **Lenguaje:** {stack_data.get('language', 'desconocido')}")
        lines.append(f"- **Framework:** {stack_data.get('framework', 'desconocido')}")
        lines.append(f"- **ORM:** {orm_data.get('orm', 'none')}")
        escape_hatches = orm_data.get("escape_hatches", [])
        if escape_hatches:
            lines.append(
                "- **Escape hatches:** "
                + ", ".join(f"`{eh}`" for eh in escape_hatches)
            )
        db_hints = stack_data.get("database_hints", [])
        if db_hints:
            lines.append(f"- **Pistas de BD:** {', '.join(db_hints)}")
        lines.append("")

        injectable_params = recon.get("endpoints", {}).get("injectable_params", [])
        if injectable_params:
            lines.append("### Parámetros priorizados")
            lines.append("")
            for p in injectable_params[:10]:
                lines.append(
                    f"- `{p.get('name')}` ({p.get('method')}) — "
                    f"prioridad {p.get('priority')}"
                )
            lines.append("")

        if graphql_data.get("endpoints"):
            lines.append("### Endpoints GraphQL")
            lines.append("")
            for ep in graphql_data.get("endpoints", []):
                lines.append(f"- `{ep}`")
            lines.append(
                f"- **Introspección:** "
                f"{'Habilitada' if graphql_data.get('introspection_enabled') else 'Deshabilitada'}"
            )
            injectable = graphql_data.get("injectable_args", [])
            if injectable:
                lines.append("- **Argumentos potencialmente inyectables:**")
                for arg in injectable:
                    lines.append(
                        f"  - `{arg.get('query_name')}.{arg.get('arg_name')}` "
                        f"({arg.get('arg_type')})"
                    )
            lines.append("")

        nosqli_data = recon.get("nosqli", {})
        if nosqli_data and nosqli_data.get("engine", "unknown") != "unknown" or (
            nosqli_data.get("operator_injection", {}).get("vulnerable")
            or nosqli_data.get("where_injection", {}).get("vulnerable")
        ):
            lines.append("### NoSQL Injection (MongoDB)")
            lines.append("")
            lines.append(f"- **Motor:** {nosqli_data.get('engine', 'unknown')}")
            op = nosqli_data.get("operator_injection", {})
            if op.get("vulnerable"):
                lines.append(
                    f"- 🔴 **Operator injection confirmada** "
                    f"(vector: {op.get('vector')})"
                )
                for ev in op.get("evidence", []):
                    lines.append(f"  - {ev}")
            where = nosqli_data.get("where_injection", {})
            if where.get("vulnerable"):
                lines.append(
                    f"- 🔴 **$where injection confirmada** "
                    f"(técnica: {where.get('technique')})"
                )
                for ev in where.get("evidence", []):
                    lines.append(f"  - {ev}")
            if not op.get("vulnerable") and not where.get("vulnerable"):
                lines.append("- Sin NoSQL injection detectada")
            lines.append("")

        # Asistencia de IA — historial completo (confirmado o no), no
        # solo lo que terminó como hallazgo, para que las decisiones
        # de Gemini queden auditables.
        ai_assist = enriched_results.get("ai_assist")
        if ai_assist and ai_assist.get("used"):
            lines.append("## 🤖 Asistencia de IA (Gemini)")
            lines.append("")
            lines.append(
                f"- **Fingerprint de stack:** `{ai_assist.get('fingerprint', 'N/A')}`"
            )
            lines.append(
                f"- **Bitácora completa (prompts/respuestas crudas):** "
                f"`{ai_assist.get('audit_log_path', '')}`"
            )
            recovery = ai_assist.get("sqlmap_recovery")
            if recovery and recovery.get("suggested_flags"):
                lines.append(
                    f"- **Flags de recovery sugeridos:** "
                    f"`{' '.join(recovery['suggested_flags'])}`"
                )
                if recovery.get("reasoning"):
                    lines.append(f"  - _{recovery['reasoning']}_")
            lines.append("")

            tries = (
                ai_assist.get("known_techniques_tried", [])
                + ai_assist.get("gemini_suggestions", [])
            )
            if tries:
                lines.append("| Origen | Payload | Técnica | Confirmado | Razonamiento |")
                lines.append("|---|---|---|---|---|")
                for t in tries:
                    confirmed_mark = "✅" if t.get("confirmed") else "❌"
                    payload_cell = str(t.get("payload", "")).replace("|", "\\|")
                    reasoning_cell = str(t.get("reasoning", "")).replace("|", "\\|")
                    lines.append(
                        f"| {t.get('source', 'N/A')} | `{payload_cell}` | "
                        f"{t.get('technique', 'N/A')} | {confirmed_mark} | "
                        f"{reasoning_cell} |"
                    )
                lines.append("")

        # Remediación
        lines.append("## 🛡️ Recomendaciones de Remediación")
        lines.append("")
        specific = enriched_results.get("remediation", [])
        if specific:
            lines.append(f"### Específicas para {orm_data.get('orm', 'la app')}")
            lines.append("")
            for rec in specific:
                lines.append(f"- {rec}")
            lines.append("")

        general = enriched_results.get("general_remediation", [])
        if general:
            lines.append("### Recomendaciones Generales")
            lines.append("")
            for rec in general:
                lines.append(f"- {rec}")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            "*Generado por **inyector v1.0.0** — TribuCibernetica · "
            "tribucibernetica.com · hola@tribucibernetica.com*"
        )
        lines.append("")
        lines.append(
            "*Este reporte es confidencial. Solo para uso en entornos "
            "autorizados. El uso de esta herramienta contra sistemas sin "
            "autorización es ilegal.*"
        )

        markdown_content = "\n".join(lines)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        logger.info(f"Reporte Markdown generado: {output_path}")
        return output_path
