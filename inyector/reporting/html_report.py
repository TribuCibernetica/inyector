"""Módulo de generación de reportes HTML.

Genera reportes HTML completos con estilo dark theme
y toda la información del scan y reconocimiento.
"""

import os
from datetime import datetime
from jinja2 import Template
from inyector.utils.logger import get_logger

logger = get_logger(__name__)


class HTMLReportGenerator:
    """Genera reportes HTML ejecutivos con tema oscuro."""

    HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte SQLi — inyector v1.0</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #0a0f1a; --bg-secondary: #0f1722; --bg-card: #131d2e;
            --bg-code: #0f1f2e; --accent: #00ff88; --accent-dim: #00cc6a;
            --text-primary: #ffffff; --text-secondary: #8899aa; --text-dim: #556677;
            --border: #1a2a3a; --critical: #ff3366; --high: #ff6633;
            --medium: #ffaa00; --low: #00aaff; --clean: #00ff88;
        }
        body { font-family: 'Inter', sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 40px; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { text-align: center; padding: 40px 0; border-bottom: 1px solid var(--border); margin-bottom: 40px; }
        .header .logo { font-size: 2.2rem; font-weight: 700; color: var(--accent); letter-spacing: 4px; text-transform: uppercase; margin-bottom: 8px; }
        .header .subtitle { color: var(--text-secondary); font-size: 0.95rem; font-weight: 300; }
        .header .scan-info { margin-top: 20px; color: var(--text-dim); font-size: 0.85rem; }
        .badge { display: inline-block; padding: 4px 14px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
        .badge-critical { background: var(--critical); color: #fff; }
        .badge-alto { background: var(--high); color: #fff; }
        .badge-medio { background: var(--medium); color: #000; }
        .badge-bajo { background: var(--low); color: #fff; }
        .badge-limpio { background: var(--clean); color: #000; }
        .badge-info { background: rgba(0,255,136,0.15); color: var(--accent); border: 1px solid var(--accent); }
        .badge-waf { background: rgba(255,51,102,0.15); color: var(--critical); border: 1px solid var(--critical); }
        .severity-banner { text-align: center; padding: 20px; margin-bottom: 40px; border-radius: 12px; }
        .severity-banner.critical { background: rgba(255,51,102,0.1); border: 1px solid var(--critical); }
        .severity-banner.alto { background: rgba(255,102,51,0.1); border: 1px solid var(--high); }
        .severity-banner.medio { background: rgba(255,170,0,0.1); border: 1px solid var(--medium); }
        .severity-banner.bajo { background: rgba(0,170,255,0.1); border: 1px solid var(--low); }
        .severity-banner.limpio { background: rgba(0,255,136,0.1); border: 1px solid var(--clean); }
        .severity-banner h2 { font-size: 1.4rem; margin-bottom: 4px; }
        .section { margin-bottom: 40px; }
        .section-title { font-size: 1.3rem; font-weight: 600; color: var(--accent); margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 16px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .card-header h3 { font-size: 1.05rem; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; margin: 8px 0; }
        th, td { text-align: left; padding: 12px 16px; border-bottom: 1px solid var(--border); }
        th { color: var(--text-secondary); font-weight: 500; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }
        td { font-size: 0.9rem; }
        code, .code-block { font-family: 'JetBrains Mono', monospace; background: var(--bg-code); border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-size: 0.85rem; color: var(--accent); overflow-x: auto; display: block; margin: 8px 0; white-space: pre-wrap; word-break: break-all; }
        code.inline { display: inline; padding: 2px 8px; border-radius: 4px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .summary-item { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
        .summary-item .label { color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
        .summary-item .value { font-size: 1.1rem; font-weight: 600; }
        .remediation-item { padding: 12px 16px; border-left: 3px solid var(--accent); margin-bottom: 10px; background: rgba(0,255,136,0.03); border-radius: 0 8px 8px 0; }
        .footer { text-align: center; padding: 40px 0; border-top: 1px solid var(--border); margin-top: 40px; color: var(--text-dim); font-size: 0.8rem; }
        .footer .logo-small { color: var(--accent); font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">&#x27C1; INYECTOR</div>
            <div class="subtitle">Reporte de SQL Injection — v1.0.0</div>
            <div class="scan-info">{{ scan_date }} · {{ target_url }}</div>
        </div>
        <div class="severity-banner {{ severity_class }}">
            <h2>Severidad: <span class="badge badge-{{ severity_class }}">{{ severity }}</span></h2>
            <p style="color: var(--text-secondary); margin-top: 8px;">{% if vulnerable %}Se encontraron {{ vuln_count }} vulnerabilidad(es) de SQL Injection{% else %}No se detectaron vulnerabilidades de SQL Injection{% endif %}</p>
        </div>
        <div class="section">
            <h2 class="section-title">📊 Resumen Ejecutivo</h2>
            <div class="summary-grid">
                <div class="summary-item"><div class="label">URL Objetivo</div><div class="value" style="font-size: 0.9rem; word-break: break-all;">{{ target_url }}</div></div>
                <div class="summary-item"><div class="label">WAF Detectado</div><div class="value">{% if waf_name != 'none' %}<span class="badge badge-waf">{{ waf_name }}</span> ({{ waf_confidence }}%){% else %}<span class="badge badge-info">Ninguno</span>{% endif %}</div></div>
                <div class="summary-item"><div class="label">Stack Tecnológico</div><div class="value">{{ stack_framework }} ({{ stack_language }})</div></div>
                <div class="summary-item"><div class="label">ORM Detectado</div><div class="value">{{ orm_name }}</div></div>
                <div class="summary-item"><div class="label">Vulnerabilidades</div><div class="value" style="color: {{ 'var(--critical)' if vulnerable else 'var(--clean)' }};">{{ vuln_count }}</div></div>
                <div class="summary-item"><div class="label">DBMS</div><div class="value">{{ dbms_name }} {{ dbms_version }}</div></div>
            </div>
        </div>
        {% if vulnerable %}
        <div class="section">
            <h2 class="section-title">🔴 Vulnerabilidades Encontradas</h2>
            {% for vuln in vulnerabilities %}
            <div class="card">
                <div class="card-header"><h3><span class="badge badge-critical">{{ vuln.parameter }}</span>&nbsp; {{ vuln.type }}</h3><span class="badge badge-{{ (vuln.severity|default('MEDIO'))|lower }}">{{ vuln.severity|default('MEDIO') }}</span></div>
                <table>
                    <tr><th style="width: 140px;">Título</th><td>{{ vuln.title }}</td></tr>
                    <tr><th>Técnica</th><td>{{ vuln.type }}</td></tr>
                    {% if vuln.dbms %}<tr><th>DBMS</th><td>{{ vuln.dbms }}</td></tr>{% endif %}
                </table>
                {% if vuln.payload %}<div style="margin-top: 12px;"><span style="color: var(--text-secondary); font-size: 0.85rem;">Payload:</span><code>{{ vuln.payload }}</code></div>{% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        <div class="section">
            <h2 class="section-title">🔍 Reconocimiento</h2>
            <div class="card"><div class="card-header"><h3>WAF Fingerprinting</h3><span class="badge badge-info">{{ waf_name }}</span></div>
                <table><tr><th>WAF</th><td>{{ waf_name }}</td></tr><tr><th>Confianza</th><td>{{ waf_confidence }}%</td></tr>
                <tr><th>Evidencias</th><td>{% for ev in waf_evidence %}• {{ ev }}<br>{% endfor %}{% if not waf_evidence %}Sin evidencias específicas{% endif %}</td></tr>
                {% if tampers %}<tr><th>Tampers usados</th><td>{{ tampers }}</td></tr>{% endif %}</table></div>
            <div class="card"><div class="card-header"><h3>Stack Detection</h3></div>
                <table><tr><th>Lenguaje</th><td>{{ stack_language }}</td></tr><tr><th>Framework</th><td>{{ stack_framework }}</td></tr>
                <tr><th>ORM</th><td>{{ orm_name }}</td></tr>
                {% if escape_hatches %}<tr><th>Escape Hatches</th><td>{% for eh in escape_hatches %}<code class="inline">{{ eh }}</code> {% endfor %}</td></tr>{% endif %}
                <tr><th>DB Hints</th><td>{{ db_hints }}</td></tr>
                {% if injectable_params %}<tr><th>Parámetros priorizados</th><td>{% for p in injectable_params %}<code class="inline">{{ p.name }}</code> ({{ p.method }}, {{ p.priority }})&nbsp; {% endfor %}</td></tr>{% endif %}</table></div>
            {% if graphql_endpoints %}
            <div class="card"><div class="card-header"><h3>GraphQL</h3></div>
                <table><tr><th>Endpoints</th><td>{% for ep in graphql_endpoints %}{{ ep }}<br>{% endfor %}</td></tr>
                <tr><th>Introspección</th><td>{{ "Habilitada" if graphql_introspection else "Deshabilitada" }}</td></tr>
                {% if graphql_injectable %}<tr><th>Args Inyectables</th><td>{% for arg in graphql_injectable %}{{ arg.query_name }}.{{ arg.arg_name }} ({{ arg.arg_type }})<br>{% endfor %}</td></tr>{% endif %}</table></div>
            {% endif %}
            {% if nosqli_checked %}
            <div class="card"><div class="card-header"><h3>NoSQL Injection (MongoDB)</h3>{% if nosqli_vulnerable %}<span class="badge badge-critical">Vulnerable</span>{% else %}<span class="badge badge-info">Sin hallazgos</span>{% endif %}</div>
                <table><tr><th>Motor</th><td>{{ nosqli_engine }}</td></tr>
                {% if nosqli_operator_vuln %}<tr><th>Operator injection</th><td>Confirmada ({{ nosqli_operator_vector }})</td></tr>{% endif %}
                {% if nosqli_where_vuln %}<tr><th>$where injection</th><td>Confirmada ({{ nosqli_where_technique }})</td></tr>{% endif %}</table></div>
            {% endif %}
        </div>
        <div class="section">
            <h2 class="section-title">🛡️ Recomendaciones de Remediación</h2>
            {% if specific_remediation %}<div class="card"><div class="card-header"><h3>Específicas para {{ orm_name }}</h3></div>{% for rec in specific_remediation %}<div class="remediation-item">{{ rec }}</div>{% endfor %}</div>{% endif %}
            <div class="card"><div class="card-header"><h3>Recomendaciones Generales</h3></div>{% for rec in general_remediation %}<div class="remediation-item">{{ rec }}</div>{% endfor %}</div>
        </div>
        <div class="footer">
            <p>Generado por <span class="logo-small">&#x27C1; inyector v1.0.0</span> — TribuCibernetica</p>
            <p style="margin-top: 8px;">tribucibernetica.com · hola@tribucibernetica.com</p>
            <p style="margin-top: 16px; font-size: 0.75rem;">Este reporte es confidencial. Solo para uso en entornos autorizados.<br>El uso de esta herramienta contra sistemas sin autorización es ilegal.</p>
        </div>
    </div>
</body>
</html>'''

    def generate(self, enriched_results: dict, output_path: str) -> str:
        """Genera un reporte HTML completo.

        Args:
            enriched_results: Resultados enriquecidos del scan.
            output_path: Ruta del archivo de salida.

        Returns:
            Ruta del archivo generado.
        """
        logger.info(f"Generando reporte HTML: {output_path}")

        recon = enriched_results.get("recon", {})
        waf_data = recon.get("waf", {})
        stack_data = recon.get("stack", {})
        orm_data = recon.get("orm", {})
        graphql_data = recon.get("graphql", {})

        severity = enriched_results.get("severity", "LIMPIO")
        severity_class_map = {
            "CRÍTICO": "critical", "ALTO": "alto",
            "MEDIO": "medio", "BAJO": "bajo", "LIMPIO": "limpio",
        }
        severity_class = severity_class_map.get(severity, "limpio")

        template_data = {
            "scan_date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "target_url": enriched_results.get("target_url", "N/A"),
            "severity": severity,
            "severity_class": severity_class,
            "vulnerable": enriched_results.get("vulnerable", False),
            "vuln_count": len(enriched_results.get("vulnerabilities", [])),
            "vulnerabilities": enriched_results.get("vulnerabilities", []),
            "waf_name": waf_data.get("waf", "none"),
            "waf_confidence": int(waf_data.get("confidence", 0) * 100),
            "waf_evidence": waf_data.get("evidence", []),
            "tampers": ", ".join(recon.get("tampers_used", [])),
            "stack_language": stack_data.get("language", "desconocido"),
            "stack_framework": stack_data.get("framework", "desconocido"),
            "db_hints": ", ".join(stack_data.get("database_hints", [])) or "N/A",
            "injectable_params": recon.get("endpoints", {}).get("injectable_params", [])[:10],
            "nosqli_checked": bool(recon.get("nosqli")),
            "nosqli_engine": recon.get("nosqli", {}).get("engine", "unknown"),
            "nosqli_operator_vuln": recon.get("nosqli", {}).get("operator_injection", {}).get("vulnerable", False),
            "nosqli_operator_vector": recon.get("nosqli", {}).get("operator_injection", {}).get("vector", ""),
            "nosqli_where_vuln": recon.get("nosqli", {}).get("where_injection", {}).get("vulnerable", False),
            "nosqli_where_technique": recon.get("nosqli", {}).get("where_injection", {}).get("technique", ""),
            "nosqli_vulnerable": (
                recon.get("nosqli", {}).get("operator_injection", {}).get("vulnerable", False)
                or recon.get("nosqli", {}).get("where_injection", {}).get("vulnerable", False)
            ),
            "orm_name": orm_data.get("orm", "none"),
            "escape_hatches": orm_data.get("escape_hatches", []),
            "dbms_name": enriched_results.get("dbms", {}).get("name", "N/A"),
            "dbms_version": enriched_results.get("dbms", {}).get("version", ""),
            "graphql_endpoints": graphql_data.get("endpoints", []),
            "graphql_introspection": graphql_data.get("introspection_enabled", False),
            "graphql_injectable": graphql_data.get("injectable_args", []),
            "specific_remediation": enriched_results.get("remediation", []),
            "general_remediation": enriched_results.get("general_remediation", []),
        }

        template = Template(self.HTML_TEMPLATE)
        html_content = template.render(**template_data)

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Reporte HTML generado: {output_path}")
        return output_path
