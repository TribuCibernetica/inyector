"""Tests para MarkdownReportGenerator.

Cubren la forma real de `enriched_results` (ver
inyector/reporting/enricher.py) y el branching real de generate():
- Encabezado de vulnerabilidades vs. encabezado "sin vulnerabilidades"
  según `vulnerable`.
- Sección "Asistencia de IA (Gemini)" solo si `ai_assist.used`.
- Sección NoSQL solo si el motor es distinto de 'unknown' o si hay
  una inyección NoSQL confirmada (condición real en el código:
  `nosqli_data.get("engine") != "unknown" or vulnerable`).
- El escape manual de '|' en las celdas de la tabla de intentos de IA
  (para no romper el markdown), que es lógica real y no obvia.
- Con un dict casi vacío el generador no debe explotar.
"""

import os

from inyector.reporting.markdown_report import MarkdownReportGenerator


def _full_results(**overrides):
    results = {
        "target_url": "http://testphp.example.com/listproducts.php?cat=1",
        "vulnerable": True,
        "vulnerabilities": [
            {
                "parameter": "cat",
                "type": "boolean-based blind",
                "title": "AND boolean-based blind - WHERE or HAVING clause",
                "technique": "B",
                "dbms": "MySQL",
                "payload": "cat=1 AND 9294=9294",
                "severity": "ALTO",
            },
        ],
        "dbms": {"name": "MySQL", "version": ">= 5.1"},
        "severity": "ALTO",
        "remediation": ["Evitar DB::raw() y whereRaw() con variables sin sanitizar"],
        "general_remediation": ["Implementar Prepared Statements / Parametrized Queries"],
        "recon": {
            "waf": {"waf": "Cloudflare", "confidence": 0.9, "evidence": ["header X-CF-RAY presente"]},
            "stack": {"language": "PHP", "framework": "Laravel", "database_hints": ["mysql"]},
            "orm": {"orm": "eloquent", "escape_hatches": ["DB::raw"]},
            "graphql": {"endpoints": [], "introspection_enabled": False, "injectable_args": []},
            "nosqli": {
                "engine": "mongodb",
                "operator_injection": {"vulnerable": True, "vector": "$ne", "evidence": ["respuesta distinta con $ne"]},
                "where_injection": {"vulnerable": False},
            },
            "endpoints": {"injectable_params": [{"name": "cat", "method": "GET", "priority": "high"}]},
            "tampers_used": ["space2comment"],
        },
        "ai_assist": {
            "used": True,
            "fingerprint": "php-laravel-eloquent-mysql",
            "audit_log_path": "/app/logs/ai_audit_abc123.jsonl",
            "sqlmap_recovery": {
                "suggested_flags": ["--tamper=space2comment", "--level=5"],
                "reasoning": "WAF detectado, evadir con tamper",
            },
            "known_techniques_tried": [
                {
                    "source": "knowledge_base",
                    "payload": "1' OR '1'='1",
                    "technique": "boolean",
                    "confirmed": False,
                    "reasoning": "no hubo cambio en la respuesta",
                },
            ],
            "gemini_suggestions": [
                {
                    "source": "gemini",
                    "payload": "1|SLEEP(5)",
                    "technique": "time-based",
                    "confirmed": True,
                    "reasoning": "delay de 5s | respuesta anómala",
                },
            ],
        },
    }
    results.update(overrides)
    return results


def test_generate_full_results_contains_critical_info(tmp_path):
    output_path = str(tmp_path / "report.md")

    returned_path = MarkdownReportGenerator().generate(_full_results(), output_path)

    assert returned_path == output_path
    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "http://testphp.example.com/listproducts.php?cat=1" in md
    assert "Cloudflare" in md
    assert "eloquent" in md
    assert "MySQL" in md
    assert "cat=1 AND 9294=9294" in md
    assert "**ALTO**" in md
    assert "🟠" in md  # emoji de severidad ALTO


def test_generate_vulnerabilities_heading_when_vulnerable(tmp_path):
    output_path = str(tmp_path / "report.md")

    MarkdownReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "## 🔴 Vulnerabilidades Encontradas" in md
    assert "### Parámetro: `cat`" in md
    assert "## ✅ Sin vulnerabilidades detectadas" not in md


def test_generate_clean_heading_when_no_vulnerabilities(tmp_path):
    output_path = str(tmp_path / "report.md")
    results = _full_results(vulnerable=False, vulnerabilities=[], severity="LIMPIO")
    results["recon"]["nosqli"] = {
        "engine": "unknown",
        "operator_injection": {"vulnerable": False},
        "where_injection": {"vulnerable": False},
    }

    MarkdownReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "## ✅ Sin vulnerabilidades detectadas" in md
    assert "## 🔴 Vulnerabilidades Encontradas" not in md
    assert "🟢" in md  # emoji de severidad LIMPIO


def test_generate_ai_assist_section_present_when_used(tmp_path):
    output_path = str(tmp_path / "report.md")

    MarkdownReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "## 🤖 Asistencia de IA (Gemini)" in md
    assert "php-laravel-eloquent-mysql" in md
    assert "--tamper=space2comment" in md


def test_generate_ai_assist_section_absent_when_not_used(tmp_path):
    output_path = str(tmp_path / "report.md")
    results = _full_results(ai_assist={"used": False})

    MarkdownReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "Asistencia de IA (Gemini)" not in md


def test_generate_ai_assist_absent_key_does_not_raise(tmp_path):
    output_path = str(tmp_path / "report.md")
    results = _full_results()
    del results["ai_assist"]

    MarkdownReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "Asistencia de IA (Gemini)" not in md


def test_generate_escapes_pipe_characters_in_ai_assist_table(tmp_path):
    output_path = str(tmp_path / "report.md")

    MarkdownReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    # El payload y el razonamiento contienen '|' crudo, que rompería
    # la tabla markdown si no se escapa con '\|'.
    assert "1\\|SLEEP(5)" in md
    assert "delay de 5s \\| respuesta anómala" in md


def test_generate_nosqli_section_present_when_engine_known(tmp_path):
    output_path = str(tmp_path / "report.md")

    MarkdownReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "### NoSQL Injection (MongoDB)" in md
    assert "Operator injection confirmada" in md


def test_generate_nosqli_section_absent_when_engine_unknown_and_not_vulnerable(tmp_path):
    output_path = str(tmp_path / "report.md")
    results = _full_results()
    results["recon"]["nosqli"] = {
        "engine": "unknown",
        "operator_injection": {"vulnerable": False},
        "where_injection": {"vulnerable": False},
    }

    MarkdownReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "NoSQL Injection (MongoDB)" not in md


def test_generate_minimal_dict_does_not_raise(tmp_path):
    output_path = str(tmp_path / "report.md")

    returned_path = MarkdownReportGenerator().generate({}, output_path)

    assert returned_path == output_path
    with open(output_path, "r", encoding="utf-8") as f:
        md = f.read()

    assert "N/A" in md
    assert "🟢" in md
    assert "## ✅ Sin vulnerabilidades detectadas" in md
    assert "Asistencia de IA (Gemini)" not in md
    assert "NoSQL Injection (MongoDB)" not in md


def test_generate_creates_missing_output_directory(tmp_path):
    nested_path = str(tmp_path / "nested" / "dir" / "report.md")

    returned_path = MarkdownReportGenerator().generate(_full_results(), nested_path)

    assert returned_path == nested_path
    assert os.path.exists(nested_path)
