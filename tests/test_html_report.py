"""Tests para HTMLReportGenerator.

Cubren la forma real de `enriched_results` (ver
inyector/reporting/enricher.py y su uso en cli.py) y el branching
real de la plantilla Jinja2:
- La sección "Asistencia de IA (Gemini)" solo debe aparecer si
  `ai_assist.used` es verdadero.
- La sección "NoSQL Injection" solo debe aparecer si `recon.nosqli`
  es un dict no vacío (bool(recon.get("nosqli"))).
- Con un dict casi vacío el generador no debe explotar (todos los
  campos de la plantilla usan .get(...) con defaults).
"""

import os

from inyector.reporting.html_report import HTMLReportGenerator


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
                "operator_injection": {"vulnerable": True, "vector": "$ne"},
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
                    "payload": "1 AND SLEEP(5)",
                    "technique": "time-based",
                    "confirmed": True,
                    "reasoning": "delay de 5s detectado",
                },
            ],
        },
    }
    results.update(overrides)
    return results


def test_generate_full_results_contains_critical_info(tmp_path):
    output_path = str(tmp_path / "report.html")

    returned_path = HTMLReportGenerator().generate(_full_results(), output_path)

    assert returned_path == output_path
    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "http://testphp.example.com/listproducts.php?cat=1" in html
    assert "Cloudflare" in html
    assert "eloquent" in html
    assert "MySQL" in html
    assert "cat=1 AND 9294=9294" in html
    assert "boolean-based blind" in html
    assert "ALTO" in html


def test_generate_severity_maps_to_expected_badge_class(tmp_path):
    output_path = str(tmp_path / "report.html")

    HTMLReportGenerator().generate(_full_results(severity="CRÍTICO"), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert 'severity-banner critical' in html
    assert "CRÍTICO" in html


def test_generate_vulnerabilities_section_present_when_vulnerable(tmp_path):
    output_path = str(tmp_path / "report.html")

    HTMLReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "Vulnerabilidades Encontradas" in html


def test_generate_vulnerabilities_section_absent_when_clean(tmp_path):
    output_path = str(tmp_path / "report.html")
    results = _full_results(vulnerable=False, vulnerabilities=[], severity="LIMPIO")

    HTMLReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "Vulnerabilidades Encontradas" not in html
    assert "No se detectaron vulnerabilidades de SQL Injection" in html


def test_generate_ai_assist_section_present_when_used(tmp_path):
    output_path = str(tmp_path / "report.html")

    HTMLReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "Asistencia de IA (Gemini)" in html
    assert "php-laravel-eloquent-mysql" in html
    assert "1 AND SLEEP(5)" in html


def test_generate_ai_assist_section_absent_when_not_used(tmp_path):
    output_path = str(tmp_path / "report.html")
    results = _full_results(ai_assist={"used": False})

    HTMLReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "Asistencia de IA (Gemini)" not in html


def test_generate_nosqli_section_present_when_nosqli_data_exists(tmp_path):
    output_path = str(tmp_path / "report.html")

    HTMLReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "NoSQL Injection (MongoDB)" in html
    assert "Vulnerable" in html


def test_generate_nosqli_section_absent_when_no_nosqli_data(tmp_path):
    output_path = str(tmp_path / "report.html")
    results = _full_results()
    del results["recon"]["nosqli"]

    HTMLReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "NoSQL Injection (MongoDB)" not in html


def test_generate_minimal_dict_does_not_raise(tmp_path):
    output_path = str(tmp_path / "report.html")

    returned_path = HTMLReportGenerator().generate({}, output_path)

    assert returned_path == output_path
    with open(output_path, "r", encoding="utf-8") as f:
        html = f.read()

    assert "N/A" in html
    assert "LIMPIO" in html
    assert "Asistencia de IA (Gemini)" not in html
    assert "NoSQL Injection (MongoDB)" not in html


def test_generate_creates_missing_output_directory(tmp_path):
    nested_path = str(tmp_path / "nested" / "dir" / "report.html")

    returned_path = HTMLReportGenerator().generate(_full_results(), nested_path)

    assert returned_path == nested_path
    assert os.path.exists(nested_path)
