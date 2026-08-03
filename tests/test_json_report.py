"""Tests para JSONReportGenerator.

Cubren la forma real del diccionario `enriched_results` que produce
ResultEnricher.enrich() (ver inyector/reporting/enricher.py) y que
cli.py pasa directamente al generador. Puntos no obvios que se
verifican:
- Cada vulnerabilidad pierde su clave 'raw_output' en el JSON final
  (puede contener el log crudo de sqlmap, no debe filtrarse al
  reporte estructurado).
- Con un dict casi vacío (como el que se genera cuando sqlmap no
  encuentra nada y no hubo AI assist ni recon) el generador no debe
  explotar y debe caer en los defaults documentados en el código
  (severity LIMPIO, listas vacías, etc.).
"""

import json

from inyector.reporting.json_report import JSONReportGenerator


def _full_results(**overrides):
    results = {
        "target_url": "http://testphp.example.com/listproducts.php?cat=1",
        "injection_point": "GET cat",
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
                "severity_score": 8.0,
                "raw_output": "[19:45:15] [INFO] testing connection...",
            },
        ],
        "dbms": {"name": "MySQL", "version": ">= 5.1"},
        "databases": ["information_schema", "acuart"],
        "severity": "ALTO",
        "severity_score": 8.0,
        "auto_escalated": True,
        "remediation": ["Evitar DB::raw() y whereRaw() con variables sin sanitizar"],
        "general_remediation": ["Implementar Prepared Statements / Parametrized Queries"],
        "recon": {
            "waf": {"waf": "Cloudflare", "confidence": 0.9, "evidence": ["header X-CF-RAY"]},
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
            "consistency_notes": ["WAF detectado pero sin bloqueo confirmado"],
        },
        "ai_assist": {
            "used": True,
            "fingerprint": "php-laravel-eloquent-mysql",
            "audit_log_path": "/app/logs/ai_audit_abc123.jsonl",
            "sqlmap_recovery": {
                "suggested_flags": ["--tamper=space2comment", "--level=5"],
                "reasoning": "WAF detectado, evadir con tamper",
            },
            "known_techniques_tried": [],
            "gemini_suggestions": [],
        },
    }
    results.update(overrides)
    return results


def test_generate_full_results_contains_expected_keys_and_values(tmp_path):
    output_path = str(tmp_path / "report.json")

    returned_path = JSONReportGenerator().generate(_full_results(), output_path)

    assert returned_path == output_path
    with open(output_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["target"]["url"] == "http://testphp.example.com/listproducts.php?cat=1"
    assert report["severity"]["level"] == "ALTO"
    assert report["severity"]["score"] == 8.0
    assert report["scan_meta"]["auto_escalated"] is True
    assert report["reconnaissance"]["waf"]["waf"] == "Cloudflare"
    assert report["reconnaissance"]["orm"]["orm"] == "eloquent"
    assert report["reconnaissance"]["nosqli"]["operator_injection"]["vulnerable"] is True
    assert report["dbms"]["name"] == "MySQL"
    assert report["databases"] == ["information_schema", "acuart"]
    assert report["ai_assist"]["fingerprint"] == "php-laravel-eloquent-mysql"
    assert report["remediation"]["specific"] == [
        "Evitar DB::raw() y whereRaw() con variables sin sanitizar"
    ]
    assert len(report["vulnerabilities"]) == 1
    assert report["vulnerabilities"][0]["parameter"] == "cat"


def test_generate_strips_raw_output_from_vulnerabilities(tmp_path):
    output_path = str(tmp_path / "report.json")

    JSONReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    vuln = report["vulnerabilities"][0]
    assert "raw_output" not in vuln
    # El resto de las claves de la vulnerabilidad se preserva.
    assert vuln["technique"] == "B"
    assert vuln["payload"] == "cat=1 AND 9294=9294"


def test_generate_no_findings_reports_empty_vulnerabilities(tmp_path):
    output_path = str(tmp_path / "report.json")
    results = _full_results(vulnerable=False, vulnerabilities=[], severity="LIMPIO", severity_score=0.0)

    JSONReportGenerator().generate(results, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["vulnerabilities"] == []
    assert report["severity"]["level"] == "LIMPIO"


def test_generate_minimal_dict_does_not_raise_and_uses_defaults(tmp_path):
    output_path = str(tmp_path / "report.json")

    JSONReportGenerator().generate({}, output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["target"]["url"] == ""
    assert report["severity"]["level"] == "LIMPIO"
    assert report["severity"]["score"] == 0.0
    assert report["scan_meta"]["auto_escalated"] is False
    assert report["vulnerabilities"] == []
    assert report["dbms"] == {}
    assert report["databases"] == []
    assert report["ai_assist"] == {}
    assert report["remediation"] == {"specific": [], "general": []}
    assert report["reconnaissance"]["waf"] == {}
    assert report["reconnaissance"]["nosqli"] == {}


def test_generate_creates_missing_output_directory(tmp_path):
    nested_path = str(tmp_path / "nested" / "dir" / "report.json")

    returned_path = JSONReportGenerator().generate(_full_results(), nested_path)

    assert returned_path == nested_path
    with open(nested_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["target"]["url"] == _full_results()["target_url"]


def test_generate_includes_meta_disclaimer(tmp_path):
    output_path = str(tmp_path / "report.json")

    JSONReportGenerator().generate(_full_results(), output_path)

    with open(output_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    assert report["meta"]["tool"] == "inyector"
    assert "confidencial" in report["meta"]["disclaimer"]
