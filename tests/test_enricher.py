"""Tests para ResultEnricher.

Cubre el cálculo de severidad máxima entre varias vulnerabilidades, el
remediation específico por ORM, y el caso no obvio marcado en el propio
código: un NoSQLi confirmado (operator_injection o where_injection)
debe elevar la severidad a ALTO/8.0 cuando sqlmap reportó "limpio"
(porque sqlmap no soporta NoSQL), pero NO debe degradar una severidad
ya más alta -- aunque el remediation de NoSQLi se agrega siempre,
independientemente de si hubo o no downgrade de score.
"""

from inyector.reporting.enricher import ResultEnricher

CLEAN_SCAN = {"vulnerable": False, "vulnerabilities": [], "target_url": "http://x.com"}


def _recon(orm="none", nosqli=None):
    data = {"orm": {"orm": orm}}
    if nosqli is not None:
        data["nosqli"] = nosqli
    return data


def test_clean_scan_with_no_orm_gets_generic_remediation():
    enricher = ResultEnricher()
    result = enricher.enrich(CLEAN_SCAN, _recon())

    assert result["severity"] == "LIMPIO"
    assert result["severity_score"] == 0.0
    assert result["remediation"] == ResultEnricher.REMEDIATION_MAP["none"]
    assert result["general_remediation"] == ResultEnricher.GENERAL_REMEDIATION
    assert result["recon"] == _recon()
    # El scan original se preserva en el resultado enriquecido.
    assert result["target_url"] == "http://x.com"


def test_vulnerable_with_no_vulnerabilities_entries_yields_bajo_not_limpio():
    # Caso límite: vulnerable=True pero la lista de vulnerabilities
    # está vacía -> el loop nunca corre, y el valor inicial de
    # max_severity ("BAJO", 0.0) queda como resultado final.
    enricher = ResultEnricher()
    scan = {"vulnerable": True, "vulnerabilities": []}
    result = enricher.enrich(scan, _recon())

    assert result["severity"] == "BAJO"
    assert result["severity_score"] == 0.0


def test_severity_reflects_the_highest_scoring_technique_among_several():
    enricher = ResultEnricher()
    scan = {
        "vulnerable": True,
        "vulnerabilities": [
            {"technique": "B"},
            {"technique": "S"},  # score 10.0, el más alto
            {"technique": "T"},
        ],
    }
    result = enricher.enrich(scan, _recon())

    assert result["severity"] == "CRÍTICO"
    assert result["severity_score"] == 10.0
    # Cada vulnerabilidad individual queda anotada con su propia severidad.
    techniques = {v["technique"]: v["severity"] for v in scan["vulnerabilities"]}
    assert techniques == {"B": "ALTO", "S": "CRÍTICO", "T": "ALTO"}


def test_unknown_technique_defaults_to_medio():
    enricher = ResultEnricher()
    scan = {"vulnerable": True, "vulnerabilities": [{"technique": "Z"}]}
    result = enricher.enrich(scan, _recon())

    assert result["severity"] == "MEDIO"
    assert result["severity_score"] == 5.0
    assert scan["vulnerabilities"][0]["severity"] == "MEDIO"


def test_remediation_is_orm_specific_for_known_orm():
    enricher = ResultEnricher()
    result = enricher.enrich(CLEAN_SCAN, _recon(orm="django_orm"))

    assert result["remediation"] == ResultEnricher.REMEDIATION_MAP["django_orm"]
    assert result["remediation"] != ResultEnricher.REMEDIATION_MAP["none"]


def test_missing_orm_key_in_recon_data_defaults_to_none_remediation():
    enricher = ResultEnricher()
    # recon_data sin la clave "orm" en absoluto (no solo vacía).
    result = enricher.enrich(CLEAN_SCAN, {})

    assert result["remediation"] == ResultEnricher.REMEDIATION_MAP["none"]


def test_missing_nosqli_key_does_not_crash_and_has_no_effect():
    enricher = ResultEnricher()
    result = enricher.enrich(CLEAN_SCAN, {})

    assert result["severity"] == "LIMPIO"
    assert result["severity_score"] == 0.0


def test_nosqli_operator_injection_upgrades_clean_scan_to_alto():
    enricher = ResultEnricher()
    recon = _recon(nosqli={"operator_injection": {"vulnerable": True}})
    result = enricher.enrich(CLEAN_SCAN, recon)

    assert result["severity"] == "ALTO"
    assert result["severity_score"] == 8.0
    assert any("NoSQLi" in item for item in result["remediation"])


def test_nosqli_where_injection_also_upgrades_clean_scan():
    enricher = ResultEnricher()
    recon = _recon(nosqli={"where_injection": {"vulnerable": True}})
    result = enricher.enrich(CLEAN_SCAN, recon)

    assert result["severity"] == "ALTO"
    assert result["severity_score"] == 8.0


def test_nosqli_does_not_downgrade_an_already_higher_severity():
    # sqlmap ya encontró algo CRÍTICO (score 9.5) -- el NoSQLi no debe
    # bajarlo a ALTO/8.0, pero sí debe agregar su remediation.
    enricher = ResultEnricher()
    scan = {"vulnerable": True, "vulnerabilities": [{"technique": "E"}]}
    recon = _recon(orm="none", nosqli={"where_injection": {"vulnerable": True}})
    result = enricher.enrich(scan, recon)

    assert result["severity"] == "CRÍTICO"
    assert result["severity_score"] == 9.5
    assert any("NoSQLi" in item for item in result["remediation"])
    # El remediation de ORM ("none") sigue presente junto con el de NoSQLi.
    assert result["remediation"][: len(ResultEnricher.REMEDIATION_MAP["none"])] == (
        ResultEnricher.REMEDIATION_MAP["none"]
    )


def test_nosqli_not_vulnerable_leaves_severity_untouched():
    enricher = ResultEnricher()
    recon = _recon(nosqli={
        "operator_injection": {"vulnerable": False},
        "where_injection": {"vulnerable": False},
    })
    result = enricher.enrich(CLEAN_SCAN, recon)

    assert result["severity"] == "LIMPIO"
    assert result["severity_score"] == 0.0
    assert not any("NoSQLi" in item for item in result["remediation"])
