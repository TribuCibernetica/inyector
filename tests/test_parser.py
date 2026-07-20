"""Tests de regresión para SqlmapOutputParser.

Cubren específicamente los bugs reales encontrados en producción:
- target_url capturaba el método HTTP ('GET') en vez de la URL.
- dbms.name capturaba texto de un prompt heurístico con comillas.
- dbms.version se cortaba en el primer punto (ej. '5.1' -> '5').
"""

from inyector.reporting.parser import SqlmapOutputParser

# Fragmento real de sqlmap: "URL:" en una línea y "GET <url>" en la
# siguiente (bug: el regex viejo capturaba la palabra "GET").
SQLMAP_OUTPUT_WITH_URL_HEADER = """
[1/1] URL:
GET http://localhost:18080/?id=1
do you want to test this URL? [Y/n/q]
> Y
[19:45:15] [INFO] testing connection to the target URL
"""

# Fragmento real: primero aparece la suposición heurística entre
# comillas (con texto de prompt pegado), y solo al final la línea
# autoritativa. El parser debe quedarse con la última.
SQLMAP_OUTPUT_WITH_DBMS_GUESS_AND_CONFIRMATION = """
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[19:45:26] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.68, PHP 8.2.32
back-end DBMS: MySQL >= 5.1 (MariaDB fork)
"""

VULN_BLOCK = """
sqlmap identified the following injection point(s) with a total of 41 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 9294=9294
---
"""


def test_target_url_skips_http_method():
    parser = SqlmapOutputParser()
    result = parser.parse(SQLMAP_OUTPUT_WITH_URL_HEADER, output_dir="/tmp/does-not-exist")
    assert result["target_url"] == "http://localhost:18080/?id=1"
    assert result["target_url"] != "GET"


def test_dbms_name_and_version_survive_heuristic_guess_and_period():
    parser = SqlmapOutputParser()
    result = parser.parse(
        SQLMAP_OUTPUT_WITH_DBMS_GUESS_AND_CONFIRMATION,
        output_dir="/tmp/does-not-exist",
    )
    assert result["dbms"]["name"] == "MySQL"
    assert result["dbms"]["version"] == ">= 5.1"


def test_vulnerability_block_parsed_correctly():
    parser = SqlmapOutputParser()
    result = parser.parse(VULN_BLOCK, output_dir="/tmp/does-not-exist")
    assert result["vulnerable"] is True
    assert len(result["vulnerabilities"]) == 1
    vuln = result["vulnerabilities"][0]
    assert vuln["parameter"] == "id (GET)"
    assert vuln["type"] == "boolean-based blind"
    assert vuln["technique"] == "B"


def test_no_vulnerability_reported_as_clean():
    parser = SqlmapOutputParser()
    result = parser.parse(
        "[INFO] all tested parameters do not appear to be injectable",
        output_dir="/tmp/does-not-exist",
    )
    assert result["vulnerable"] is False
    assert result["vulnerabilities"] == []
